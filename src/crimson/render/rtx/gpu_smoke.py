"""GPU-resident atmosphere; the CPU retains only immutable events and clocks."""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.texture_mode import restore_current_target, texture_mode

from ...math_parity import f32
from ...sim.smoke_events import SmokeEmission
from .gpu_smoke_shaders import GPU_SMOKE_FRAGMENT, GPU_SMOKE_SPLAT_FRAGMENT
from .smoke_shaders import SMOKE_VERTEX
from .smoke_simulation import FADE_SECONDS, MAX_PENDING_EMISSIONS, STEP_SECONDS

GRID_SIZE = 320
GUARD_BAND = 128.0
PRESSURE_ITERATIONS = 12


@dataclass
class GpuSmokeField:
    origin: Vec2
    size: Vec2
    idle_seconds: float = 0.0
    retention_seconds: float = 10.0

    @property
    def fade(self) -> float:
        return min(1.0, max(0.0, (self.retention_seconds-self.idle_seconds)/FADE_SECONDS))


class GpuSmokeSimulation:
    def __init__(self, *, resolution: int = GRID_SIZE) -> None:
        self.resolution = resolution
        self.fields: dict[int, GpuSmokeField] = {}
        self.pending: list[tuple[float, SmokeEmission]] = []
        self.batches: deque[tuple[tuple[SmokeEmission, ...], float, float]] = deque()
        self.targets: list[rl.RenderTexture] = []
        self.shader: rl.Shader | None = None
        self.splat_shader: rl.Shader | None = None
        self.locations: dict[str, int] = {}
        self.splat_locations: dict[str, int] = {}
        self.origin = Vec2(-GUARD_BAND, -GUARD_BAND)
        self.size = Vec2(1024+2*GUARD_BAND, 1024+2*GUARD_BAND)
        self.current = 0
        self.accumulator = 0.0
        self.decay = .20
        self.dirty_reset = True
        self.executed_steps = 0

    @property
    def texture(self) -> rl.Texture:
        return self.targets[self.current].texture

    def reset(self) -> None:
        self.fields.clear()
        self.pending.clear()
        self.batches.clear()
        self.accumulator = 0.0
        self.decay = .20
        self.dirty_reset = True
        self.executed_steps = 0

    def consume(self, emissions: tuple[SmokeEmission, ...], dt_sim: float) -> None:
        if not math.isfinite(dt_sim) or dt_sim < 0:
            raise ValueError("smoke presentation delta must be finite and nonnegative")
        ready: list[SmokeEmission] = []
        waiting = []
        for age, emission in self.pending:
            age = f32(f32(age)+f32(dt_sim))
            if age >= 0:
                ready.append(emission)
            else:
                waiting.append((age, emission))
        self.pending = waiting
        for emission in emissions:
            if emission.color.a <= 0 or max(emission.scale, emission.expansion*2*STEP_SECONDS) <= 0 or not all(math.isfinite(v) for v in (
                emission.pos.x, emission.pos.y, emission.vel.x, emission.vel.y, emission.scale,
                emission.color.r, emission.color.g, emission.color.b, emission.color.a,
                emission.delay_seconds, emission.expansion, emission.retention_seconds, emission.rotation,
            )):
                continue
            if emission.delay_seconds > 0:
                if len(self.pending) < MAX_PENDING_EMISSIONS:
                    self.pending.append((-emission.delay_seconds, emission))
            else:
                ready.append(emission)
        # Retain elapsed empty ticks: frame grouping must not change transport.
        if ready or self.fields:
            fade = self.fields[0].fade if ready and self.fields else 1.
            self.batches.append((tuple(ready), dt_sim, fade))
        if ready:
            field = self.fields.setdefault(0, GpuSmokeField(self.origin, self.size))
            field.retention_seconds = max(field.retention_seconds-field.idle_seconds,
                                          *(min(15., max(2., e.retention_seconds)) for e in ready))
            field.idle_seconds = 0.
        for field in self.fields.values():
            field.idle_seconds += dt_sim
        if self.fields and self.fields[0].fade <= 0:
            # Fully expired material cannot affect a later new domain. This is
            # exact lifetime culling, not dropping elapsed simulation steps.
            self.fields.clear()
            self.batches.clear()
            self.accumulator = 0.
            self.dirty_reset = True

    def _set(self, shader: rl.Shader, locations: dict[str, int], name: str, values: tuple[float, ...]) -> None:
        kind = {1: rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
                2: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
                4: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4}[len(values)]
        buffer = rl.ffi.new("float[]", values)
        rl.set_shader_value(shader, locations[name], rl.ffi.cast("void *", buffer), kind)

    def _ensure(self) -> None:
        if self.shader is not None:
            return
        try:
            for attr, source, locations in (
                ("shader", GPU_SMOKE_FRAGMENT, self.locations),
                ("splat_shader", GPU_SMOKE_SPLAT_FRAGMENT, self.splat_locations),
            ):
                shader = rl.load_shader_from_memory(SMOKE_VERTEX, source)
                if int(shader.id) <= 0 or shader.id == rl.rl_get_shader_id_default():
                    raise RuntimeError("GPU smoke solver shader compilation failed")
                setattr(self, attr, shader)
                names = ("u_resolution", "u_world_size", "u_aux", "u_mode", "u_dt", "u_decay", "u_fade") if attr == "shader" else (
                    "u_resolution", "u_world_size", "u_source", "u_motion", "u_rotation")
                locations.update({name: int(rl.get_shader_location(shader, name)) for name in names})
                self._set(shader, locations, "u_resolution", (float(self.resolution), float(self.resolution)))
            for _ in range(5):
                self.targets.append(load_float_render_texture(self.resolution, self.resolution))
        except Exception:
            self.close()
            raise
        finally:
            restore_current_target()

    def _pass(self, destination: int, source: int, mode: int, aux: int | None = None) -> None:
        assert self.shader is not None
        rl.set_shader_value(self.shader, self.locations["u_mode"], rl.ffi.new("int *", mode),
                            rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
        with texture_mode(self.targets[destination]):
            rl.rl_disable_color_blend()
            rl.begin_shader_mode(self.shader)
            try:
                if aux is not None:
                    rl.set_shader_value_texture(self.shader, self.locations["u_aux"], self.targets[aux].texture)
                n = self.resolution
                rl.draw_texture_pro(self.targets[source].texture, rl_rectangle(0, 0, n, -n),
                                    rl_rectangle(0, 0, n, n), rl_vector2(0, 0), 0., rl.WHITE)
                rl.rl_draw_render_batch_active()
            finally:
                rl.end_shader_mode()
                rl.rl_enable_color_blend()

    def _inject(self, emissions: tuple[SmokeEmission, ...]) -> None:
        assert self.splat_shader is not None
        with texture_mode(self.targets[self.current]):
            # Alpha stores signed velocity Y, so use ONE/ONE instead of SRC_ALPHA.
            rl.rl_set_blend_factors(1, 1, 0x8006)
            rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM)
            rl.begin_shader_mode(self.splat_shader)
            try:
                for emission in emissions:
                    size = max(emission.scale, emission.expansion*2*STEP_SECONDS)
                    speed = emission.vel.length()
                    direction = emission.vel/speed if speed > 1e-5 else Vec2()
                    center = emission.pos+direction*(size*.35)-self.origin
                    strength = emission.color.a
                    if emission.source == "effect":
                        strength *= min(1., max(0., emission.color.r*.2126+emission.color.g*.7152+emission.color.b*.0722))
                    if emission.profile == "nuke":
                        strength *= 8.
                        self.decay = .12
                    self._set(self.splat_shader, self.splat_locations, "u_source", (center.x/self.size.x, center.y/self.size.y, size, strength))
                    self._set(self.splat_shader, self.splat_locations, "u_motion", (emission.vel.x, emission.vel.y, emission.expansion, float(emission.profile == "nuke")))
                    self._set(self.splat_shader, self.splat_locations, "u_rotation", (emission.rotation,))
                    radius = max(16., size*2.5)
                    x, y = (center.x-radius)/self.size.x*self.resolution, (center.y-radius)/self.size.y*self.resolution
                    rl.draw_rectangle_rec(rl_rectangle(x, y, radius*2/self.size.x*self.resolution, radius*2/self.size.y*self.resolution), rl.WHITE)
                    rl.rl_draw_render_batch_active()
            finally:
                rl.end_shader_mode()
                rl.end_blend_mode()

    def prepare(self, *, world_size: Vec2 | None = None) -> None:
        self._ensure()
        if not self.fields and not self.batches:
            return
        assert self.shader is not None and self.splat_shader is not None
        size = (world_size or Vec2(1024,1024))+Vec2(2*GUARD_BAND,2*GUARD_BAND)
        if size != self.size:
            self.size = size
            self.dirty_reset = True
        for field in self.fields.values():
            field.origin, field.size = self.origin, self.size
        for shader, locations in ((self.shader, self.locations), (self.splat_shader, self.splat_locations)):
            self._set(shader, locations, "u_world_size", (self.size.x, self.size.y))
        self._set(self.shader, self.locations, "u_dt", (STEP_SECONDS,))
        if self.dirty_reset:
            for target in self.targets:
                with texture_mode(target):
                    rl.clear_background(rl.BLANK)
            self.current = 0
            self.dirty_reset = False
        while self.batches:
            emissions, dt, fade = self.batches.popleft()
            if fade < 1.:
                self._set(self.shader, self.locations, "u_fade", (fade,))
                self._pass(1-self.current, self.current, 5)
                self.current = 1-self.current
            if emissions:
                self._inject(emissions)
            self.accumulator += dt
            while self.accumulator+1e-9 >= STEP_SECONDS:
                other = 1-self.current
                self._pass(other, self.current, 0)
                self._pass(2, other, 1)
                with texture_mode(self.targets[3]):
                    rl.clear_background(rl.BLANK)
                p = 3
                for _ in range(PRESSURE_ITERATIONS):
                    nxt = 7-p
                    self._pass(nxt, p, 2, 2)
                    p = nxt
                self._pass(self.current, other, 3, p)
                self.decay += STEP_SECONDS*(.20-self.decay)*.07
                self._set(self.shader, self.locations, "u_decay", (self.decay,))
                self._pass(other, self.current, 4)
                self.current = other
                self.accumulator = max(0., self.accumulator-STEP_SECONDS)
                self.executed_steps += 1

    def close(self) -> None:
        self.reset()
        for target in self.targets:
            rl.unload_render_texture(target)
        self.targets.clear()
        for shader in (self.shader, self.splat_shader):
            if shader is not None:
                rl.unload_shader(shader)
        self.shader = self.splat_shader = None
        self.locations.clear()
        self.splat_locations.clear()
