"""Owned persistent fluid smoke: GPU simulation and lazy GPU display resources."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2

from ...perks import PerkId
from ..laser_sight import laser_sight_geometry
from .gpu_smoke import GpuSmokeSimulation
from .material_lights import MAX_ILLUMINATION_SOURCES, MaterialLight
from .smoke_composite import SmokeComposite
from .smoke_shaders import SMOKE_FRAGMENT, SMOKE_VERTEX

if TYPE_CHECKING:
    from ...sim.smoke_events import AtmosphereImpulse, SmokeEmission
    from ..frame import RenderFrame
    from ..world.context import WorldRenderCtx
    from ..world.viewport import ViewTransform
    from .smoke_simulation import SmokeSimulation


class SmokeRenderer:
    def __init__(self, *, cpu_reference: bool = False) -> None:
        self.simulation: SmokeSimulation | GpuSmokeSimulation
        if cpu_reference:
            from .smoke_simulation import SmokeSimulation

            self.simulation = SmokeSimulation()
        else:
            self.simulation = GpuSmokeSimulation()
        self.available = True
        self.compositor = SmokeComposite()
        self.shader: rl.Shader | None = None
        self.locations: dict[str, int] = {}
        self.textures: dict[int, rl.Texture] = {}
        self._uploaded: dict[int, tuple[int, int]] = {}
        self.prepared = False

    def reset(self) -> None:
        self.simulation.reset()
        self._uploaded.clear()
        self.prepared = False

    def consume(self, emissions: tuple[SmokeEmission, ...], *, dt_sim: float,
                impulses: tuple[AtmosphereImpulse, ...] = ()) -> None:
        if self.available:
            if isinstance(self.simulation, GpuSmokeSimulation):
                self.simulation.consume(emissions, dt_sim, impulses=impulses)
            else:
                self.simulation.consume(emissions, dt_sim)

    def _uniform(self, name: str, values: Sequence[float], *, count: int = 1) -> None:
        assert self.shader is not None
        width = len(values) // count
        kind = {
            1: rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT,
            2: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
            4: rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
        }[width]
        buffer = rl.ffi.new("float[]", list(values))
        rl.set_shader_value_v(self.shader, self.locations[name], rl.ffi.cast("void *", buffer), kind, count)

    def _integer(self, name: str, value: int) -> None:
        assert self.shader is not None
        rl.set_shader_value(
            self.shader, self.locations[name], rl.ffi.new("int *", value),
            rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
        )

    def select_lights(self, lights: Sequence[MaterialLight]) -> list[MaterialLight]:
        """Spend the smoke budget on overlapping emitters, including exhaust."""
        ranked = []
        for light in lights:
            if light.illumination_gain <= 0.0:
                continue
            reach = light.radius + light.length * .5 + light.ring_radius
            for field in self.simulation.fields.values():
                dx = max(field.origin.x - light.pos.x, 0., light.pos.x - field.origin.x - field.size.x)
                dy = max(field.origin.y - light.pos.y, 0., light.pos.y - field.origin.y - field.size.y)
                if dx * dx + dy * dy < reach * reach:
                    strength = max(light.rgb) * min(4., light.illumination_gain) * light.smoke_gain * light.radius
                    ranked.append((strength, light))
                    break
        ranked.sort(key=lambda pair: pair[0], reverse=True)
        return [light for _, light in ranked[:MAX_ILLUMINATION_SOURCES]]

    def prepare(self, frame: RenderFrame, lights: Sequence[MaterialLight]) -> None:
        self.prepared = False
        if not self.available:
            return
        if self.shader is None:
            shader = rl.load_shader_from_memory(SMOKE_VERTEX, SMOKE_FRAGMENT)
            if int(shader.id) <= 0 or shader.id == rl.rl_get_shader_id_default():
                logging.getLogger(__name__).warning("RTX smoke shader unavailable; using native smoke")
                self.available = False
                self.simulation.reset()
                return
            self.shader = shader
            self.locations = {name: int(rl.get_shader_location(shader, name)) for name in (
                "u_origin", "u_size", "u_opacity", "u_light_count", "u_light_pos", "u_light_rgb", "u_light_shape",
                "u_sight_count", "u_sights", "u_state_flip",
            )}
        if isinstance(self.simulation, GpuSmokeSimulation):
            try:
                ground = frame.ground
                self.simulation.prepare(world_size=Vec2(ground.width, ground.height) if ground is not None else None)
            except RuntimeError:
                logging.getLogger(__name__).warning("GPU smoke unavailable; using native smoke", exc_info=True)
                self.simulation.close()
                self.available = False
                return
        else:
            self._upload_reference()
        if not self.simulation.fields:
            return
        # The sight's reflection-only source is handled by narrow scattering,
        # never promoted to broad red illumination.
        self._integer("u_state_flip", int(isinstance(self.simulation, GpuSmokeSimulation)))
        illumination = self.select_lights(lights)
        self._integer("u_light_count", len(illumination))
        if illumination:
            self._uniform("u_light_pos", [v for l in illumination for v in (l.pos.x, l.pos.y, l.height, l.radius)], count=len(illumination))
            self._uniform("u_light_rgb", [v for l in illumination for v in (*l.rgb, min(4.0, l.illumination_gain) * l.smoke_gain)], count=len(illumination))
            self._uniform("u_light_shape", [v for l in illumination for v in (l.direction.x, l.direction.y, l.length * .5, l.ring_radius)], count=len(illumination))
        sights = []
        if PerkId.SHARPSHOOTER in frame.state.perks:
            for player in frame.players[:4]:
                if player.health > 0.0:
                    near, far, _ = laser_sight_geometry(player.pos, player.aim_heading)
                    sights.append((near.x, near.y, far.x, far.y))
        self._integer("u_sight_count", len(sights))
        if sights:
            self._uniform("u_sights", [v for sight in sights for v in sight], count=len(sights))
        self.prepared = True

    def _upload_reference(self) -> None:
        import numpy as np

        from .smoke_simulation import SmokeSimulation

        assert isinstance(self.simulation, SmokeSimulation)
        rl.rl_draw_render_batch_active()
        for slot, field in self.simulation.fields.items():
            if self._uploaded.get(slot) == (field.identity, field.version):
                continue
            height, width = field.density.shape
            previous = self.textures.get(slot)
            if previous is not None and (previous.width != width or previous.height != height):
                rl.unload_texture(previous)
                del self.textures[slot]
            if slot not in self.textures:
                fmt = rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32
                texture_id = int(rl.rl_load_texture(rl.ffi.NULL, width, height, fmt, 1))
                if texture_id <= 0:
                    raise RuntimeError("RTX fluid smoke texture allocation failed")
                texture = rl.Texture(texture_id, width, height, 1, fmt)
                rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
                rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
                self.textures[slot] = texture
            state = np.zeros((height, width, 4), dtype=np.float32)
            state[:, :, 0] = field.density
            state[:, :, 1] = field.temperature
            rl.update_texture(self.textures[slot], rl.ffi.cast("void *", rl.ffi.from_buffer(state)))
            self._uploaded[slot] = (field.identity, field.version)

    def draw(self, ctx: WorldRenderCtx, *, alpha: float) -> None:
        if not self.prepared or self.shader is None:
            return
        if isinstance(self.simulation, GpuSmokeSimulation):
            try:
                self.compositor.draw(ctx.view, lambda: self._draw_fields(ctx.view, alpha=alpha))
            except RuntimeError:
                logging.getLogger(__name__).warning("GPU smoke composite unavailable; using native smoke", exc_info=True)
                self.available = False
                self.simulation.close()
                self.compositor.close()
        else:
            rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
            try:
                self._draw_fields(ctx.view, alpha=alpha)
            finally:
                rl.end_blend_mode()

    def _draw_fields(self, view: ViewTransform, *, alpha: float) -> None:
        assert self.shader is not None
        rl.begin_shader_mode(self.shader)
        try:
            for slot, field in self.simulation.fields.items():
                rl.rl_draw_render_batch_active()
                self._uniform("u_origin", (field.origin.x, field.origin.y))
                self._uniform("u_size", (field.size.x, field.size.y))
                if isinstance(self.simulation, GpuSmokeSimulation):
                    texture = self.simulation.texture
                    width, height = texture.width, texture.height
                else:
                    texture = self.textures[slot]
                    width, height = texture.width, texture.height
                self._uniform("u_opacity", (alpha * field.fade,))
                origin = view.world_to_screen(field.origin)
                rl.draw_texture_pro(
                    texture, rl_rectangle(0, 0, width, height),
                    rl_rectangle(origin.x, origin.y, field.size.x * view.view_scale.x, field.size.y * view.view_scale.y),
                    rl_vector2(0, 0), 0.0, rl.WHITE,
                )
        finally:
            rl.end_shader_mode()

    def close(self) -> None:
        self.reset()
        self.available = True
        self.compositor.close()
        if isinstance(self.simulation, GpuSmokeSimulation):
            self.simulation.close()
        for texture in self.textures.values():
            rl.unload_texture(texture)
        self.textures.clear()
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
        self.locations.clear()
