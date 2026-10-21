"""Owned persistent fluid smoke: CPU simulation, lazy GPU display resources."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import numpy as np

from grim.raylib_api import rl, rl_rectangle, rl_vector2

from ...perks import PerkId
from ..laser_sight import laser_sight_geometry
from .material_lights import MAX_ILLUMINATION_SOURCES, MaterialLight
from .smoke_shaders import SMOKE_FRAGMENT, SMOKE_VERTEX
from .smoke_simulation import FIELD_SIZE, GRID_SIZE, SmokeSimulation

if TYPE_CHECKING:
    from ...sim.smoke_events import SmokeEmission
    from ..frame import RenderFrame
    from ..world.context import WorldRenderCtx


class SmokeRenderer:
    def __init__(self) -> None:
        self.simulation = SmokeSimulation()
        self.shader: rl.Shader | None = None
        self.locations: dict[str, int] = {}
        self.textures: dict[int, rl.Texture] = {}
        self._uploaded: dict[int, tuple[int, int]] = {}
        self.prepared = False

    def reset(self) -> None:
        self.simulation.reset()
        self._uploaded.clear()
        self.prepared = False

    def consume(self, emissions: tuple[SmokeEmission, ...], *, dt_sim: float) -> None:
        self.simulation.consume(emissions, dt_sim)

    def claims_sprite(self, slot: int, generation: int) -> bool:
        return self.prepared and self.simulation.claims_entry("sprite", slot, generation)

    def claims_effect(self, slot: int, generation: int) -> bool:
        return self.prepared and self.simulation.claims_entry("effect", slot, generation)

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

    def prepare(self, frame: RenderFrame, lights: Sequence[MaterialLight]) -> None:
        self.prepared = False
        if not self.simulation.fields:
            return
        if self.shader is None:
            shader = rl.load_shader_from_memory(SMOKE_VERTEX, SMOKE_FRAGMENT)
            if int(shader.id) <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX fluid smoke shader compilation failed")
            self.shader = shader
            self.locations = {name: int(rl.get_shader_location(shader, name)) for name in (
                "u_origin", "u_opacity", "u_light_count", "u_light_pos", "u_light_rgb", "u_light_shape",
                "u_sight_count", "u_sights",
            )}
        rl.rl_draw_render_batch_active()
        for slot, field in self.simulation.fields.items():
            if self._uploaded.get(slot) == (field.identity, field.version):
                continue
            if slot not in self.textures:
                fmt = rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32
                texture_id = int(rl.rl_load_texture(rl.ffi.NULL, GRID_SIZE, GRID_SIZE, fmt, 1))
                if texture_id <= 0:
                    raise RuntimeError("RTX fluid smoke texture allocation failed")
                texture = rl.Texture(texture_id, GRID_SIZE, GRID_SIZE, 1, fmt)
                rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
                rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
                self.textures[slot] = texture
            state = np.zeros((GRID_SIZE, GRID_SIZE, 4), dtype=np.float32)
            state[:, :, 0] = field.density
            state[:, :, 1] = field.temperature
            rl.update_texture(self.textures[slot], rl.ffi.cast("void *", rl.ffi.from_buffer(state)))
            self._uploaded[slot] = (field.identity, field.version)
        # The sight's reflection-only source is handled by narrow scattering,
        # never promoted to broad red illumination.
        illumination = [light for light in lights if light.illumination_gain > 0.0][:MAX_ILLUMINATION_SOURCES]
        self._integer("u_light_count", len(illumination))
        if illumination:
            self._uniform("u_light_pos", [v for l in illumination for v in (l.pos.x, l.pos.y, l.height, l.radius)], count=len(illumination))
            self._uniform("u_light_rgb", [v for l in illumination for v in (*l.rgb, min(4.0, l.illumination_gain))], count=len(illumination))
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

    def draw(self, ctx: WorldRenderCtx, *, alpha: float) -> None:
        if not self.prepared or self.shader is None:
            return
        view = ctx.view
        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        rl.begin_shader_mode(self.shader)
        try:
            for slot, field in self.simulation.fields.items():
                rl.rl_draw_render_batch_active()
                self._uniform("u_origin", (field.origin.x, field.origin.y))
                self._uniform("u_opacity", (alpha * field.fade,))
                origin = view.world_to_screen(field.origin)
                rl.draw_texture_pro(
                    self.textures[slot], rl_rectangle(0, 0, GRID_SIZE, GRID_SIZE),
                    rl_rectangle(origin.x, origin.y, FIELD_SIZE * view.view_scale.x, FIELD_SIZE * view.view_scale.y),
                    rl_vector2(0, 0), 0.0, rl.WHITE,
                )
        finally:
            rl.end_shader_mode()
            rl.end_blend_mode()

    def close(self) -> None:
        self.reset()
        for texture in self.textures.values():
            rl.unload_texture(texture)
        self.textures.clear()
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
        self.locations.clear()
