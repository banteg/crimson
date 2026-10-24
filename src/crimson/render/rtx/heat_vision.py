"""Monster Vision in RTX: living monsters read as heat, and walk warm, fading trails into the ground.

Bodies take a second pass over each species' sprites (heat_body.frag), keyed to Monster Vision's own fade rather
than the creature's tint, so Hidden Evil's near-invisible aliens show in full. Trails live in a world-space buffer
at half the terrain's resolution: faded by game time, stamped with each monster's footprint, added under the bodies.
The sensor is selective: fire and explosions keep their own look and never wash the monsters out.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import msgspec

from grim.blend import blend_custom
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rd, rl, rl_rectangle
from grim.texture_mode import texture_mode

from ..world.constants import monster_vision_fade_alpha
from .creature_shaders import CREATURE_VERTEX
from .creature_translucency import load_thickness_texture
from .hdr import _HDR_TONEMAP_VS_330
from .shaders import glsl

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState
    from ..frame import RenderFrame
    from ..world.viewport import ViewTransform

TRAIL_TEXELS_PER_UNIT = 0.5
TRAIL_HALF_LIFE_S = 0.9
# A footprint's radius, as a share of the creature's size.
FOOTPRINT = 0.45
BODY_OPACITY = 0.88
# Softens the thickness proxy's squares, once per atlas: a 5x5 box per texel.
THICKNESS_BLUR = 2
# A monster frozen in Freeze's ice keeps this share of its warmth.
FROZEN_WARMTH = 0.3
# Longer gaps between frames (a seek, a stall) start the trails over.
MAX_GAP_MS = 1000.0

_HEAT_STAMP = glsl("heat_trail.frag").replace("#version 330\n", "#version 330\n#define HEAT_STAMP\n", 1)


def _load(vertex: str, fragment: str) -> rl.Shader:
    shader = rl.load_shader_from_memory(vertex, fragment)
    if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
        raise RuntimeError("RTX Monster Vision heat shader compilation failed")
    return shader


def _float(shader: rl.Shader, name: str, value: float) -> None:
    rl.set_shader_value(shader, rl.get_shader_location(shader, name), rl.ffi.new("float *", value),
                        rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT)


def _vec2(shader: rl.Shader, name: str, value: Vec2) -> None:
    buffer = rl.ffi.new("float[2]", [value.x, value.y])
    rl.set_shader_value(shader, rl.get_shader_location(shader, name), rl.ffi.cast("void *", buffer),
                        rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2)


def heat_visibility(creature: CreatureState, *, entity_alpha: float) -> float:
    """How strongly Monster Vision shows a monster: its native fade, never the creature's own tint alpha."""
    return min(monster_vision_fade_alpha(creature.death_timer) * entity_alpha, 1.0)


def heat_warmth(creature: CreatureState, frame: RenderFrame, *, entity_alpha: float) -> float:
    """How hot it reads: its visibility, cooled while Freeze holds it, with Freeze's own fade out."""
    frozen = min(max(frame.state.bonuses.freeze, 0.0), 1.0)
    return heat_visibility(creature, entity_alpha=entity_alpha) * (1.0 - (1.0 - FROZEN_WARMTH) * frozen)


class HeatVision(msgspec.Struct):
    trail: rl.RenderTexture | None = None
    stamp_shader: rl.Shader | None = None
    trail_shader: rl.Shader | None = None
    body_shader: rl.Shader | None = None
    thickness: dict[int, rl.Texture] = msgspec.field(default_factory=dict)
    last_ms: float | None = None

    def _ensure_trail(self, ground_size: Vec2) -> rl.RenderTexture:
        width = max(1, round(ground_size.x * TRAIL_TEXELS_PER_UNIT))
        height = max(1, round(ground_size.y * TRAIL_TEXELS_PER_UNIT))
        if self.trail is not None and (self.trail.texture.width, self.trail.texture.height) != (width, height):
            self.clear()
        if self.trail is None:
            self.trail = load_float_render_texture(width, height)
            rl.set_texture_filter(self.trail.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
            with texture_mode(self.trail):
                rl.clear_background(rl.BLANK)
            self.last_ms = None
        return self.trail

    def update(self, frame: RenderFrame, *, ground_size: Vec2) -> None:
        """Once per drawn frame: fade the trails by the game time since the last, then stamp every footprint.

        Stored heat ignores scene transitions; `draw_trails` fades it with the scene instead.
        """
        trail = self._ensure_trail(ground_size)
        if self.stamp_shader is None:
            self.stamp_shader = _load(_HDR_TONEMAP_VS_330, _HEAT_STAMP)
        shader = self.stamp_shader
        now = frame.elapsed_ms
        gap = None if self.last_ms is None else now - self.last_ms
        self.last_ms = now
        rl.rl_draw_render_batch_active()
        with texture_mode(trail):
            rl.begin_shader_mode(shader)
            try:
                if gap is None or gap < 0. or gap > MAX_GAP_MS:
                    rl.clear_background(rl.BLANK)
                elif gap > 0.:
                    _float(shader, "u_fade", 1. - .5 ** (gap * .001 / TRAIL_HALF_LIFE_S))
                    with blend_custom(rd.RL_ZERO, rd.RL_ONE_MINUS_SRC_ALPHA, rd.RL_FUNC_ADD):
                        rl.draw_rectangle(0, 0, trail.texture.width, trail.texture.height, rl.WHITE)
                _float(shader, "u_fade", -1.)
                with blend_custom(rd.RL_ONE, rd.RL_ONE, rd.RL_MAX):
                    rl.rl_set_texture(rl.rl_get_texture_id_default())
                    rl.rl_begin(rd.RL_QUADS)
                    for creature in frame.creatures.entries:
                        warmth = heat_warmth(creature, frame, entity_alpha=1.) if creature.active else 0.
                        if warmth <= 1e-3:
                            continue
                        p = creature.pos * TRAIL_TEXELS_PER_UNIT
                        r = creature.size * FOOTPRINT * TRAIL_TEXELS_PER_UNIT
                        rl.rl_color4ub(255, 255, 255, int(warmth * 255 + .5))
                        for u, v in ((0, 0), (0, 1), (1, 1), (1, 0)):
                            rl.rl_tex_coord2f(u, v)
                            rl.rl_vertex2f(p.x + (2 * u - 1) * r, p.y + (2 * v - 1) * r)
                    rl.rl_end()
                    rl.rl_set_texture(0)
                    rl.rl_draw_render_batch_active()
            finally:
                rl.end_shader_mode()

    def draw_trails(
        self, view: ViewTransform, *, ground_size: Vec2, entity_alpha: float, restore_shader: rl.Shader | None,
    ) -> None:
        if self.trail is None:
            return
        if self.trail_shader is None:
            self.trail_shader = _load(CREATURE_VERTEX, glsl("heat_trail.frag"))
        shader = self.trail_shader
        rl.rl_draw_render_batch_active()
        rl.begin_shader_mode(shader)
        try:
            _vec2(shader, "u_camera", view.camera)
            _vec2(shader, "u_view_scale", view.view_scale)
            _vec2(shader, "u_ground_size", ground_size)
            _float(shader, "u_alpha", entity_alpha)
            with blend_custom(rd.RL_ONE, rd.RL_ONE, rd.RL_FUNC_ADD):
                # Bind after the blend switch: rlgl clears auxiliary samplers when it flushes.
                rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_heat"), self.trail.texture)
                rl.draw_rectangle_rec(rl_rectangle(0, 0, view.out_size.x, view.out_size.y), rl.WHITE)
        finally:
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    @contextmanager
    def body_scope(self, *, texture: rl.Texture, restore_shader: rl.Shader | None) -> Iterator[None]:
        if self.body_shader is None:
            self.body_shader = _load(CREATURE_VERTEX, glsl("heat_body.frag"))
        shader = self.body_shader
        rl.rl_draw_render_batch_active()
        thickness = self.thickness.get(int(texture.id))
        if thickness is None:
            thickness = self.thickness[int(texture.id)] = load_thickness_texture(texture, blur=THICKNESS_BLUR)
        rl.begin_shader_mode(shader)
        try:
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_thickness"), thickness)
            yield
        finally:
            rl.rl_draw_render_batch_active()
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def clear(self) -> None:
        if self.trail is not None:
            rl.unload_render_texture(self.trail)
        self.trail = None
        self.last_ms = None

    def close(self) -> None:
        self.clear()
        for texture in self.thickness.values():
            rl.unload_texture(texture)
        self.thickness.clear()
        for shader in (self.stamp_shader, self.trail_shader, self.body_shader):
            if shader is not None:
                rl.unload_shader(shader)
        self.stamp_shader = self.trail_shader = self.body_shader = None
