"""Lazy analytic auras and independent, shadowless Monster Vision ground light."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import msgspec

from grim.blend import blend_custom
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl
from grim.texture_mode import current_target_size, texture_mode

from ...perks import PerkId
from ..world.constants import monster_vision_fade_alpha
from .hdr import _HDR_TONEMAP_VS_330
from .material_shaders import MONSTER_VISION_FRAGMENT

if TYPE_CHECKING:
    from ..frame import RenderFrame
    from ..world.viewport import ViewTransform
    from .materials import MaterialGroundRenderer

MONSTER_VISION_RADIUS = 60.0
# Keep each batch well below rlgl's capacity; auxiliary samplers are rebound after flushes.
_SOURCE_BATCH_SIZE = 256

MONSTER_VISION_VERTEX = r"""
#version 330
in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;
uniform mat4 mvp;
uniform vec2 u_camera;
uniform vec2 u_view_scale;
uniform vec2 u_ground_size;
out vec2 fragTexCoord;
out vec4 fragColor;
out vec3 perk_source;
void main() {
    vec2 world = vertexPosition.xy / u_view_scale - u_camera;
    fragTexCoord = vec2(world.x, u_ground_size.y - world.y) / u_ground_size;
    fragColor = vertexColor;
    // Each quad carries its own source center: no uniform uploads or light limit per enemy.
    perk_source = vec3(vertexTexCoord, vertexColor.a);
    gl_Position = mvp * vec4(vertexPosition, 1.);
}
"""

ANALYTIC_AURA_FRAGMENT = r"""
#version 330
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;
void main() {
    float r = length((fragTexCoord - .5) * 2.);
    float envelope = 1. - smoothstep(.8, 1., r);
    // Fit to the original AURA cell's alpha; retain its 90-unit footprint and yellow tint.
    float alpha = clamp(1.04770258 * exp(-4.85 * r) * envelope, 0., 1.);
    finalColor = vec4(fragColor.rgb, fragColor.a * alpha);
}
"""


class MonsterVisionSource(msgspec.Struct, frozen=True):
    pos: Vec2
    alpha: float


def monster_vision_sources(
    frame: RenderFrame, view: ViewTransform, *, entity_alpha: float = 1.0,
) -> list[MonsterVisionSource]:
    """All active/fading auras whose finite light support intersects the view; no ranking cap."""
    if PerkId.MONSTER_VISION not in frame.state.perks or entity_alpha <= 1e-3:
        return []
    lo = view.camera * -1.
    hi = lo + view.screen_size
    sources = []
    for creature in frame.creatures.entries:
        if not creature.active:
            continue
        alpha = monster_vision_fade_alpha(creature.death_timer) * clamp(entity_alpha, 0., 1.)
        p = creature.pos
        r = MONSTER_VISION_RADIUS
        if alpha <= 1e-3 or p.x + r <= lo.x or p.y + r <= lo.y or p.x - r >= hi.x or p.y - r >= hi.y:
            continue
        sources.append(MonsterVisionSource(p, alpha))
    return sources


class PerkLighting(msgspec.Struct):
    target: rl.RenderTexture | None = None
    shader: rl.Shader | None = None
    aura_shader: rl.Shader | None = None
    locations: dict[str, int] = msgspec.field(default_factory=dict)
    active: bool = False

    def ensure_aura_shader(self) -> rl.Shader:
        if self.aura_shader is None:
            shader = rl.load_shader_from_memory(_HDR_TONEMAP_VS_330, ANALYTIC_AURA_FRAGMENT)
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX Monster Vision aura shader compilation failed")
            self.aura_shader = shader
        return self.aura_shader

    @contextmanager
    def aura_scope(self, *, restore_shader: rl.Shader | None) -> Iterator[None]:
        rl.begin_shader_mode(self.ensure_aura_shader())
        try:
            yield
        finally:
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def _ensure(self, width: int, height: int) -> rl.Shader:
        if self.shader is None:
            shader = rl.load_shader_from_memory(MONSTER_VISION_VERTEX, MONSTER_VISION_FRAGMENT)
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX Monster Vision material shader compilation failed")
            self.shader = shader
            self.locations = {
                name: int(rl.get_shader_location(shader, name))
                for name in (
                    "u_camera", "u_view_scale", "u_ground_size", "u_time_s", "u_perk_component",
                    "u_surface_tex", "u_substrate_tex", "u_material_tex",
                )
            }
        if self.target is None or (self.target.texture.width, self.target.texture.height) != (width, height):
            # FP32 prevents repeated half-float blend rounding from dimming very
            # dense overlaps; this target contains only raw linear radiance.
            target = load_float_render_texture(
                width, height, pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32,
            )
            if self.target is not None:
                rl.unload_render_texture(self.target)
            self.target = target
            rl.set_texture_filter(target.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        return self.shader

    def prepare(
        self, ground: MaterialGroundRenderer, frame: RenderFrame, view: ViewTransform,
        *, entity_alpha: float = 1.0, debug: int | None = None,
    ) -> None:
        self.active = False
        mode = int(frame.rtx_debug) if debug is None else debug
        if mode not in (0, 5, 6, 7, 8, 14):
            return
        sources = monster_vision_sources(frame, view, entity_alpha=entity_alpha)
        if not sources:
            return
        width, height = current_target_size()
        if min(width, height, view.out_size.x, view.out_size.y) <= 0:
            return
        assert ground.surface is not None and ground.coverage is not None and ground.substrate is not None
        assert ground.substrate.render_target is not None
        shader = self._ensure(width, height)
        assert self.target is not None
        scale = view.view_scale.mul_components(Vec2(width / view.out_size.x, height / view.out_size.y))
        for name, value in (
            ("u_camera", view.camera), ("u_view_scale", scale),
            ("u_ground_size", Vec2(ground.width, ground.height)),
        ):
            values = rl.ffi.new("float[2]", [value.x, value.y])
            rl.set_shader_value(shader, self.locations[name], rl.ffi.cast("void *", values),
                                rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2)
        rl.set_shader_value(shader, self.locations["u_time_s"],
                            rl.ffi.new("float *", frame.elapsed_ms * .001 - ground.wetness_epoch),
                            rl.ShaderUniformDataType.SHADER_UNIFORM_FLOAT)
        component = 2 if mode in (5, 14) else 1 if mode in (6, 7, 8) else 0
        rl.set_shader_value(shader, self.locations["u_perk_component"], rl.ffi.new("int *", component),
                            rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
        lo = view.camera * -1.
        hi = lo + view.screen_size
        with texture_mode(self.target), blend_custom(rd.RL_ONE, rd.RL_ONE, rd.RL_FUNC_ADD):
            rl.clear_background(rl.BLANK)
            rl.begin_shader_mode(shader)
            try:
                for start in range(0, len(sources), _SOURCE_BATCH_SIZE):
                    # Raylib clears auxiliary sampler bindings when flushing its render batch.
                    rl.rl_draw_render_batch_active()
                    for name, texture in (
                        ("u_surface_tex", ground.surface.texture),
                        ("u_material_tex", ground.coverage.texture),
                        ("u_substrate_tex", ground.substrate.render_target.texture),
                    ):
                        rl.set_shader_value_texture(shader, self.locations[name], texture)
                    rl.rl_set_texture(rl.rl_get_texture_id_default())
                    rl.rl_begin(rd.RL_QUADS)
                    for source in sources[start:start + _SOURCE_BATCH_SIZE]:
                        p = source.pos
                        r = MONSTER_VISION_RADIUS
                        x0, y0 = max(lo.x, p.x - r), max(lo.y, p.y - r)
                        x1, y1 = min(hi.x, p.x + r), min(hi.y, p.y + r)
                        rl.rl_color4ub(255, 255, 255, int(source.alpha * 255 + .5))
                        # Positive winding in the screen's downwards Y coordinates.
                        for x, y in ((x0, y0), (x0, y1), (x1, y1), (x1, y0)):
                            rl.rl_tex_coord2f(p.x, p.y)
                            rl.rl_vertex2f((x + view.camera.x) * scale.x, (y + view.camera.y) * scale.y)
                    rl.rl_end()
                    rl.rl_set_texture(0)
                    rl.rl_draw_render_batch_active()
            finally:
                rl.end_shader_mode()
        self.active = True

    @contextmanager
    def ground_texture_scope(self, shader: rl.Shader) -> Iterator[None]:
        if self.target is None:
            yield
            return
        # Ground already uses all four rlgl auxiliary slots when body occlusion is
        # present. OpenGL 3.3 guarantees at least 16 fragment texture units; reserve
        # unit 5 explicitly without displacing those bindings or the base texture.
        rl.rl_draw_render_batch_active()
        rl.set_shader_value(shader, rl.get_shader_location(shader, "u_perk_tex"), rl.ffi.new("int *", 5),
                            rl.ShaderUniformDataType.SHADER_UNIFORM_INT)
        rl.rl_active_texture_slot(5)
        rl.rl_enable_texture(self.target.texture.id)
        rl.rl_active_texture_slot(0)
        try:
            yield
        finally:
            rl.rl_draw_render_batch_active()
            rl.rl_active_texture_slot(5)
            rl.rl_disable_texture()
            rl.rl_active_texture_slot(0)

    def close(self) -> None:
        if self.target is not None:
            rl.unload_render_texture(self.target)
        for shader in (self.shader, self.aura_shader):
            if shader is not None:
                rl.unload_shader(shader)
        self.target = self.shader = self.aura_shader = None
        self.locations.clear()
        self.active = False
