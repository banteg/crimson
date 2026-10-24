"""Ion arc contacts as round, additive ground glows instead of lights (material_lights.ion_contact_glows).

A contact's glow is always a disc; drawn on its own it no longer takes one of the lights' budget places, which ion
crowds would otherwise fill. Each quad's color carries the glow's hue at full value and its peak over GLOW_PEAK in
alpha (the vertex color stops at one), scaled by the scene's transition.
"""

from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.blend import blend_custom
from grim.geom import Vec2
from grim.raylib_api import rd, rl

from .hdr import _HDR_TONEMAP_VS_330
from .material_lights import ContactGlow
from .shaders import glsl

# contact_glow.frag's GLOW_PEAK.
GLOW_PEAK = 4.0


def glow_color(rgb: tuple[float, float, float], alpha: float) -> tuple[int, int, int, int]:
    """The vertex color that carries a glow's radiance: its hue at full value, its peak over GLOW_PEAK in alpha."""
    peak = max(max(rgb), 1e-6)

    def byte(value: float) -> int:
        return int(min(1., value) * 255 + .5)

    return byte(rgb[0] / peak), byte(rgb[1] / peak), byte(rgb[2] / peak), byte(peak / GLOW_PEAK * alpha)


class ContactGlows(msgspec.Struct):
    shader: rl.Shader | None = None

    def draw(self, glows: Sequence[ContactGlow], *, camera: Vec2, view_scale: Vec2, alpha: float,
             restore_shader: rl.Shader | None) -> None:
        if not glows or alpha <= 1e-3:
            return
        if self.shader is None:
            shader = rl.load_shader_from_memory(_HDR_TONEMAP_VS_330, glsl("contact_glow.frag"))
            if shader.id <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX contact glow shader compilation failed")
            self.shader = shader
        rl.rl_draw_render_batch_active()
        rl.begin_shader_mode(self.shader)
        try:
            with blend_custom(rd.RL_ONE, rd.RL_ONE, rd.RL_FUNC_ADD):
                rl.rl_set_texture(rl.rl_get_texture_id_default())
                rl.rl_begin(rd.RL_QUADS)
                for glow in glows:
                    rl.rl_color4ub(*glow_color(glow.rgb, alpha))
                    x, y = (glow.pos.x + camera.x) * view_scale.x, (glow.pos.y + camera.y) * view_scale.y
                    rx, ry = glow.radius * view_scale.x, glow.radius * view_scale.y
                    for u, v in ((0, 0), (0, 1), (1, 1), (1, 0)):
                        rl.rl_tex_coord2f(u, v)
                        rl.rl_vertex2f(x + (2 * u - 1) * rx, y + (2 * v - 1) * ry)
                rl.rl_end()
                rl.rl_set_texture(0)
                rl.rl_draw_render_batch_active()
        finally:
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
