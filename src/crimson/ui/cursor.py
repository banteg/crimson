from __future__ import annotations

import math

import msgspec

from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.geom import Vec2
from grim.raylib_api import rl

from ..effects_atlas import EffectId, effect_src_rect

CURSOR_EFFECT_ID = int(EffectId.GLOW)


def draw_cursor_glow(particles: rl.Texture | None, *, pos: Vec2, alpha: float) -> None:
    """The aim reticle's single additive glow quad."""
    if particles is None:
        return
    src = effect_src_rect(CURSOR_EFFECT_ID, texture_width=float(particles.width), texture_height=float(particles.height))
    if src is None:
        return
    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.draw_texture_pro(
        particles,
        rl.Rectangle(*src),
        rl.Rectangle(float(pos.x - 32.0), float(pos.y - 32.0), 64.0, 64.0),
        rl.Vector2(0.0, 0.0),
        0.0,
        grim_color(1.0, 1.0, 1.0, alpha),
    )
    rl.end_blend_mode()


def draw_aim_cursor(
    particles: rl.Texture | None,
    aim: rl.Texture | None,
    *,
    pos: Vec2,
    alpha: float,
) -> None:
    """`ui_render_aim_enhancement`: the glow and reticle quads, both tinted by `cv_aimEnhancementFade`."""
    draw_cursor_glow(particles, pos=pos, alpha=alpha)
    if aim is None:
        color = rl.Color(235, 235, 235, 220)
        rl.draw_circle_lines(int(pos.x), int(pos.y), 10, color)
        rl.draw_line(int(pos.x - 14.0), int(pos.y), int(pos.x - 6.0), int(pos.y), color)
        rl.draw_line(int(pos.x + 6.0), int(pos.y), int(pos.x + 14.0), int(pos.y), color)
        rl.draw_line(int(pos.x), int(pos.y - 14.0), int(pos.x), int(pos.y - 6.0), color)
        rl.draw_line(int(pos.x), int(pos.y + 6.0), int(pos.x), int(pos.y + 14.0), color)
        return
    src = rl.Rectangle(0.0, 0.0, float(aim.width), float(aim.height))
    dst = rl.Rectangle(float(pos.x - 10.0), float(pos.y - 10.0), 20.0, 20.0)
    rl.draw_texture_pro(aim, src, dst, rl.Vector2(0.0, 0.0), 0.0, grim_color(1.0, 1.0, 1.0, alpha))


class _CursorPulse(msgspec.Struct):
    """Native `ui_cursor_pulse_phase`: only advances while a cursor renders."""

    phase: float = 0.0


_pulse = _CursorPulse()


def ui_cursor_render(resources: RuntimeResources, *, dt: float, pos: Vec2 | None = None) -> None:
    """`ui_cursor_render`: advance the pulse, draw four additive glow quads, then the arrow."""
    _pulse.phase += dt * 1.1
    if pos is None:
        pos = Vec2.from_xy(canvas.mouse_position())
    particles = resources.texture(TextureId.PARTICLES)
    src = effect_src_rect(CURSOR_EFFECT_ID, texture_width=float(particles.width), texture_height=float(particles.height))
    if src is not None:
        tint = grim_color(1.0, 1.0, 1.0, (math.sin(_pulse.phase) ** 2 + 2.0) * 0.32)
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        for dx, dy, size in ((-28.0, -28.0, 64.0), (-10.0, -18.0, 64.0), (-18.0, -10.0, 64.0), (-48.0, -48.0, 128.0)):
            rl.draw_texture_pro(
                particles,
                rl.Rectangle(*src),
                rl.Rectangle(float(pos.x + dx), float(pos.y + dy), size, size),
                rl.Vector2(0.0, 0.0),
                0.0,
                tint,
            )
        rl.end_blend_mode()
    cursor = resources.texture(TextureId.UI_CURSOR)
    rl.draw_texture_pro(
        cursor,
        rl.Rectangle(0.0, 0.0, float(cursor.width), float(cursor.height)),
        rl.Rectangle(float(pos.x - 2.0), float(pos.y - 2.0), 32.0, 32.0),
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )
