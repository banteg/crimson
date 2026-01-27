from __future__ import annotations

import math

import pyray as rl

from ..effects_atlas import effect_src_rect

CURSOR_EFFECT_ID = 0x0D


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def draw_cursor_glow(
    particles: rl.Texture | None,
    *,
    x: float,
    y: float,
    pulse_time: float | None = None,
    effect_id: int = CURSOR_EFFECT_ID,
) -> None:
    if particles is None:
        return
    src = effect_src_rect(
        int(effect_id),
        texture_width=float(particles.width),
        texture_height=float(particles.height),
    )
    if src is None:
        return

    src_rect = rl.Rectangle(src[0], src[1], src[2], src[3])
    origin = rl.Vector2(0.0, 0.0)

    rl.begin_blend_mode(rl.BLEND_ADDITIVE)
    if pulse_time is None:
        dst = rl.Rectangle(float(x - 32.0), float(y - 32.0), 64.0, 64.0)
        rl.draw_texture_pro(particles, src_rect, dst, origin, 0.0, rl.WHITE)
    else:
        alpha = (math.pow(2.0, math.sin(float(pulse_time))) + 2.0) * 0.32
        alpha = _clamp01(alpha)
        tint = rl.Color(255, 255, 255, int(alpha * 255.0 + 0.5))
        for dx, dy, size in (
            (-28.0, -28.0, 64.0),
            (-10.0, -18.0, 64.0),
            (-18.0, -10.0, 64.0),
            (-48.0, -48.0, 128.0),
        ):
            dst = rl.Rectangle(float(x + dx), float(y + dy), float(size), float(size))
            rl.draw_texture_pro(particles, src_rect, dst, origin, 0.0, tint)
    rl.end_blend_mode()


def draw_aim_cursor(
    particles: rl.Texture | None,
    aim: rl.Texture | None,
    *,
    x: float,
    y: float,
) -> None:
    draw_cursor_glow(particles, x=x, y=y)
    if aim is None:
        color = rl.Color(235, 235, 235, 220)
        rl.draw_circle_lines(int(x), int(y), 10, color)
        rl.draw_line(int(x - 14.0), int(y), int(x - 6.0), int(y), color)
        rl.draw_line(int(x + 6.0), int(y), int(x + 14.0), int(y), color)
        rl.draw_line(int(x), int(y - 14.0), int(x), int(y - 6.0), color)
        rl.draw_line(int(x), int(y + 6.0), int(x), int(y + 14.0), color)
        return
    src = rl.Rectangle(0.0, 0.0, float(aim.width), float(aim.height))
    dst = rl.Rectangle(float(x - 10.0), float(y - 10.0), 20.0, 20.0)
    rl.draw_texture_pro(aim, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)


def draw_menu_cursor(
    particles: rl.Texture | None,
    cursor: rl.Texture | None,
    *,
    x: float,
    y: float,
    pulse_time: float,
) -> None:
    draw_cursor_glow(particles, x=x, y=y, pulse_time=pulse_time)
    if cursor is None:
        return
    src = rl.Rectangle(0.0, 0.0, float(cursor.width), float(cursor.height))
    dst = rl.Rectangle(float(x - 2.0), float(y - 2.0), 32.0, 32.0)
    rl.draw_texture_pro(cursor, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

