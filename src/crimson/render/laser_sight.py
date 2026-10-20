"""Native Sharpshooter sight geometry shared by drawing and material reflections."""

from __future__ import annotations

from grim.geom import Vec2

from ..math_parity import NATIVE_HALF_PI, f32, f32_vec2, sin_f32, x87_pc24_cos_mul, x87_pc24_sin_mul


def laser_sight_geometry(player_pos: Vec2, aim_heading: float) -> tuple[Vec2, Vec2, Vec2]:
    """Return the near/far center and quad half-width, preserving native stores."""

    player_pos = f32_vec2(player_pos)
    aim_heading = f32(aim_heading)
    heading = f32(aim_heading - NATIVE_HALF_PI)
    # Native keeps the far cosine wide, but stores its sine before scaling.
    end = f32_vec2(
        player_pos + Vec2(x87_pc24_cos_mul(heading, 512.0), f32(sin_f32(heading) * 512.0)),
    )
    start_heading = f32(heading - f32(0.150915))
    start = f32_vec2(
        player_pos + Vec2(x87_pc24_cos_mul(start_heading, 15.0), x87_pc24_sin_mul(start_heading, 15.0)),
    )
    half_width = Vec2(
        x87_pc24_cos_mul(aim_heading, f32(1.1)),
        x87_pc24_sin_mul(aim_heading, f32(1.1)),
    )
    return start, end, half_width
