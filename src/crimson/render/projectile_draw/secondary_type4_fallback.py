from __future__ import annotations

import pyray as rl

from .types import SecondaryProjectileDrawCtx


def draw_secondary_type4_fallback(ctx: SecondaryProjectileDrawCtx) -> bool:
    if int(ctx.proj_type) != 4:
        return False
    rl.draw_circle(
        int(ctx.screen_pos.x),
        int(ctx.screen_pos.y),
        max(1.0, 12.0 * ctx.scale),
        rl.Color(200, 120, 255, int(255 * ctx.alpha + 0.5)),
    )
    return True


__all__ = ["draw_secondary_type4_fallback"]
