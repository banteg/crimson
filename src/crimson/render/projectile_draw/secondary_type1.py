from __future__ import annotations

from .secondary_rocket_common import SecondaryRocketStyle, draw_secondary_rocket_style
from .types import SecondaryProjectileDrawCtx

_TYPE1_ROCKET_STYLE = SecondaryRocketStyle(
    base_size=14.0,
    glow_size=60.0,
    glow_rgb=(1.0, 1.0, 1.0),
    glow_alpha_mul=0.68,
)


def draw_secondary_type1(ctx: SecondaryProjectileDrawCtx) -> bool:
    if int(ctx.proj_type) != 1:
        return False
    return draw_secondary_rocket_style(ctx, style=_TYPE1_ROCKET_STYLE)


__all__ = ["draw_secondary_type1"]
