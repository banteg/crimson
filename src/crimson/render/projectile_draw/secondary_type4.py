from __future__ import annotations

from .secondary_rocket_common import SecondaryRocketStyle, draw_secondary_rocket_style
from .types import SecondaryProjectileDrawCtx

_TYPE4_ROCKET_STYLE = SecondaryRocketStyle(
    base_size=8.0,
    glow_size=30.0,
    glow_rgb=(0.7, 0.7, 1.0),
    glow_alpha_mul=0.158,
)


def draw_secondary_type4(ctx: SecondaryProjectileDrawCtx) -> bool:
    if int(ctx.proj_type) != 4:
        return False
    return draw_secondary_rocket_style(ctx, style=_TYPE4_ROCKET_STYLE)


__all__ = ["draw_secondary_type4"]
