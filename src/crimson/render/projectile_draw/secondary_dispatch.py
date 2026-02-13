from __future__ import annotations

from .secondary_detonation import draw_secondary_detonation, draw_secondary_type4_fallback
from .secondary_rocket import draw_secondary_rocket_like
from .types import SecondaryProjectileDrawCtx

SECONDARY_PROJECTILE_DRAW_HANDLERS = (
    draw_secondary_rocket_like,
    draw_secondary_type4_fallback,
    draw_secondary_detonation,
)


def draw_secondary_projectile_from_registry(ctx: SecondaryProjectileDrawCtx) -> bool:
    for handler in SECONDARY_PROJECTILE_DRAW_HANDLERS:
        if handler(ctx):
            return True
    return False


__all__ = ["draw_secondary_projectile_from_registry"]
