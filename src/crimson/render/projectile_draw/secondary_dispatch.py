from __future__ import annotations

from collections.abc import Callable

from ...projectiles.types import SecondaryProjectileTypeId
from .secondary_detonation import draw_secondary_detonation
from .secondary_rocket import (
    draw_secondary_projectile_bloom,
    draw_secondary_rocket,
    draw_secondary_type4_fallback,
)
from .types import SecondaryProjectileDrawCtx

type SecondaryProjectileDrawHandler = Callable[[SecondaryProjectileDrawCtx], bool]

SECONDARY_PROJECTILE_DRAW_HANDLERS_BY_TYPE: dict[int, tuple[SecondaryProjectileDrawHandler, ...]] = {
    SecondaryProjectileTypeId.ROCKET: (draw_secondary_rocket,),
    SecondaryProjectileTypeId.HOMING_ROCKET: (draw_secondary_rocket,),
    SecondaryProjectileTypeId.DETONATION: (draw_secondary_detonation,),
    SecondaryProjectileTypeId.ROCKET_MINIGUN: (draw_secondary_rocket, draw_secondary_type4_fallback),
}


def draw_secondary_projectile_from_registry(ctx: SecondaryProjectileDrawCtx) -> bool:
    # Native projectile_render owns this common pass separately from the
    # type-specific rocket sprite/glow passes, so exploding entries retain it.
    draw_secondary_projectile_bloom(ctx)

    handlers = SECONDARY_PROJECTILE_DRAW_HANDLERS_BY_TYPE.get(int(ctx.proj_type), ())
    for handler in handlers:
        if handler(ctx):
            return True
    return False


__all__ = ["draw_secondary_projectile_from_registry"]
