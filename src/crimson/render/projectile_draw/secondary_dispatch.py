from __future__ import annotations

from collections.abc import Callable

from .secondary_detonation import draw_secondary_detonation
from .secondary_rocket import draw_secondary_rocket, draw_secondary_type4_fallback
from .types import SecondaryProjectileDrawCtx

type SecondaryProjectileDrawHandler = Callable[[SecondaryProjectileDrawCtx], bool]

SECONDARY_PROJECTILE_DRAW_HANDLERS_BY_TYPE: dict[int, tuple[SecondaryProjectileDrawHandler, ...]] = {
    1: (draw_secondary_rocket,),
    2: (draw_secondary_rocket,),
    3: (draw_secondary_detonation,),
    4: (draw_secondary_rocket, draw_secondary_type4_fallback),
}


def draw_secondary_projectile_from_registry(ctx: SecondaryProjectileDrawCtx) -> bool:
    handlers = SECONDARY_PROJECTILE_DRAW_HANDLERS_BY_TYPE.get(int(ctx.proj_type), ())
    for handler in handlers:
        if handler(ctx):
            return True
    return False


__all__ = ["draw_secondary_projectile_from_registry"]
