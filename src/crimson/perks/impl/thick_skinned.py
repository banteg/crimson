from __future__ import annotations

from ...math_parity import f32, x87_pc24_mul, x87_pc24_sub
from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks

# Native f32 literal 0.33333334 (one ulp above 1/3).
_THICK_SKINNED_FRACTION = float(f32(0.33333334))


def apply_thick_skinned(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            # Native computes `h - h * 0.33333334f` and stores f32. Its `= 1.0`
            # clamp only fires when the result is <= 0, which cannot happen for
            # positive health - dead code, so no floor here.
            health = f32(player.health)
            player.health = x87_pc24_sub(
                health,
                x87_pc24_mul(health, _THICK_SKINNED_FRACTION),
            )


HOOKS = PerkHooks(
    perk_id=PerkId.THICK_SKINNED,
    apply_handler=apply_thick_skinned,
)
