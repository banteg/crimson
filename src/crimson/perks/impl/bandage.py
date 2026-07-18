from __future__ import annotations

from ...math_parity import f32, x87_pc24_add, x87_pc24_mul
from ...rng_caller_static import RngCallerStatic
from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks


def apply_bandage(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        # The native loop has no alive gate: dead players consume the rand,
        # have their (negative) health multiplied, and spawn a burst at the
        # corpse. The default mode keeps the documented fix of healing only
        # alive players (original-bugs.md item 3).
        if not ctx.state.preserve_bugs and player.health <= 0.0:
            continue
        amount = float(
            ctx.state.rng.rand_tagged(RngCallerStatic.PERK_APPLY_BANDAGE_HEAL)
            % 50
            + 1,
        )
        health = f32(player.health)
        if ctx.state.preserve_bugs:
            # Original exe behavior (likely bug): health multiplier.
            player.health = min(100.0, x87_pc24_mul(health, amount))
        else:
            # Intended behavior from in-game text: restore up to 50% HP.
            player.health = min(100.0, x87_pc24_add(health, amount))
        ctx.state.effects.spawn_burst(
            pos=player.pos,
            count=8,
            rng=ctx.state.rng,
            detail_preset=5,
        )


HOOKS = PerkHooks(
    perk_id=PerkId.BANDAGE,
    apply_handler=apply_bandage,
)
