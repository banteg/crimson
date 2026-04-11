from __future__ import annotations

from ...rng_caller_static import RngCallerStatic
from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks


def apply_bandage(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            amount = float(
                ctx.state.rng.rand_tagged(RngCallerStatic.PERK_APPLY_BANDAGE_HEAL)
                % 50
                + 1,
            )
            if ctx.state.preserve_bugs:
                # Original exe behavior (likely bug): health multiplier.
                player.health = min(100.0, player.health * amount)
            else:
                # Intended behavior from in-game text: restore up to 50% HP.
                player.health = min(100.0, player.health + amount)
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
