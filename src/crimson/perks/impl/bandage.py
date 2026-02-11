from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def apply_bandage(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            scale = float(ctx.state.rng.rand() % 50 + 1)
            player.health = min(100.0, player.health * scale)
            ctx.state.effects.spawn_burst(
                pos=player.pos,
                count=8,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )


HOOKS = PerkHooks(
    perk_id=PerkId.BANDAGE,
    apply_handler=apply_bandage,
)
