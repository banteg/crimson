from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def apply_infernal_contract(ctx: PerkApplyCtx) -> None:
    ctx.owner.level += 3
    if ctx.perk_state is not None:
        ctx.perk_state.pending_count += 3
        ctx.perk_state.choices_dirty = True
    for player in ctx.players:
        if player.health > 0.0:
            player.health = 0.1


HOOKS = PerkHooks(
    perk_id=PerkId.INFERNAL_CONTRACT,
    apply_handler=apply_infernal_contract,
)
