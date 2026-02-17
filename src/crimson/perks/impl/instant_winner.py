from __future__ import annotations

from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks


def apply_instant_winner(ctx: PerkApplyCtx) -> None:
    ctx.owner.experience += 2500


HOOKS = PerkHooks(
    perk_id=PerkId.INSTANT_WINNER,
    apply_handler=apply_instant_winner,
)
