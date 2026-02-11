from __future__ import annotations

from .apply_context import PerkApplyCtx
from .hook_types import PerkHooks
from .ids import PerkId


def apply_instant_winner(ctx: PerkApplyCtx) -> None:
    ctx.owner.experience += 2500


HOOKS = PerkHooks(
    perk_id=PerkId.INSTANT_WINNER,
    apply_handler=apply_instant_winner,
)
