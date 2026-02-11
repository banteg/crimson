from __future__ import annotations

from .apply_context import PerkApplyCtx
from .hook_types import PerkHooks
from .ids import PerkId


def apply_plaguebearer(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        player.plaguebearer_active = True


HOOKS = PerkHooks(
    perk_id=PerkId.PLAGUEBEARER,
    apply_handler=apply_plaguebearer,
)
