from __future__ import annotations

from .apply_context import PerkApplyCtx
from .counts import adjust_perk_count
from .helpers import perk_count_get
from .ids import PerkId


def apply_death_clock(ctx: PerkApplyCtx) -> None:
    adjust_perk_count(
        ctx.owner,
        PerkId.REGENERATION,
        amount=-perk_count_get(ctx.owner, PerkId.REGENERATION),
    )
    adjust_perk_count(
        ctx.owner,
        PerkId.GREATER_REGENERATION,
        amount=-perk_count_get(ctx.owner, PerkId.GREATER_REGENERATION),
    )
    for player in ctx.players:
        if player.health > 0.0:
            player.health = 100.0
