from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx
from ..runtime.counts import adjust_perk_count
from ..runtime.effects_context import PerksUpdateEffectsCtx
from ..helpers import perk_active, perk_count_get
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


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


def update_death_clock(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.DEATH_CLOCK):
        return

    # Native gates this effect on shared/player-0 perk state, then applies health
    # drain to every active local player.
    for player in ctx.players:
        if float(player.health) <= 0.0:
            player.health = 0.0
        else:
            player.health = float(player.health) - ctx.dt * 3.3333333


HOOKS = PerkHooks(
    perk_id=PerkId.DEATH_CLOCK,
    apply_handler=apply_death_clock,
    effects_steps=(update_death_clock,),
)
