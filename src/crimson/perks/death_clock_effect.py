from __future__ import annotations

from .effects_context import PerksUpdateEffectsCtx
from .helpers import perk_active
from .ids import PerkId


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
