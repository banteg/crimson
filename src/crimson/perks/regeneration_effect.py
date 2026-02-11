from __future__ import annotations

from .effects_context import PerksUpdateEffectsCtx
from .helpers import perk_active
from .ids import PerkId


def update_regeneration(ctx: PerksUpdateEffectsCtx) -> None:
    if ctx.players and perk_active(ctx.players[0], PerkId.REGENERATION) and (ctx.state.rng.rand() & 1):
        for player in ctx.players:
            if not (0.0 < float(player.health) < 100.0):
                continue
            player.health = float(player.health) + ctx.dt
            if player.health > 100.0:
                player.health = 100.0
