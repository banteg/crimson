from __future__ import annotations

from ..runtime.effects_context import PerksUpdateEffectsCtx
from ..helpers import perk_active
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def update_regeneration(ctx: PerksUpdateEffectsCtx) -> None:
    if ctx.players and perk_active(ctx.players[0], PerkId.REGENERATION) and (ctx.state.rng.rand() & 1):
        for player in ctx.players:
            if not (0.0 < float(player.health) < 100.0):
                continue
            player.health = float(player.health) + ctx.dt
            if player.health > 100.0:
                player.health = 100.0


HOOKS = PerkHooks(
    perk_id=PerkId.REGENERATION,
    effects_steps=(update_regeneration,),
)
