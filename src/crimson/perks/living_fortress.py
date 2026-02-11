from __future__ import annotations

from .helpers import perk_active
from .hook_types import PerkHooks
from .ids import PerkId
from .player_tick_context import PlayerPerkTickCtx


def tick_living_fortress(ctx: PlayerPerkTickCtx) -> None:
    if ctx.stationary and perk_active(ctx.player, PerkId.LIVING_FORTRESS):
        ctx.player.living_fortress_timer = min(30.0, ctx.player.living_fortress_timer + ctx.dt)
    else:
        ctx.player.living_fortress_timer = 0.0


HOOKS = PerkHooks(
    perk_id=PerkId.LIVING_FORTRESS,
    player_tick_steps=(tick_living_fortress,),
)
