from __future__ import annotations

from ...math_parity import f32, x87_pc24_add
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.hook_types import PerkHooks
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_living_fortress(ctx: PlayerPerkTickCtx) -> None:
    if perk_active(ctx.perk_player, PerkId.LIVING_FORTRESS):
        ctx.player.living_fortress_timer = min(
            f32(30.0),
            x87_pc24_add(
                float(ctx.player.living_fortress_timer),
                float(ctx.dt),
            ),
        )
    else:
        ctx.player.living_fortress_timer = 0.0


HOOKS = PerkHooks(
    perk_id=PerkId.LIVING_FORTRESS,
    player_tick_steps=(tick_living_fortress,),
)
