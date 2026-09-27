from __future__ import annotations

from ...math_parity import f32, x87_pc24_add
from ..ids import PerkId
from ..runtime.player_tick_context import PlayerPerkTickCtx


def tick_living_fortress(ctx: PlayerPerkTickCtx) -> None:
    if PerkId.LIVING_FORTRESS in ctx.state.perks:
        ctx.player.living_fortress_timer = min(
            f32(30.0),
            x87_pc24_add(
                float(ctx.player.living_fortress_timer),
                float(ctx.dt),
            ),
        )
    else:
        ctx.player.living_fortress_timer = 0.0
