from __future__ import annotations

from ...math_parity import f32, x87_pc24_mul, x87_pc24_sub
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx


def update_death_clock(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if PerkId.DEATH_CLOCK not in ctx.state.perks:
        return

    # Native gates this effect on shared/player-0 perk state, then applies health
    # drain to every active local player.
    drain = x87_pc24_mul(f32(float(ctx.dt)), f32(3.33333325))
    for player in ctx.players:
        if float(player.health) <= 0.0:
            player.health = 0.0
        else:
            player.health = x87_pc24_sub(f32(float(player.health)), drain)
