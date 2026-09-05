from __future__ import annotations

from ...math_parity import f32, x87_pc24_sub
from ..helpers import perk_count_get
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx


def update_lean_mean_exp_machine(ctx: PerksUpdateEffectsCtx) -> None:
    ctx.state.lean_mean_exp_timer = x87_pc24_sub(
        f32(float(ctx.state.lean_mean_exp_timer)),
        f32(float(ctx.dt)),
    )
    if ctx.state.lean_mean_exp_timer < 0.0:
        ctx.state.lean_mean_exp_timer = f32(0.25)
        if not ctx.players:
            return

        # Native `perks_update_effects` uses global `perk_count_get` and awards the
        # periodic XP tick only to player 0 (`player_experience[0]`).
        player0 = ctx.players[0]
        perk_count = perk_count_get(player0, PerkId.LEAN_MEAN_EXP_MACHINE)
        if perk_count > 0:
            player0.experience += perk_count * 10
