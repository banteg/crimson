from __future__ import annotations

from .effects_context import PerksUpdateEffectsCtx
from .helpers import perk_count_get
from .ids import PerkId


def update_lean_mean_exp_machine(ctx: PerksUpdateEffectsCtx) -> None:
    ctx.state.lean_mean_exp_timer -= ctx.dt
    if ctx.state.lean_mean_exp_timer < 0.0:
        ctx.state.lean_mean_exp_timer = 0.25
        if not ctx.players:
            return

        # Native `perks_update_effects` uses global `perk_count_get` and awards the
        # periodic XP tick only to player 0 (`player_experience[0]`).
        player0 = ctx.players[0]
        perk_count = perk_count_get(player0, PerkId.LEAN_MEAN_EXP_MACHINE)
        if perk_count > 0:
            player0.experience += perk_count * 10
