from __future__ import annotations

from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx


def update_evil_eyes_target(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return

    if ctx.state.preserve_bugs:
        player0 = ctx.players[0]
        if not perk_active(player0, PerkId.EVIL_EYES):
            player0.evil_eyes_target_creature = -1
            return
        player0.evil_eyes_target_creature = ctx.aim_target_for_player(0)
        return

    for player in ctx.players:
        if float(player.health) <= 0.0:
            player.evil_eyes_target_creature = -1
            continue
        if not perk_active(player, PerkId.EVIL_EYES):
            player.evil_eyes_target_creature = -1
            continue
        player.evil_eyes_target_creature = ctx.aim_target_for_player(player.index)
