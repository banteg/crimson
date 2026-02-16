from __future__ import annotations

from ..runtime.effects_context import PerksUpdateEffectsCtx
from ..helpers import perk_active
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def update_evil_eyes_target(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return

    source_player = ctx.aim_source_player()
    player0 = ctx.players[0]
    if source_player is None or not perk_active(source_player, PerkId.EVIL_EYES):
        player0.evil_eyes_target_creature = -1
        return

    target = ctx.aim_target()
    player0.evil_eyes_target_creature = target


HOOKS = PerkHooks(
    perk_id=PerkId.EVIL_EYES,
    effects_steps=(update_evil_eyes_target,),
)
