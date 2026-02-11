from __future__ import annotations

from .effects_context import PerksUpdateEffectsCtx
from .helpers import perk_active
from .hook_types import PerkHooks
from .ids import PerkId


def update_evil_eyes_target(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return

    target = ctx.aim_target()
    player0 = ctx.players[0]
    player0.evil_eyes_target_creature = target if perk_active(player0, PerkId.EVIL_EYES) else -1


HOOKS = PerkHooks(
    perk_id=PerkId.EVIL_EYES,
    effects_steps=(update_evil_eyes_target,),
)
