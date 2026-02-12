from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def apply_breathing_room(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        player.health -= player.health * (2.0 / 3.0)

    frame_dt = ctx.frame_dt()
    creatures = ctx.creatures
    if creatures is not None:
        for creature in creatures:
            if creature.active:
                creature.hitbox_size = float(creature.hitbox_size) - frame_dt

    ctx.state.bonus_spawn_guard = False


HOOKS = PerkHooks(
    perk_id=PerkId.BREATHING_ROOM,
    apply_handler=apply_breathing_room,
)
