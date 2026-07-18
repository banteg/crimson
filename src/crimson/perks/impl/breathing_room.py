from __future__ import annotations

from ...math_parity import f32, x87_pc24_mul, x87_pc24_sub
from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks

_BREATHING_ROOM_FRACTION = f32(0.6666667)


def apply_breathing_room(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        health = f32(player.health)
        reduction = x87_pc24_mul(health, _BREATHING_ROOM_FRACTION)
        player.health = x87_pc24_sub(health, reduction)

    frame_dt = f32(ctx.frame_dt())
    creatures = ctx.creatures
    if creatures is not None:
        for creature in creatures:
            if creature.active:
                creature.lifecycle_stage = x87_pc24_sub(
                    f32(creature.lifecycle_stage),
                    frame_dt,
                )

    ctx.state.bonus_spawn_guard = False


HOOKS = PerkHooks(
    perk_id=PerkId.BREATHING_ROOM,
    apply_handler=apply_breathing_room,
)
