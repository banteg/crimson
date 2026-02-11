from __future__ import annotations

from .apply_context import PerkApplyCtx
from .hook_types import PerkHooks
from .ids import PerkId


def apply_lifeline_50_50(ctx: PerkApplyCtx) -> None:
    creatures = ctx.creatures
    if creatures is None:
        return

    kill_toggle = False
    for creature in creatures:
        if kill_toggle and creature.active and float(creature.hp) <= 500.0 and (int(creature.flags) & 0x04) == 0:
            creature.active = False
            ctx.state.effects.spawn_burst(
                pos=creature.pos,
                count=4,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )
        kill_toggle = not kill_toggle


HOOKS = PerkHooks(
    perk_id=PerkId.LIFELINE_50_50,
    apply_handler=apply_lifeline_50_50,
)
