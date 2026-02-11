from __future__ import annotations

from ..runtime.effects_context import PerksUpdateEffectsCtx
from ..helpers import perk_active
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def update_regeneration(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.REGENERATION):
        return
    if (ctx.state.rng.rand() & 1) == 0:
        return

    heal_amount = ctx.dt
    # Native no-ops Greater Regeneration. In default rewrite mode we apply the
    # intended upgrade and keep the no-op behind `--preserve-bugs`.
    if (
        not bool(ctx.state.preserve_bugs)
        and perk_active(ctx.players[0], PerkId.GREATER_REGENERATION)
    ):
        heal_amount = ctx.dt * 2.0

    for player in ctx.players:
        if not (0.0 < float(player.health) < 100.0):
            continue
        player.health = float(player.health) + heal_amount
        if player.health > 100.0:
            player.health = 100.0


HOOKS = PerkHooks(
    perk_id=PerkId.REGENERATION,
    effects_steps=(update_regeneration,),
)
