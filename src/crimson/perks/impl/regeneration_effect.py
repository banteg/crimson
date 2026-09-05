from __future__ import annotations

from ...math_parity import f32, x87_pc24_add, x87_pc24_mul
from ...rng_caller_static import RngCallerStatic
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx


def update_regeneration(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.REGENERATION):
        return
    if (
        ctx.state.rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_REGENERATION_GATE)
        & 1
    ) == 0:
        return
    dt = f32(float(ctx.dt))

    if ctx.state.preserve_bugs:
        # Native `perks_update_effects` applies the regen tick to player 1 only,
        # and repeats that write loop by `config_player_count`.
        player0 = ctx.players[0]
        for _ in range(len(ctx.players)):
            if not (0.0 < float(player0.health) < 100.0):
                continue
            player0.health = x87_pc24_add(f32(float(player0.health)), dt)
            if player0.health > 100.0:
                player0.health = 100.0
        return

    heal_amount = dt
    # Native no-ops Greater Regeneration. In default rewrite mode we apply the
    # intended upgrade and keep the no-op behind `--preserve-bugs`.
    if (
        not ctx.state.preserve_bugs
        and perk_active(ctx.players[0], PerkId.GREATER_REGENERATION)
    ):
        heal_amount = x87_pc24_mul(dt, f32(2.0))

    for player in ctx.players:
        if not (0.0 < float(player.health) < 100.0):
            continue
        player.health = x87_pc24_add(
            f32(float(player.health)),
            heal_amount,
        )
        if player.health > 100.0:
            player.health = 100.0
