from __future__ import annotations

from ...math_parity import f32, x87_pc24_mul, x87_pc24_sub
from ...rng_caller_static import RngCallerStatic
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx


def update_pyrokinetic(ctx: PerksUpdateEffectsCtx) -> None:


    players = ctx.players[:1] if ctx.state.preserve_bugs else ctx.players
    for player in players:
        if not perk_active(player, PerkId.PYROKINETIC):
            continue
        if (not ctx.state.preserve_bugs) and float(player.health) <= 0.0:
            continue

        target = ctx.aim_target_for_player(player.index)
        if target == -1:
            continue
        creature = ctx.creatures[target]
        creature.collision_timer = x87_pc24_sub(
            f32(float(creature.collision_timer)),
            f32(float(ctx.dt)),
        )
        if creature.collision_timer < 0.0:
            creature.collision_timer = 0.5
            for intensity, caller in (
                (0.8, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P8),
                (0.6, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P6),
                (0.4, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P4),
                (0.3, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P3),
                (0.2, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P2),
            ):
                angle = x87_pc24_mul(
                    float(ctx.state.rng.rand_tagged(caller) % 628),
                    f32(0.01),
                )
                ctx.state.particles.spawn_particle(pos=creature.pos, angle=angle, intensity=float(intensity))
            ctx.fx_queue.add_random(
                pos=creature.pos,
                rng=ctx.state.rng,
            )
