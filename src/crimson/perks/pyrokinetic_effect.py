from __future__ import annotations

from .effects_context import PerksUpdateEffectsCtx
from .helpers import perk_active
from .ids import PerkId


def update_pyrokinetic(ctx: PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if ctx.creatures is None:
        return
    if not perk_active(ctx.players[0], PerkId.PYROKINETIC):
        return

    target = ctx.aim_target()
    if target == -1:
        return
    creature = ctx.creatures[target]
    creature.collision_timer = float(creature.collision_timer) - float(ctx.dt)
    if creature.collision_timer < 0.0:
        creature.collision_timer = 0.5
        for intensity in (0.8, 0.6, 0.4, 0.3, 0.2):
            angle = float(int(ctx.state.rng.rand()) % 0x274) * 0.01
            ctx.state.particles.spawn_particle(pos=creature.pos, angle=angle, intensity=float(intensity))
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos=creature.pos, rand=ctx.state.rng.rand)
