from __future__ import annotations

from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx
from ..runtime.hook_types import PerkHooks


def update_pyrokinetic(ctx: PerksUpdateEffectsCtx) -> None:
    if ctx.creatures is None:
        return

    players = ctx.players[:1] if bool(ctx.state.preserve_bugs) else ctx.players
    for player in players:
        if not perk_active(player, PerkId.PYROKINETIC):
            continue
        if not bool(ctx.state.preserve_bugs) and float(player.health) <= 0.0:
            continue

        target = ctx.aim_target_for_player(player.index)
        if target == -1:
            continue
        creature = ctx.creatures[target]
        creature.collision_timer = float(creature.collision_timer) - float(ctx.dt)
        if creature.collision_timer < 0.0:
            creature.collision_timer = 0.5
            for intensity in (0.8, 0.6, 0.4, 0.3, 0.2):
                angle = float(int(ctx.state.rng.rand()) % 0x274) * 0.01
                ctx.state.particles.spawn_particle(pos=creature.pos, angle=angle, intensity=float(intensity))
            if ctx.fx_queue is not None:
                ctx.fx_queue.add_random(pos=creature.pos, rand=ctx.state.rng.rand)


HOOKS = PerkHooks(
    perk_id=PerkId.PYROKINETIC,
    effects_steps=(update_pyrokinetic,),
)
