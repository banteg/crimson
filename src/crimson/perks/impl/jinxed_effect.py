from __future__ import annotations

from ..runtime.effects_context import PerksUpdateEffectsCtx
from ..helpers import perk_active
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def update_jinxed_timer(ctx: PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        ctx.state.jinxed_timer -= ctx.dt


def update_jinxed(ctx: PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        return
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.JINXED):
        return

    player = ctx.players[0]
    if int(ctx.state.rng.rand()) % 10 == 3:
        player.health = float(player.health) - 5.0
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos=player.pos, rand=ctx.state.rng.rand)
            ctx.fx_queue.add_random(pos=player.pos, rand=ctx.state.rng.rand)

    ctx.state.jinxed_timer = float(int(ctx.state.rng.rand()) % 0x14) * 0.1 + float(ctx.state.jinxed_timer) + 2.0

    if float(ctx.state.bonuses.freeze) <= 0.0 and ctx.creatures is not None:
        pool_mod = min(0x17F, len(ctx.creatures))
        if pool_mod <= 0:
            return

        idx = int(ctx.state.rng.rand()) % pool_mod
        attempts = 0
        while attempts < 10 and not ctx.creatures[idx].active:
            idx = int(ctx.state.rng.rand()) % pool_mod
            attempts += 1
        if not ctx.creatures[idx].active:
            return

        creature = ctx.creatures[idx]
        creature.hp = -1.0
        creature.hitbox_size = float(creature.hitbox_size) - ctx.dt * 20.0
        player.experience = int(float(player.experience) + float(creature.reward_value))
        ctx.state.sfx_queue.append("sfx_trooper_inpain_01")


HOOKS = PerkHooks(
    perk_id=PerkId.JINXED,
    effects_steps=(update_jinxed_timer, update_jinxed),
)
