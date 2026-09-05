from __future__ import annotations

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ...math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from ...rng_caller_static import RngCallerStatic
from ...sim.state_types import PlayerState
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.effects_context import PerksUpdateEffectsCtx


def _award_experience_once_from_reward(*, player: PlayerState, reward_value: float) -> int:
    reward_f32 = f32(float(reward_value))
    if float(reward_f32) <= 0.0:
        return 0

    before = int(player.experience)
    total_f32 = x87_pc24_add(f32(float(before)), reward_f32)
    after = int(float(total_f32))
    player.experience = int(after)
    return int(after - before)


def _select_jinxed_accident_target(ctx: PerksUpdateEffectsCtx) -> PlayerState:
    player0 = ctx.players[0]
    if ctx.state.preserve_bugs:
        return player0

    alive_players = [player for player in ctx.players if float(player.health) > 0.0]
    if not alive_players:
        return player0
    if len(alive_players) == 1:
        return alive_players[0]

    pick = ctx.state.rng.rand_tagged(RngCallerStatic.REWRITE_JINXED_ACCIDENT_TARGET_PICK) % len(alive_players)
    return alive_players[pick]


def update_jinxed_timer(ctx: PerksUpdateEffectsCtx) -> None:
    timer = f32(float(ctx.state.jinxed_timer))
    if timer >= 0.0:
        ctx.state.jinxed_timer = x87_pc24_sub(timer, f32(float(ctx.dt)))


def update_jinxed(ctx: PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        return
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.JINXED):
        return

    if ctx.state.rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE) % 10 == 3:
        player = _select_jinxed_accident_target(ctx)
        player.health = x87_pc24_sub(f32(float(player.health)), f32(5.0))
        ctx.fx_queue.add_random(
            pos=player.pos,
            rng=ctx.state.rng,
        )
        ctx.fx_queue.add_random(
            pos=player.pos,
            rng=ctx.state.rng,
        )

    timer_roll = float(
        ctx.state.rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET) % 20,
    )
    ctx.state.jinxed_timer = x87_pc24_add(
        x87_pc24_add(
            x87_pc24_mul(timer_roll, f32(0.1)),
            f32(float(ctx.state.jinxed_timer)),
        ),
        f32(2.0),
    )

    if float(ctx.state.bonuses.freeze) <= 0.0:
        pool_limit = 0x17F if ctx.state.preserve_bugs else 0x180
        pool_mod = min(pool_limit, len(ctx.creatures))
        if pool_mod <= 0:
            return

        idx = ctx.state.rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK) % pool_mod
        attempts = 0
        while attempts < 10 and not ctx.creatures[idx].active:
            idx = ctx.state.rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_RETRY) % pool_mod
            attempts += 1
        if not ctx.creatures[idx].active:
            return

        creature = ctx.creatures[idx]
        creature.hp = -1.0
        creature.lifecycle_stage = x87_pc24_sub(
            f32(float(creature.lifecycle_stage)),
            x87_pc24_mul(f32(float(ctx.dt)), f32(20.0)),
        )
        # Native awards the reward exactly once: the Jinxed kill branch has no
        # Double Experience handling, unlike creature_handle_death.
        _award_experience_once_from_reward(
            player=ctx.players[0],
            reward_value=float(creature.reward_value),
        )
        ctx.state.sfx_queue.append(SfxRequest(SfxId.TROOPER_INPAIN_01, creature.pos))
