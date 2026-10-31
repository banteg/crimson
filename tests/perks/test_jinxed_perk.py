from __future__ import annotations

import pytest

from crimson.cl_build import ClBuild
from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.builders.session import make_world
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression

_FX_QUEUE_CALLERS = [
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
]
_JINXED_ZERO_ROLL_AFTER_0P2 = x87_pc24_add(
    x87_pc24_add(
        x87_pc24_mul(0.0, f32(0.1)),
        x87_pc24_sub(f32(0.0), f32(0.2)),
    ),
    f32(2.0),
)


@pytest.mark.parametrize("hp,death_timer", [(-10.0, 10.0), (0.0, 16.0), (100.0, 10.0)])
@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
def test_jinxed_retries_dead_or_dying_targets_only_in_default_mode(
    hp: float, death_timer: float, rules: int, preserve_bugs: bool,
) -> None:
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    legacy = preserve_bugs or rules == 1
    state, player = world.state, world.players[0]
    state.perks[PerkId.JINXED] = 1
    state.rng = ScriptedCrand([0, 0, 0, 1])  # no accident, timer, corpse, living target
    corpse = CreatureState(active=True, hp=hp, death_timer=death_timer, reward_value=100.0)
    living = CreatureState(active=True, hp=50.0, death_timer=16.0, reward_value=200.0)
    world.creatures.entries[0:2] = [corpse, living]
    player.experience = 100

    perks_update_effects(state, world.players, 0.01, creatures=world.creatures.entries, fx_queue=FxQueue())

    assert player.experience == (200 if legacy else 300)
    assert corpse.hp == (-1.0 if legacy else hp)
    expected_timer = x87_pc24_sub(f32(death_timer), x87_pc24_mul(f32(0.01), 20.0)) if legacy else death_timer
    assert corpse.death_timer == expected_timer
    assert living.hp == (50.0 if legacy else -1.0)
    retries = [r for r in state.rng.records_since() if r.caller == RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_RETRY]
    assert len(retries) == (0 if legacy else 1)


def test_jinxed_stops_after_ten_retries_without_rewarding_a_corpse() -> None:
    world = make_world()
    state, player = world.state, world.players[0]
    state.perks[PerkId.JINXED] = 1
    state.rng = ScriptedCrand([0] * 13)
    corpse = CreatureState(active=True, hp=-10.0, death_timer=10.0, reward_value=100.0)
    world.creatures.entries[0] = corpse

    perks_update_effects(state, world.players, 0.01, creatures=world.creatures.entries, fx_queue=FxQueue())

    assert player.experience == 0
    assert corpse.hp == -10.0 and corpse.death_timer == 10.0
    assert state.sfx_queue == []
    assert len(state.rng.records_since()) == 13


def test_perks_update_effects_jinxed_default_accident_can_hit_other_alive_players() -> None:
    dt = 0.2

    state = GameplayState(preserve_bugs=False)
    state.rng = ScriptedCrand(
        [
            3,  # accident roll
            1,  # alive-player selection: choose player index 1
            0,  # timer roll
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )
    state.bonuses.freeze = 1.0

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    state.perks[int(PerkId.JINXED)] = 1
    player1 = PlayerState(index=1, pos=Vec2(20.0, 20.0), health=70.0)

    fx_queue = FxQueue()

    perks_update_effects(state, [player0, player1], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, _JINXED_ZERO_ROLL_AFTER_0P2)
    assert_float_close(player0.health, 50.0)
    assert_float_close(player1.health, 65.0)
    assert fx_queue.count == 2
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        RngCallerStatic.REWRITE_JINXED_ACCIDENT_TARGET_PICK,
        *_FX_QUEUE_CALLERS,
        *_FX_QUEUE_CALLERS,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
    ]


def test_perks_update_effects_jinxed_preserve_bugs_keeps_accident_on_player0() -> None:
    dt = 0.2

    state = GameplayState(preserve_bugs=True)
    state.rng = ScriptedCrand(
        [
            3,  # accident roll
            0,  # timer roll
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )
    state.bonuses.freeze = 1.0

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    state.perks[int(PerkId.JINXED)] = 1
    player1 = PlayerState(index=1, pos=Vec2(20.0, 20.0), health=70.0)

    fx_queue = FxQueue()

    perks_update_effects(state, [player0, player1], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, _JINXED_ZERO_ROLL_AFTER_0P2)
    assert_float_close(player0.health, 45.0)
    assert_float_close(player1.health, 70.0)
    assert fx_queue.count == 2
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        *_FX_QUEUE_CALLERS,
        *_FX_QUEUE_CALLERS,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
    ]


def test_perks_update_effects_jinxed_default_skips_dead_players_without_extra_pick() -> None:
    dt = 0.2

    state = GameplayState(preserve_bugs=False)
    state.rng = ScriptedCrand(
        [
            3,  # accident roll
            0,  # timer roll
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )
    state.bonuses.freeze = 1.0

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    state.perks[int(PerkId.JINXED)] = 1
    player1 = PlayerState(index=1, pos=Vec2(20.0, 20.0), health=0.0)

    fx_queue = FxQueue()

    perks_update_effects(state, [player0, player1], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, _JINXED_ZERO_ROLL_AFTER_0P2)
    assert_float_close(player0.health, 45.0)
    assert_float_close(player1.health, 0.0)
    assert fx_queue.count == 2
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        *_FX_QUEUE_CALLERS,
        *_FX_QUEUE_CALLERS,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
    ]


@pytest.mark.parametrize(
    ("cl_build", "preserve_bugs", "kills"),
    [
        (ClBuild.V1_9_8, True, True),
        (ClBuild.V1_9_8, False, False),
        (ClBuild.V1_9_93, True, False),
    ],
)
def test_jinxed_kills_during_freeze_only_with_1_9_8_bugs(cl_build: ClBuild, preserve_bugs: bool, kills: bool) -> None:
    # 1.9.8 picks a creature with Freeze active (original bug 57); 1.9.93 returns after the timer reset.
    draws = 3 if kills else 2
    rng = ScriptedCrand([0] * draws)  # no accident, timer, creature pick
    state = GameplayState(cl_build=cl_build, preserve_bugs=preserve_bugs, rng=rng)
    state.perks[PerkId.JINXED] = 1
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2())
    target = CreatureState(active=True, hp=50.0, death_timer=16.0, reward_value=200.0)

    perks_update_effects(state, [player], 0.01, creatures=[target], fx_queue=FxQueue())

    assert target.hp == (-1.0 if kills else 50.0)
    assert player.experience == (200 if kills else 0)
    assert [request.sfx_id for request in state.sfx_queue] == [SfxId.TROOPER_INPAIN_01] * kills
    assert_rng_progression(rng, before_calls=0, before_state=0, expected_draws=draws)
