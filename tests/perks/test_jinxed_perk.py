from __future__ import annotations

from crimson.effects import FxQueue
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close

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
