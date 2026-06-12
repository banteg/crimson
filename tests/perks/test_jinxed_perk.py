from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression

_FX_QUEUE_CALLERS = [
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
]


def test_perks_update_effects_jinxed_kills_creature_and_awards_base_reward() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x17F)]
    creatures[2].active = True
    creatures[2].hp = 100.0
    creatures[2].lifecycle_stage = 16.0
    creatures[2].reward_value = 12.7

    state = GameplayState()
    state.rng = ScriptedCrand(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            2,  # creature index: rand%0x17f
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=100, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert_float_close(state.jinxed_timer, 1.8)
    assert creatures[2].hp == -1.0
    assert_float_close(creatures[2].lifecycle_stage, 16.0 - dt * 20.0)
    assert player.experience == 112
    assert state.sfx_queue == [SfxId.TROOPER_INPAIN_01]
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK,
    ]


def test_perks_update_effects_jinxed_award_uses_float32_sum_before_truncation() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x17F)]
    creatures[2].active = True
    creatures[2].hp = 100.0
    creatures[2].lifecycle_stage = 16.0
    creatures[2].reward_value = 97.99636190476191

    state = GameplayState()
    state.rng = ScriptedCrand(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            2,  # creature index: rand%0x17f
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=139_451, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert player.experience == 139_549
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK,
    ]


def test_perks_update_effects_jinxed_accident_damages_player_and_spawns_fx() -> None:
    dt = 0.2

    state = GameplayState()
    state.rng = ScriptedCrand(
        [
            3,  # accident roll
            0,  # timer roll
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )
    state.bonuses.freeze = 1.0

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, 1.8)
    assert_float_close(player.health, 45.0)
    assert fx_queue.count == 2
    assert state.sfx_queue == []
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        *_FX_QUEUE_CALLERS,
        *_FX_QUEUE_CALLERS,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
    ]


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
    player0.perk_counts[int(PerkId.JINXED)] = 1
    player1 = PlayerState(index=1, pos=Vec2(20.0, 20.0), health=70.0)

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player0, player1], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, 1.8)
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
    player0.perk_counts[int(PerkId.JINXED)] = 1
    player1 = PlayerState(index=1, pos=Vec2(20.0, 20.0), health=70.0)

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player0, player1], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, 1.8)
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
    player0.perk_counts[int(PerkId.JINXED)] = 1
    player1 = PlayerState(index=1, pos=Vec2(20.0, 20.0), health=0.0)

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player0, player1], dt, creatures=[], fx_queue=fx_queue)

    assert_float_close(state.jinxed_timer, 1.8)
    assert_float_close(player0.health, 45.0)
    assert_float_close(player1.health, 0.0)
    assert fx_queue.count == 2
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        *_FX_QUEUE_CALLERS,
        *_FX_QUEUE_CALLERS,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
    ]


def test_perks_update_effects_jinxed_default_uses_full_384_slot_pool() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x180)]
    creatures[0x17F].active = True
    creatures[0x17F].hp = 100.0
    creatures[0x17F].lifecycle_stage = 16.0
    creatures[0x17F].reward_value = 12.7

    state = GameplayState(preserve_bugs=False)
    state.rng = ScriptedCrand(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            0x17F,  # creature index: rand%0x180
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=100, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert creatures[0x17F].hp == -1.0
    assert player.experience == 112
    assert state.sfx_queue == [SfxId.TROOPER_INPAIN_01]
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK,
    ]


def test_perks_update_effects_jinxed_preserve_bugs_keeps_383_slot_rolls() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x180)]
    creatures[0x17F].active = True
    creatures[0x17F].hp = 100.0
    creatures[0x17F].lifecycle_stage = 16.0
    creatures[0x17F].reward_value = 12.7

    state = GameplayState(preserve_bugs=True)
    state.rng = ScriptedCrand(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            0x17F,  # creature index: rand%0x17f -> 0
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=100, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert creatures[0x17F].hp == 100.0
    assert player.experience == 100
    assert state.sfx_queue == []
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK,
        *([RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_RETRY] * 10),
    ]


def test_perks_update_effects_jinxed_retries_inactive_creature_pick() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x17F)]
    creatures[2].active = True
    creatures[2].hp = 100.0
    creatures[2].lifecycle_stage = 16.0
    creatures[2].reward_value = 12.7

    state = GameplayState()
    state.rng = ScriptedCrand(
        [
            0,  # accident roll: rand%10 != 3
            0,  # timer roll: (rand%0x14)*0.1
            1,  # first creature index: inactive
            2,  # retry creature index: active
        ],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=100, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    assert creatures[2].hp == -1.0
    assert player.experience == 112
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK,
        RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_RETRY,
    ]


def test_perks_update_effects_jinxed_timer_uses_f32_underflow_threshold() -> None:
    # Capture boundary from gameplay_diff_capture tick 5163:
    # native decrements to a tiny positive value and does not proc Jinxed this tick.
    dt = 0.03400000184774399

    state = GameplayState()
    state.jinxed_timer = 0.034000836312770844
    rng = ScriptedCrand([3, 0, 7, 9], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state.rng = rng
    before_calls = rng.calls
    before_state = rng.state

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=[])

    assert_float_close(state.jinxed_timer, 8.344650268554688e-07)
    assert_float_close(player.health, 50.0)
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=before_state,
    )
    assert rng.values_since(before_calls) == []


def test_perks_update_effects_jinxed_award_ignores_double_experience_bonus() -> None:
    dt = 0.2
    creatures = [CreatureState() for _ in range(0x17F)]
    creatures[2].active = True
    creatures[2].hp = 100.0
    creatures[2].lifecycle_stage = 16.0
    creatures[2].reward_value = 12.7

    state = GameplayState()
    state.bonuses.double_experience = 5.0
    state.rng = ScriptedCrand([0, 0, 2], fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), experience=100, health=50.0)
    player.perk_counts[int(PerkId.JINXED)] = 1

    perks_update_effects(state, [player], dt, creatures=creatures)

    # Native's Jinxed kill branch has a single XP store with no
    # bonus_double_xp_timer handling.
    assert player.experience == 112
