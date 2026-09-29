from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim import run_init
from crimson.sim.bootstrap import advance_gameplay_reset_rng
from crimson.sim.run_spec import RunSpec, RunStatus
from crimson.sim.terrain_generate import terrain_generate, terrain_generate_random
from crimson.sim.world_state import WorldState
from crimson.terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    Q2_TERRAIN_SLOTS,
    Q3_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    TerrainSlotTriplet,
)
from grim.rand import CallerStatic, Crand, RecordingCrand
from tests.support.helpers import ScriptedCrand

_PRELUDE = [
    RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_1,
    RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_2,
    RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_3,
]
_Q4 = RngCallerStatic.UNLOCK_TERRAIN_Q4
_Q3 = RngCallerStatic.UNLOCK_TERRAIN_Q3
_Q2 = RngCallerStatic.UNLOCK_TERRAIN_Q2
# Stamps at 1024x1024: 1024 * 1024 * density / 0x80000 for densities 800, 35 and 15.
_EXPLICIT_STAMPS = [
    *[
        RngCallerStatic.TERRAIN_GENERATE_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_BASE_X,
    ]
    * 1600,
    *[
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_X,
    ]
    * 70,
    *[
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_X,
    ]
    * 30,
]
_RANDOM_STAMPS = [
    *[
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_X,
    ]
    * 1600,
    *[
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_X,
    ]
    * 70,
    *[
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_X,
    ]
    * 30,
]


@pytest.mark.parametrize(
    ("unlock_index", "rolls", "slots", "roll_callers"),
    [
        (19, [], DEFAULT_TERRAIN_SLOTS, []),
        (20, [3], Q2_TERRAIN_SLOTS, [_Q2]),
        (20, [2], DEFAULT_TERRAIN_SLOTS, [_Q2]),
        (29, [11], Q2_TERRAIN_SLOTS, [_Q2]),
        (30, [3], Q3_TERRAIN_SLOTS, [_Q3]),
        (30, [0, 3], Q2_TERRAIN_SLOTS, [_Q3, _Q2]),
        (39, [3], Q3_TERRAIN_SLOTS, [_Q3]),
        (39, [0, 0], DEFAULT_TERRAIN_SLOTS, [_Q3, _Q2]),
        (40, [3], Q4_TERRAIN_SLOTS, [_Q4]),
        (40, [7, 3], Q3_TERRAIN_SLOTS, [_Q4, _Q3]),
        (40, [0, 0, 3], Q2_TERRAIN_SLOTS, [_Q4, _Q3, _Q2]),
        (40, [0, 0, 0], DEFAULT_TERRAIN_SLOTS, [_Q4, _Q3, _Q2]),
    ],
)
def test_terrain_generate_random_branches(
    unlock_index: int,
    rolls: list[int],
    slots: TerrainSlotTriplet,
    roll_callers: list[CallerStatic],
) -> None:
    rng = ScriptedCrand([0, 0, 0, *rolls], fallback=ScriptedCrand.Fallback.ZERO)

    setup = terrain_generate_random(rng, unlock_index)

    assert setup.terrain_slots == slots
    # A successful roll runs `terrain_generate`, so its stamps carry the explicit generator's callers.
    stamps = _RANDOM_STAMPS if slots == DEFAULT_TERRAIN_SLOTS else _EXPLICIT_STAMPS
    assert [record.caller for record in rng.records_since()] == [*_PRELUDE, *roll_callers, *stamps]


def test_successful_unlock_roll_draws_the_explicit_terrain_from_the_next_state() -> None:
    seed = next(seed for seed in range(64) if (_advanced(seed, 3).rand() & 7) == 3)
    rng = Crand(seed)

    setup = terrain_generate_random(rng, 40)

    expected_rng = _advanced(seed, 4)
    assert setup == terrain_generate(expected_rng, Q4_TERRAIN_SLOTS)
    assert rng.state == expected_rng.state


def test_terrain_generate_records_explicit_stamp_callers_and_keeps_slots() -> None:
    rng = RecordingCrand(Crand(0x1234))

    setup = terrain_generate(rng, (2, 2, 3))

    assert setup.terrain_slots == (2, 2, 3)
    assert (len(setup.layers.base), len(setup.layers.overlay), len(setup.layers.detail)) == (1600, 70, 30)
    assert [record.caller for record in rng.records_since()] == _EXPLICIT_STAMPS


def test_stamp_rotation_is_the_native_float32_product() -> None:
    # Rotation draw 313, then y and x draws 0 and 1151: the extremes of `% 314` and `% (1024 + 128)`.
    rng = ScriptedCrand([313, 0, 1151], fallback=ScriptedCrand.Fallback.ZERO)

    stamp = terrain_generate(rng, DEFAULT_TERRAIN_SLOTS).layers.base[0]

    assert stamp.rotation == 3.129999876022339
    assert (stamp.x, stamp.y) == (1087.0, -64.0)


def test_quest_startup_draws_random_terrain_then_score_tag_then_quest_terrain(monkeypatch) -> None:
    callers: list[CallerStatic | None] = []
    build = WorldState.build

    def traced_build(*, hardcore: bool, quest_fail_retry_count: int, preserve_bugs: bool = False) -> WorldState:
        world = build(hardcore=hardcore, quest_fail_retry_count=quest_fail_retry_count, preserve_bugs=preserve_bugs)
        rng = world.state.rng
        assert isinstance(rng, Crand)
        rng.set_trace_sink(lambda _before, _after, _value, caller: callers.append(caller))
        return world

    monkeypatch.setattr(run_init.WorldState, "build", traced_build)
    level = QuestLevel(1, 1)
    quest = quest_by_level(level)
    assert quest is not None
    # Seed 0x103 passes the 4.x unlock roll, so the discarded first terrain is the delegated explicit one.
    spec = RunSpec(
        game_mode_id=GameMode.QUESTS,
        seed=0x103,
        quest_level=level,
        status=RunStatus(quest_unlock_index=40),
    )

    prepared = run_init.initialize_run(spec)

    rng = Crand(0x103)
    advance_gameplay_reset_rng(rng)
    random_terrain = terrain_generate_random(rng, 40)
    rng.rand_tagged(RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG)
    quest_terrain = terrain_generate(rng, quest.terrain_slots)
    assert random_terrain.terrain_slots == Q4_TERRAIN_SLOTS
    assert prepared.terrain == quest_terrain

    reset = [
        RngCallerStatic.GAMEPLAY_RESET_STATE_RANDOM_TAG,
        *[RngCallerStatic.GAMEPLAY_RESET_STATE_CREATURE_ANIM_PHASE] * 384,
        RngCallerStatic.GAMEPLAY_RESET_STATE_HIGHSCORE_RANDOM_TAG,
    ]
    startup = [
        *reset,
        *_PRELUDE,
        _Q4,
        *_EXPLICIT_STAMPS,
        RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG,
        *_EXPLICIT_STAMPS,
    ]
    assert callers[: len(startup)] == startup
    assert callers[-1] == RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED


def _advanced(seed: int, draws: int) -> Crand:
    rng = Crand(seed)
    rng.advance(draws)
    return rng
