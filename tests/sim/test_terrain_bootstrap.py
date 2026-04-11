from __future__ import annotations

from crimson.rng_caller_static import RngCallerStatic
from grim.rand import Crand
from tests.support.helpers import ScriptedCrand


def test_advance_explicit_terrain_returns_render_boundary_and_mutates_rng() -> None:
    from crimson.sim.bootstrap import advance_explicit_terrain, terrain_stamping_draws

    terrain_slots = (2, 3, 2)
    seed = 0x1234
    rng = Crand(seed)
    expected_rng = Crand(seed)
    expected_rng.advance(terrain_stamping_draws(width=1024, height=1024))

    terrain = advance_explicit_terrain(
        rng,
        terrain_slots=terrain_slots,
        width=1024,
        height=1024,
    )

    assert terrain.terrain_slots == terrain_slots
    assert int(terrain.terrain_seed) == seed
    assert terrain.generation_kind.value == "explicit"
    assert int(rng.state) == int(expected_rng.state)


def test_advance_unlock_terrain_matches_native_rng_ordering() -> None:
    from crimson.quests import all_quests as _all_quests
    from crimson.sim.bootstrap import advance_unlock_terrain, terrain_stamping_draws
    from crimson.terrain_slots import choose_unlock_terrain_slots

    _ = _all_quests
    seed = 0xBEEF
    unlock_index = 0x28
    rng = Crand(seed)
    expected_rng = Crand(seed)

    expected_rng.advance(3)
    expected_slots = choose_unlock_terrain_slots(
        unlock_index=unlock_index,
        rng=expected_rng,
    )
    expected_seed = int(expected_rng.state)
    expected_rng.advance(terrain_stamping_draws(width=1024, height=1024))

    terrain = advance_unlock_terrain(
        rng,
        unlock_index=unlock_index,
        width=1024,
        height=1024,
    )

    assert terrain.terrain_slots == expected_slots
    assert int(terrain.terrain_seed) == expected_seed
    assert terrain.generation_kind.value == "unlock_random"
    assert int(rng.state) == int(expected_rng.state)


def test_advance_unlock_terrain_burns_hidden_random_prelude_before_unlock_rolls() -> None:
    from crimson.quests import all_quests as _all_quests
    from crimson.sim.bootstrap import advance_unlock_terrain
    from crimson.terrain_slots import Q2_TERRAIN_SLOTS

    _ = _all_quests
    rng = ScriptedCrand([3, 0, 0, 0, 0, 3], fallback=ScriptedCrand.Fallback.ZERO)

    terrain = advance_unlock_terrain(
        rng,
        unlock_index=0x28,
        width=0,
        height=0,
    )

    assert terrain.terrain_slots == Q2_TERRAIN_SLOTS
    assert int(terrain.terrain_seed) == 3
    assert int(rng.state) == 3
    assert int(rng.calls) == 6
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_1,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_2,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_3,
        RngCallerStatic.UNLOCK_TERRAIN_Q4,
        RngCallerStatic.UNLOCK_TERRAIN_Q3,
        RngCallerStatic.UNLOCK_TERRAIN_Q2,
    ]


def test_advance_explicit_terrain_records_tagged_stamp_callers() -> None:
    from crimson.sim.bootstrap import advance_explicit_terrain
    from grim.rand import RecordingCrand

    rng = RecordingCrand(Crand(0x1234))

    terrain = advance_explicit_terrain(
        rng,
        terrain_slots=(2, 3, 2),
        width=32,
        height=32,
    )

    assert terrain.terrain_slots == (2, 3, 2)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TERRAIN_GENERATE_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_BASE_X,
    ]


def test_advance_unlock_terrain_records_random_stamp_callers() -> None:
    from crimson.sim.bootstrap import advance_unlock_terrain
    from grim.rand import RecordingCrand

    rng = RecordingCrand(Crand(0xBEEF))

    terrain = advance_unlock_terrain(
        rng,
        unlock_index=0,
        width=32,
        height=32,
    )

    assert terrain.terrain_slots is not None
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_1,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_2,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_3,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_X,
    ]
