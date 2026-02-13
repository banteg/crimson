from __future__ import annotations

from dataclasses import replace

from grim.geom import Vec2

from crimson.sim.state_types import PlayerState
from crimson.replay.checkpoints import (
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    build_checkpoint,
)
from crimson.original.diff import checkpoint_field_diffs, compare_checkpoints
from crimson.sim.world_state import WorldState


def _base_world() -> WorldState:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    return world


def test_compare_checkpoints_ok() -> None:
    world = _base_world()
    ckpt = build_checkpoint(
        tick_index=0,
        world=world,
        elapsed_ms=0.0,
        rng_marks={"before_world_step": 1},
        command_hash="0123456789abcdef",
    )

    result = compare_checkpoints([ckpt], [ckpt])

    assert result.ok is True
    assert result.failure is None
    assert result.first_rng_only_tick is None


def test_compare_checkpoints_reports_missing_tick() -> None:
    world = _base_world()
    expected = build_checkpoint(tick_index=3, world=world, elapsed_ms=100.0)

    result = compare_checkpoints([expected], [])

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.kind == "missing_checkpoint"
    assert result.failure.tick_index == 3


def test_compare_checkpoints_reports_command_mismatch() -> None:
    world = _base_world()
    expected = build_checkpoint(tick_index=1, world=world, elapsed_ms=16.0, command_hash="aaaaaaaaaaaaaaaa")
    actual = replace(expected, command_hash="bbbbbbbbbbbbbbbb")

    result = compare_checkpoints([expected], [actual])

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.kind == "command_mismatch"
    assert result.failure.tick_index == 1


def test_compare_checkpoints_reports_state_mismatch_with_rng_mark() -> None:
    world = _base_world()
    expected = build_checkpoint(
        tick_index=7,
        world=world,
        elapsed_ms=123.0,
        rng_marks={"before_world_step": 10, "after_world_step": 20},
    )
    world.players[0].experience = 42
    actual = build_checkpoint(
        tick_index=7,
        world=world,
        elapsed_ms=123.0,
        rng_marks={"before_world_step": 11, "after_world_step": 20},
    )

    result = compare_checkpoints([expected], [actual])

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.kind == "state_mismatch"
    assert result.failure.tick_index == 7
    assert result.failure.first_rng_mark == "before_world_step"


def test_compare_checkpoints_tracks_rng_only_drift() -> None:
    world = _base_world()
    expected = build_checkpoint(
        tick_index=2,
        world=world,
        elapsed_ms=50.0,
        rng_marks={"before_world_step": 100},
        command_hash="abcdef0123456789",
    )
    actual = replace(
        expected,
        state_hash="ffffffffffffffff",
        rng_state=int(expected.rng_state) + 1,
        rng_marks={"before_world_step": 101},
    )

    result = compare_checkpoints([expected], [actual])

    assert result.ok is True
    assert result.failure is None
    assert result.first_rng_only_tick == 2


def test_compare_checkpoints_treats_unknown_sentinels_as_wildcards() -> None:
    world = _base_world()
    base = build_checkpoint(
        tick_index=5,
        world=world,
        elapsed_ms=80.0,
    )
    actual = replace(
        base,
        state_hash="1111111111111111",
        kills=9,
        deaths=[
            ReplayDeathLedgerEntry(
                creature_index=3,
                type_id=12,
                reward_value=100.0,
                xp_awarded=50,
                owner_id=0,
            )
        ],
        perk=ReplayPerkSnapshot(
            pending_count=0,
            choices_dirty=True,
            choices=[14, 33, 41],
            player_nonzero_counts=[[[14, 1], [33, 2]]],
        ),
        events=ReplayEventSummary(hit_count=7, pickup_count=2, sfx_count=3, sfx_head=["a", "b"]),
    )
    expected = replace(
        actual,
        state_hash="",
        kills=-1,
        deaths=[
            ReplayDeathLedgerEntry(
                creature_index=-1,
                type_id=-1,
                reward_value=0.0,
                xp_awarded=-1,
                owner_id=-1,
            )
        ],
        perk=ReplayPerkSnapshot(pending_count=-1),
        events=ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[]),
    )

    result = compare_checkpoints([expected], [actual])

    assert result.ok is True
    assert result.failure is None
    assert result.first_rng_only_tick == 5


def test_checkpoint_field_diffs_can_ignore_hash_rng_domains() -> None:
    world = _base_world()
    expected = build_checkpoint(
        tick_index=4,
        world=world,
        elapsed_ms=80.0,
        command_hash="aaaaaaaaaaaaaaaa",
        rng_marks={"before_world_step": 100},
    )
    actual = replace(
        expected,
        state_hash="ffffffffffffffff",
        command_hash="bbbbbbbbbbbbbbbb",
        rng_state=int(expected.rng_state) + 500,
        rng_marks={"before_world_step": 9999},
    )

    diffs = checkpoint_field_diffs(
        expected,
        actual,
        include_hash_fields=False,
        include_rng_fields=False,
    )

    assert diffs == []


def test_checkpoint_field_diffs_normalizes_elapsed_to_baseline() -> None:
    world = _base_world()
    expected = build_checkpoint(
        tick_index=9,
        world=world,
        elapsed_ms=250.0,
    )
    actual = replace(
        expected,
        state_hash="1234567890abcdef",
        elapsed_ms=int(expected.elapsed_ms) + 1000,
    )

    diffs = checkpoint_field_diffs(
        expected,
        actual,
        include_hash_fields=False,
        include_rng_fields=False,
        elapsed_baseline=(int(expected.elapsed_ms), int(actual.elapsed_ms)),
    )

    assert diffs == []


def test_checkpoint_field_diffs_reports_nested_paths() -> None:
    world = _base_world()
    expected = build_checkpoint(
        tick_index=1,
        world=world,
        elapsed_ms=16.0,
    )
    actual = replace(
        expected,
        players=[
            replace(
                expected.players[0],
                health=float(expected.players[0].health) - 5.0,
            )
        ],
    )

    diffs = checkpoint_field_diffs(
        expected,
        actual,
        include_hash_fields=False,
        include_rng_fields=False,
    )

    assert diffs
    assert diffs[0].field == "players[0].health"


def test_checkpoint_field_diffs_ignores_one_ms_reflex_timer_jitter() -> None:
    world = _base_world()
    expected = build_checkpoint(
        tick_index=3,
        world=world,
        elapsed_ms=48.0,
    )
    reflex_key = "9"
    expected_reflex = int(expected.bonus_timers.get(reflex_key, 0))
    if expected_reflex <= 1:
        expected_reflex = 81
    expected = replace(expected, bonus_timers={**expected.bonus_timers, reflex_key: int(expected_reflex)})
    actual_plus_one = replace(
        expected,
        bonus_timers={**expected.bonus_timers, reflex_key: int(expected_reflex + 1)},
    )
    actual_plus_two = replace(
        expected,
        bonus_timers={**expected.bonus_timers, reflex_key: int(expected_reflex + 2)},
    )

    tolerant = checkpoint_field_diffs(
        expected,
        actual_plus_one,
        include_hash_fields=False,
        include_rng_fields=False,
    )
    strict = checkpoint_field_diffs(
        expected,
        actual_plus_two,
        include_hash_fields=False,
        include_rng_fields=False,
    )

    assert tolerant == []
    assert strict
    assert strict[0].field == "bonus_timers.9"
