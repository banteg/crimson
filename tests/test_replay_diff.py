from __future__ import annotations

from dataclasses import replace

from grim.geom import Vec2

from crimson.gameplay import PlayerState
from crimson.replay.checkpoints import build_checkpoint
from crimson.replay.diff import compare_checkpoints
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
