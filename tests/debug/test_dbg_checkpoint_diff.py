from __future__ import annotations

import struct

import msgspec

from crimson.dbg.checkpoint_diff import checkpoint_deepdiff, compare_checkpoints
from crimson.replay.checkpoints import ReplayCheckpoint, ReplayPlayerCheckpoint
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _next_float32(value: float, *, ulps: int) -> float:
    bits = struct.unpack(">I", struct.pack(">f", float(value)))[0]
    next_bits = int(bits) + int(ulps)
    return float(struct.unpack(">f", struct.pack(">I", next_bits))[0])


def _checkpoint_with_health(health: float) -> ReplayCheckpoint:
    return ReplayCheckpoint(
        tick_index=0,
        rng_state=123,
        elapsed_ms=1000,
        score_xp=0,
        kills=0,
        creature_count=0,
        perk_pending=0,
        players=[
            ReplayPlayerCheckpoint(
                pos=Vec2(0.0, 0.0),
                health=float(health),
                weapon_id=WeaponId.PISTOL,
                ammo=0.0,
                experience=0,
                level=1,
            ),
        ],
        bonus_timers={},
    )


def test_checkpoint_deepdiff_requires_exact_match() -> None:
    expected = _checkpoint_with_health(1.0)
    actual = _checkpoint_with_health(_next_float32(1.0, ulps=1))

    diff = checkpoint_deepdiff(expected, actual)
    assert diff is not None
    assert diff.diff_count >= 1
    assert "players[0].health" in diff.pretty


def test_checkpoint_deepdiff_returns_none_for_identical_objects() -> None:
    expected = _checkpoint_with_health(1.0)
    actual = _checkpoint_with_health(1.0)

    assert checkpoint_deepdiff(expected, actual) is None


def test_compare_checkpoints_can_skip_elapsed_mismatch_rows() -> None:
    first_expected = _checkpoint_with_health(1.0)
    first_actual = msgspec.structs.replace(first_expected, elapsed_ms=int(first_expected.elapsed_ms) + 16)
    second_expected = msgspec.structs.replace(_checkpoint_with_health(1.0), tick_index=1)
    second_actual = msgspec.structs.replace(second_expected, score_xp=1)

    diff = compare_checkpoints(
        [first_expected, second_expected],
        [first_actual, second_actual],
        skip_elapsed_mismatch=True,
    )

    assert not diff.ok
    assert diff.skipped_elapsed_mismatch_count == 1
    assert diff.failure is not None
    assert diff.failure.tick_index == 1
