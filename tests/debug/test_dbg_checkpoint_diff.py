from __future__ import annotations

import struct

import msgspec

from crimson.dbg.checkpoint_diff import checkpoint_deepdiff, compare_checkpoints
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayCheckpointVec2,
    ReplayEventSummary,
    ReplayHitSummaryEntry,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from crimson.weapons import WeaponId


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
                pos=ReplayCheckpointVec2(0.0, 0.0),
                health=float(health),
                weapon_id=WeaponId.PISTOL,
                ammo=0.0,
                experience=0,
                level=1,
            ),
        ],
        bonus_timers={},
        deaths=[],
        perk=ReplayPerkSnapshot(
            pending_count=0,
            choices_dirty=False,
            choices=[0] * 7,
            player_nonzero_counts=[[]],
        ),
        events=ReplayEventSummary(
            hit_count=0,
            pickup_count=0,
            sfx_count=0,
            sfx_head=[],
            hit_head=[],
        ),
        tutorial=None,
        typo=None,
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


def test_compare_checkpoints_does_not_mask_state_when_elapsed_also_differs() -> None:
    expected = _checkpoint_with_health(1.0)
    actual = msgspec.structs.replace(expected, elapsed_ms=int(expected.elapsed_ms) + 16, score_xp=1)

    diff = compare_checkpoints([expected], [actual])

    assert not diff.ok
    assert diff.failure is not None
    assert diff.failure.tick_index == 0


def test_compare_checkpoints_rejects_rng_only_mismatch() -> None:
    expected = _checkpoint_with_health(1.0)
    actual = msgspec.structs.replace(expected, rng_state=int(expected.rng_state) + 1)

    diff = compare_checkpoints([expected], [actual])

    assert not diff.ok
    assert diff.failure is not None
    assert diff.failure.kind == "state_mismatch"


def test_compare_checkpoints_rejects_extra_actual_tick() -> None:
    expected = _checkpoint_with_health(1.0)
    extra = msgspec.structs.replace(expected, tick_index=1)

    diff = compare_checkpoints([expected], [expected, extra])

    assert not diff.ok
    assert diff.failure is not None
    assert diff.failure.kind == "extra_checkpoint"
    assert diff.failure.tick_index == 1


def test_compare_checkpoints_requires_hit_head_on_both_sides() -> None:
    expected = msgspec.structs.replace(
        _checkpoint_with_health(1.0),
        events=ReplayEventSummary(
            hit_count=1,
            pickup_count=0,
            sfx_count=0,
            sfx_head=[],
            hit_head=[],
        ),
    )
    actual = msgspec.structs.replace(
        expected,
        events=ReplayEventSummary(
            hit_count=1,
            pickup_count=0,
            sfx_count=0,
            sfx_head=[],
            hit_head=[
                ReplayHitSummaryEntry(
                    type_id=1,
                    origin=ReplayCheckpointVec2(1.0, 2.0),
                    hit=ReplayCheckpointVec2(3.0, 4.0),
                    target=ReplayCheckpointVec2(5.0, 6.0),
                ),
            ],
        ),
    )

    diff = compare_checkpoints([expected], [actual])

    assert not diff.ok
    assert diff.failure is not None
    assert diff.failure.tick_index == 0


def test_compare_checkpoints_compares_hit_head_when_both_sides_record_it() -> None:
    hit = ReplayHitSummaryEntry(
        type_id=1,
        origin=ReplayCheckpointVec2(1.0, 2.0),
        hit=ReplayCheckpointVec2(3.0, 4.0),
        target=ReplayCheckpointVec2(5.0, 6.0),
    )
    expected = msgspec.structs.replace(
        _checkpoint_with_health(1.0),
        events=ReplayEventSummary(
            hit_count=1,
            pickup_count=0,
            sfx_count=0,
            sfx_head=[],
            hit_head=[hit],
        ),
    )
    actual = msgspec.structs.replace(
        expected,
        events=ReplayEventSummary(
            hit_count=1,
            pickup_count=0,
            sfx_count=0,
            sfx_head=[],
            hit_head=[msgspec.structs.replace(hit, target=ReplayCheckpointVec2(7.0, 8.0))],
        ),
    )

    diff = compare_checkpoints([expected], [actual])

    assert not diff.ok
    assert diff.failure is not None
    assert diff.failure.tick_index == 0
