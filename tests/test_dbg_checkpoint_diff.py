from __future__ import annotations

import struct

from crimson.dbg.checkpoint_diff import checkpoint_deepdiff
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


def test_checkpoint_deepdiff_one_ulp_tolerance_accepts_adjacent_float32() -> None:
    expected = _checkpoint_with_health(1.0)
    actual = _checkpoint_with_health(_next_float32(1.0, ulps=1))

    strict_ulps = checkpoint_deepdiff(
        expected,
        actual,
        float_abs_tol=0.0,
        float_ulp_tol=1,
    )
    assert strict_ulps is None

    exact_only = checkpoint_deepdiff(
        expected,
        actual,
        float_abs_tol=0.0,
        float_ulp_tol=0,
    )
    assert exact_only is not None
    assert exact_only.diff_count >= 1
    assert "players[0].health" in exact_only.pretty


def test_checkpoint_deepdiff_one_ulp_tolerance_rejects_two_ulp_delta() -> None:
    expected = _checkpoint_with_health(1.0)
    actual = _checkpoint_with_health(_next_float32(1.0, ulps=2))

    diff = checkpoint_deepdiff(
        expected,
        actual,
        float_abs_tol=0.0,
        float_ulp_tol=1,
    )
    assert diff is not None
    assert diff.diff_count >= 1
    assert "players[0].health" in diff.pretty
