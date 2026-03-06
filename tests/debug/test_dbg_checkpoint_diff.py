from __future__ import annotations

import struct

from crimson.dbg.checkpoint_diff import checkpoint_deepdiff
from crimson.replay.checkpoints import ReplayCheckpoint, ReplayPlayerCheckpoint, SurvivalReplayCheckpoint
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _next_float32(value: float, *, ulps: int) -> float:
    bits = struct.unpack(">I", struct.pack(">f", float(value)))[0]
    next_bits = int(bits) + int(ulps)
    return float(struct.unpack(">f", struct.pack(">I", next_bits))[0])


def _checkpoint_with_health(health: float) -> ReplayCheckpoint:
    return SurvivalReplayCheckpoint(
        tick_index=0,
        rng_state=123,
        sim_elapsed_ms=1000,
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
