from __future__ import annotations

from crimson.sim.run_result import RunOutcome
from crimson.weapons import WeaponId
from tests.support.replay_runner_helpers import (
    ReplayRngTraceRecorder,
    _blank_rush_replay,
    _run_verify_playback,
    finish_replay,
)


def test_rush_runner_is_deterministic() -> None:
    rec = _blank_rush_replay(ticks=10, seed=0x1234)
    replay = finish_replay(rec)

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

    assert result0 == result1 == replay.result
    assert result0.outcome == RunOutcome.INCOMPLETE
    assert result0.elapsed_ms == 10 * int(1000.0 / 60.0)
    assert result0.kills == 0
    assert result0.players[0].experience == 0
    assert result0.players[0].most_used_weapon_id == WeaponId.ASSAULT_RIFLE


def test_rush_runner_checkpoints_capture_debug_fields() -> None:
    rec = _blank_rush_replay(ticks=3, seed=0x1234)
    replay = finish_replay(rec)
    checkpoints = []

    _run_verify_playback(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0, 2},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0, 2]
    for ckpt in checkpoints:
        assert isinstance(ckpt.events.hit_count, int)
        assert isinstance(ckpt.events.pickup_count, int)
        assert isinstance(ckpt.events.sfx_count, int)
        assert isinstance(ckpt.deaths, list)


def test_rush_runner_tick_rng_trace_observer_emits_rows_for_first_tick() -> None:
    rec = _blank_rush_replay(ticks=1, seed=0x1234)
    replay = finish_replay(rec)
    observer = ReplayRngTraceRecorder(rows_by_tick={})

    _run_verify_playback(
        replay,
        trace_rng=True,
        observer=observer,
    )

    assert sorted(observer.rows_by_tick.keys()) == [0]
    assert observer.rows_by_tick[0]
