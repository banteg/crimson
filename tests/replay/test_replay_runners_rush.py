from __future__ import annotations

import msgspec

from crimson.game_modes import GameMode
from crimson.sim.input_providers import PerkPickCommand, RngBurnOperation
from tests.support.replay_runner_helpers import ReplayRngTraceRecorder, _blank_rush_replay, _run_verify_playback


def test_rush_runner_is_deterministic() -> None:
    _header, rec = _blank_rush_replay(ticks=10, seed=0x1234)
    replay = rec.finish()

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.RUSH)
    assert result0.ticks == 10
    assert result0.elapsed_ms == 10 * int(1000.0 / 60.0)
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 2
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_rush_runner_uses_replay_dt_rows_for_elapsed_ms() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)

    result = _run_verify_playback(replay)

    assert result.elapsed_ms == 500


def test_rush_runner_rng_burn_prelude_shifts_rng_state() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234)
    replay = rec.finish()

    baseline = _run_verify_playback(replay)
    shifted_replay = msgspec.structs.replace(
        replay,
        ticks=[msgspec.structs.replace(tick, prelude=[RngBurnOperation(draws=1)]) for tick in replay.ticks],
    )
    shifted = _run_verify_playback(shifted_replay)
    shifted_again = _run_verify_playback(shifted_replay)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_rush_runner_ignores_stale_perk_pick_command() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        prelude=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    result = _run_verify_playback(replay)
    assert result.ticks == 1


def test_rush_runner_checkpoints_capture_debug_fields() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
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
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    observer = ReplayRngTraceRecorder(rows_by_tick={})

    _run_verify_playback(
        replay,
        trace_rng=True,
        observer=observer,
    )

    assert sorted(observer.rows_by_tick.keys()) == [0]
    assert observer.rows_by_tick[0]
