from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.driver.setup import ReplayRunnerError
from tests.replay_runner_helpers import _blank_rush_replay


def test_rush_runner_is_deterministic() -> None:
    _header, rec = _blank_rush_replay(ticks=10, seed=0x1234)
    replay = rec.finish()

    result0 = run_replay(replay)
    result1 = run_replay(replay)

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
    replay.dt[0] = 0.5

    result = run_replay(replay)

    assert result.elapsed_ms == 500


def test_rush_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234)
    replay = rec.finish()

    baseline = run_replay(replay)
    shifted = run_replay(replay, inter_tick_rand_draws=1)
    shifted_again = run_replay(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_rush_runner_rejects_events() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234)
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.raises(ReplayRunnerError, match="unsupported perk_pick"):
        run_replay(replay)


def test_rush_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
    checkpoints = []

    run_replay(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0, 2},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0, 2]
    for ckpt in checkpoints:
        assert {
            "before_world_step",
            "gw_begin",
            "gw_after_weapon_refresh",
            "gw_after_perks_rebuild",
            "gw_after_time_scale",
            "after_world_step",
            "after_rush_spawns",
        }.issubset(ckpt.rng_marks.keys())
        assert {
            "ws_begin",
            "ws_after_particles_update",
            "ws_after_sprite_effects",
            "ws_after_projectiles",
            "ws_after_bonus_update",
            "ws_after_sfx_queue_merge",
            "ws_after_player_damage_sfx",
            "ws_after_sfx",
        }.issubset(ckpt.rng_marks.keys())
        assert isinstance(ckpt.events.hit_count, int)
        assert isinstance(ckpt.events.pickup_count, int)
        assert isinstance(ckpt.events.sfx_count, int)
        assert isinstance(ckpt.deaths, list)


def test_rush_runner_trace_rng_captures_presentation_marks() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    checkpoints = []

    run_replay(
        replay,
        trace_rng=True,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0]
    assert checkpoints[0].rng_marks["ps_draws_total"] >= 0
