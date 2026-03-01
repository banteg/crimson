from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.replay import ReplayGameVersionWarning
from crimson.sim.driver.replay_runner import run_survival_replay
from crimson.sim.driver.setup import ReplayRunnerError
from tests.replay_runner_helpers import _blank_survival_replay


def test_survival_runner_is_deterministic() -> None:
    _header, rec = _blank_survival_replay(ticks=10, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_survival_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_survival_replay(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.SURVIVAL)
    assert result0.ticks == 10
    assert result0.elapsed_ms == int(10 * (1000.0 / 60.0))
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 1
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_survival_runner_honors_dt_frame_overrides_for_elapsed_ms() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(
            replay,
            dt_frame_overrides={0: 0.5},
        )

    assert result.elapsed_ms == 500


def test_survival_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        baseline = run_survival_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        shifted = run_survival_replay(replay, inter_tick_rand_draws=1)
    with pytest.warns(ReplayGameVersionWarning):
        shifted_again = run_survival_replay(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_survival_runner_rejects_invalid_perk_pick_event() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="perk_pick failed"):
            run_survival_replay(replay)


def test_survival_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=False,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0, 2},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0, 2]
    for ckpt in checkpoints:
        assert len(ckpt.command_hash) == 16
        assert {
            "before_world_step",
            "gw_begin",
            "gw_after_weapon_refresh",
            "gw_after_perks_rebuild",
            "gw_after_time_scale",
            "after_world_step",
            "after_stage_spawns",
            "after_wave_spawns",
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


def test_survival_runner_trace_rng_captures_presentation_marks() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=False,
            trace_rng=True,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0]
    assert checkpoints[0].rng_marks["ps_draws_total"] >= 0


def test_survival_runner_can_skip_invalid_perk_pick_event_non_strict() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(replay, strict_events=False)

    assert result.ticks == 3


def test_survival_runner_applies_terminal_tick_events() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_menu_open(player_index=0, tick_index=3)
    replay_with_terminal_event = rec.finish()

    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay_without_terminal_event = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with_terminal_event = run_survival_replay(replay_with_terminal_event)
    with pytest.warns(ReplayGameVersionWarning):
        without_terminal_event = run_survival_replay(replay_without_terminal_event)

    assert with_terminal_event.rng_state != without_terminal_event.rng_state


def test_survival_runner_can_capture_terminal_tick_checkpoint() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_menu_open(player_index=0, tick_index=3)
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=True,
            checkpoints_out=checkpoints,
            checkpoint_ticks={3},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [3]
    assert checkpoints[0].rng_marks == {}
