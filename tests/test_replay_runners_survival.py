from __future__ import annotations

from contextlib import contextmanager
from typing import Any, cast

import pytest

from crimson.game_modes import GameMode
from crimson.sim.driver.playback_driver import PlaybackDriver, PlaybackDriverOptions
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.driver.setup import ReplayRunnerError
from tests.replay_runner_helpers import _blank_survival_replay


def test_survival_runner_is_deterministic() -> None:
    _header, rec = _blank_survival_replay(ticks=10, seed=0x1234)
    replay = rec.finish()

    result0 = run_replay(replay)
    result1 = run_replay(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.SURVIVAL)
    assert result0.ticks == 10
    assert result0.elapsed_ms == 10 * int(1000.0 / 60.0)
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 1
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_survival_runner_uses_replay_dt_rows_for_elapsed_ms() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.dt[0] = 0.5

    result = run_replay(replay)

    assert result.elapsed_ms == 500


def test_survival_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()

    baseline = run_replay(replay)
    shifted = run_replay(replay, inter_tick_rand_draws=1)
    shifted_again = run_replay(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_survival_runner_rejects_invalid_perk_pick_event() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.raises(ReplayRunnerError, match="perk_pick failed"):
        run_replay(replay)


def test_survival_runner_applies_pre_step_events_before_timing(mocker) -> None:
    import crimson.sim.driver.playback_driver as playback_driver_module
    import crimson.sim.sessions as sessions_module

    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    order: list[str] = []

    original_apply = playback_driver_module.apply_replay_tick_events

    def _traced_apply(
        events,
        *,
        tick_index: int,
        dt: float,
        world,
        game_mode_id: GameMode,
        on_capture_state_transition=None,
    ):
        order.append("events")
        return original_apply(
            events,
            tick_index=int(tick_index),
            dt=float(dt),
            world=world,
            game_mode_id=GameMode(int(game_mode_id)),
            on_capture_state_transition=on_capture_state_transition,
        )

    original_timing = sessions_module.SurvivalDeterministicSession.timing_for_dt

    def _traced_timing(self, dt: float):
        order.append("timing")
        return original_timing(self, float(dt))

    mocker.patch.object(playback_driver_module, "apply_replay_tick_events", side_effect=_traced_apply)
    mocker.patch.object(
        sessions_module.SurvivalDeterministicSession,
        "timing_for_dt",
        autospec=True,
        side_effect=_traced_timing,
    )

    run_replay(replay, max_ticks=1)

    assert "events" in order
    assert "timing" in order
    assert order.index("events") < order.index("timing")


def test_survival_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
    checkpoints = []

    run_replay(
        replay,
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
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
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


def test_survival_runner_tick_rng_trace_observer_emits_draw_rows() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
    rows_by_tick: dict[int, list[tuple[int, int, int]]] = {}

    def _observer(tick_index: int, draws: list[tuple[int, int, int]]) -> None:
        rows_by_tick[int(tick_index)] = list(draws)

    run_replay(
        replay,
        trace_rng=True,
        tick_rng_trace_observer=_observer,
    )

    assert sorted(rows_by_tick.keys()) == [0, 1, 2]
    for draws in rows_by_tick.values():
        for state_before_u32, value_15, state_after_u32 in draws:
            expected_after = (int(state_before_u32) * 214013 + 2531011) & 0xFFFFFFFF
            assert int(state_after_u32) == int(expected_after)
            assert int(value_15) == ((int(state_after_u32) >> 16) & 0x7FFF)


def test_survival_runner_tick_rng_trace_rows_include_draws_before_trace_exit(mocker) -> None:
    import crimson.sim.driver.playback_driver as playback_driver_module

    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    rows_by_tick: dict[int, list[tuple[int, int, int]]] = {}

    @contextmanager
    def _fake_tick_rng_trace(_rng: object, *, enabled: bool):
        draws: list[tuple[int, int, int]] = []
        try:
            yield draws
        finally:
            if enabled:
                draws.append((1, 2, 3))

    mocker.patch.object(playback_driver_module, "_tick_rng_trace", side_effect=_fake_tick_rng_trace)

    run_replay(
        replay,
        trace_rng=True,
        tick_rng_trace_observer=lambda tick_index, draws: rows_by_tick.setdefault(int(tick_index), list(draws)),
    )

    assert rows_by_tick == {0: [(1, 2, 3)]}


def test_survival_runner_applies_terminal_tick_events() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    rec.record_perk_menu_open(player_index=0, tick_index=3)
    replay_with_terminal_event = rec.finish()

    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay_without_terminal_event = rec.finish()

    with_terminal_event = run_replay(replay_with_terminal_event)
    without_terminal_event = run_replay(replay_without_terminal_event)

    assert with_terminal_event.rng_state != without_terminal_event.rng_state


def test_survival_runner_can_capture_terminal_tick_checkpoint() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    rec.record_perk_menu_open(player_index=0, tick_index=3)
    replay = rec.finish()
    checkpoints = []

    run_replay(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={3},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [3]
    assert checkpoints[0].rng_marks == {}


def test_playback_driver_run_to_completion_uses_tick_runner_orchestration() -> None:
    import crimson.sim.driver.playback_driver as playback_driver_module

    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    driver = PlaybackDriver(replay, PlaybackDriverOptions())
    captured: dict[str, object] = {}

    class _StopRun(RuntimeError):
        pass

    def _capture_provider(*, player_count: int, resolve_tick_input, tick_count: int, resolve_tick_dt=None):
        captured["provider_player_count"] = int(player_count)
        captured["provider_tick_count"] = int(tick_count)
        captured["provider_resolver"] = resolve_tick_input
        captured["provider_dt_resolver"] = resolve_tick_dt
        return object()

    def _capture_runner(*args, **kwargs):
        _ = args
        captured["runner_input_provider"] = kwargs.get("input_provider")
        captured["runner_config"] = kwargs.get("config")
        raise _StopRun("stop after runner construction")

    from unittest.mock import patch

    with (
        patch.object(playback_driver_module, "ReplayInputProvider", side_effect=_capture_provider),
        patch.object(playback_driver_module, "TickRunner", side_effect=_capture_runner),
        pytest.raises(_StopRun, match="runner construction"),
    ):
        driver.run_to_completion()

    assert captured["provider_player_count"] == int(replay.header.player_count)
    assert captured["provider_tick_count"] == int(driver.tick_limit)
    assert callable(cast(Any, captured["provider_resolver"]))
    assert callable(cast(Any, captured["provider_dt_resolver"]))
    assert captured["runner_input_provider"] is not None
    assert captured["runner_config"] is not None
