from __future__ import annotations

import msgspec

from crimson.game_modes import GameMode
from crimson.sim.driver.playback_driver import PlaybackDriver, build_verify_playback_driver
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand
from tests.replay_runner_helpers import _blank_survival_replay, _run_verify_playback


def test_survival_runner_is_deterministic() -> None:
    _header, rec = _blank_survival_replay(ticks=10, seed=0x1234)
    replay = rec.finish()

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

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
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)

    result = _run_verify_playback(replay)

    assert result.elapsed_ms == 500


def test_survival_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()

    baseline = _run_verify_playback(replay)
    shifted = _run_verify_playback(replay, inter_tick_rand_draws=1)
    shifted_again = _run_verify_playback(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_survival_runner_ignores_stale_perk_pick_command() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        commands=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    result = _run_verify_playback(replay)
    assert result.ticks == 1


def test_survival_runner_menu_open_allows_same_tick_perk_pick() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        commands=[PerkMenuOpenCommand(player_index=0), PerkPickCommand(player_index=0, choice_index=0)],
    )

    result = _run_verify_playback(replay)

    assert result.game_mode_id == int(GameMode.SURVIVAL)
    assert result.ticks == 1


def test_survival_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
    checkpoints = []

    _run_verify_playback(
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

    _run_verify_playback(
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

    _run_verify_playback(
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


def test_playback_driver_run_matches_verify_driver_factory() -> None:
    _header, rec = _blank_survival_replay(ticks=4, seed=0x1234)
    replay = rec.finish()
    driver = PlaybackDriver(replay)

    driver_result = driver.run()
    wrapper_result = build_verify_playback_driver(replay).run()

    assert driver_result == wrapper_result
