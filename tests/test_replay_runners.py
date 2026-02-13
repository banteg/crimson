from __future__ import annotations

import pytest
from grim.geom import Vec2

from crimson.game_modes import GameMode
from crimson.sim.input import PlayerInput
from crimson.replay import ReplayGameVersionWarning, ReplayHeader, ReplayRecorder, UnknownEvent
from crimson.original.capture import CAPTURE_BOOTSTRAP_EVENT_KIND, CAPTURE_PERK_APPLY_EVENT_KIND
from crimson.perks import PerkId
from crimson.sim.runners import ReplayRunnerError, run_rush_replay, run_survival_replay


def _blank_survival_replay(*, ticks: int, seed: int = 0xBEEF, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_rush_replay(*, ticks: int, seed: int = 0xBEEF, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.RUSH),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


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


def test_survival_runner_applies_original_capture_bootstrap_event() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "elapsed_ms": 2000,
                    "perk_pending": 2,
                    "bonus_timers_ms": {"4": 1500},
                    "players": [
                        {
                            "pos": {"x": 600.0, "y": 600.0},
                            "health": 75.0,
                            "weapon_id": 9,
                            "ammo": 4.0,
                            "experience": 321,
                            "level": 5,
                        }
                    ],
                }
            ],
        )
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(replay, strict_events=True, max_ticks=1)

    assert result.ticks == 1
    assert result.score_xp == 321


def test_survival_runner_skips_world_dt_perk_steps_for_original_capture_dt_overrides() -> None:
    def _run(*, include_bootstrap: bool) -> float:
        header = ReplayHeader(
            game_mode_id=int(GameMode.SURVIVAL),
            seed=0x1234,
            tick_rate=60,
            player_count=1,
            game_version="0.0.0",
        )
        recorder = ReplayRecorder(header)
        recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0))])
        replay = recorder.finish()
        if include_bootstrap:
            replay.events.append(
                UnknownEvent(
                    tick_index=0,
                    kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                    payload=[{"digital_move_enabled_by_player": [True]}],
                )
            )
        replay.events.append(
            UnknownEvent(
                tick_index=0,
                kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                payload=[{"perk_id": int(PerkId.REFLEX_BOOSTED), "outside_before": False}],
            )
        )

        checkpoints = []
        with pytest.warns(ReplayGameVersionWarning):
            run_survival_replay(
                replay,
                max_ticks=1,
                checkpoints_out=checkpoints,
                checkpoint_ticks={0},
                dt_frame_overrides={0: 0.1},
            )
        assert len(checkpoints) == 1
        return float(checkpoints[0].players[0].pos.x)

    orig_capture_x = _run(include_bootstrap=True)
    plain_replay_x = _run(include_bootstrap=False)
    assert orig_capture_x > plain_replay_x


def test_survival_runner_original_capture_uses_packed_move_vector_for_turn_only_keys() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=0x1234,
        tick_rate=60,
        player_count=1,
        game_version="0.0.0",
    )
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0))])
    replay = recorder.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[{"digital_move_enabled_by_player": [True]}],
        )
    )

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            max_ticks=1,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert len(checkpoints) == 1
    assert float(checkpoints[0].players[0].pos.x) > 512.0


def test_rush_runner_is_deterministic() -> None:
    _header, rec = _blank_rush_replay(ticks=10, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_rush_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_rush_replay(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.RUSH)
    assert result0.ticks == 10
    assert result0.elapsed_ms == int(10 * (1000.0 / 60.0))
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 2
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_rush_runner_honors_dt_frame_overrides_for_elapsed_ms() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_rush_replay(
            replay,
            dt_frame_overrides={0: 0.5},
        )

    assert result.elapsed_ms == 500


def test_rush_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        baseline = run_rush_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        shifted = run_rush_replay(replay, inter_tick_rand_draws=1)
    with pytest.warns(ReplayGameVersionWarning):
        shifted_again = run_rush_replay(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_rush_runner_rejects_events() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="does not support events"):
            run_rush_replay(replay)


def test_rush_runner_applies_original_capture_bootstrap_event() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "elapsed_ms": 3000,
                    "players": [
                        {
                            "pos": {"x": 400.0, "y": 450.0},
                            "health": 90.0,
                            "weapon_id": 2,
                            "ammo": 8.0,
                            "experience": 77,
                            "level": 3,
                        }
                    ],
                }
            ],
        )
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_rush_replay(replay, max_ticks=1)

    assert result.ticks == 1
    assert result.score_xp == 77


def test_rush_runner_original_capture_uses_packed_move_vector_for_turn_only_keys() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.RUSH),
        seed=0x1234,
        tick_rate=60,
        player_count=1,
        game_version="0.0.0",
    )
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0))])
    replay = recorder.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[{"digital_move_enabled_by_player": [True]}],
        )
    )

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
            replay,
            max_ticks=1,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert len(checkpoints) == 1
    assert float(checkpoints[0].players[0].pos.x) > 512.0


def test_rush_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
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
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
            replay,
            trace_rng=True,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0]
    assert checkpoints[0].rng_marks["ps_draws_total"] >= 0
