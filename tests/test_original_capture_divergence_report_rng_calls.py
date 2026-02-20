from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.original.schema import CAPTURE_FORMAT_VERSION, CaptureTick
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from grim.geom import Vec2


def _load_report_module():
    from crimson.original import divergence_report

    return divergence_report


def _base_config(**kwargs: object) -> dict[str, object]:
    row = {
        "out_path": "",
        "split_quest_files": True,
        "quest_out_dir": "",
        "quest_out_prefix": "",
        "capture_profile": "",
        "config_env_overrides": [],
        "log_mode": "truncate",
        "console_all_events": False,
        "console_events": [],
        "include_caller": True,
        "include_backtrace": False,
        "emit_ticks_outside_tracked_states": False,
        "tracked_states": [],
        "player_count_override": 0,
        "focus_tick": -1,
        "focus_radius": 0,
        "heartbeat_ms": 1000,
        "max_head_per_kind": -1,
        "max_events_per_tick": -1,
        "max_rng_head_per_tick": -1,
        "max_rng_caller_kinds": -1,
        "enable_rng_state_mirror": True,
        "max_creature_delta_ids": 32,
        "creature_sample_limit": -1,
        "projectile_sample_limit": -1,
        "secondary_projectile_sample_limit": -1,
        "bonus_sample_limit": -1,
        "enable_input_hooks": True,
        "enable_rng_hooks": True,
        "enable_sfx_hooks": True,
        "enable_damage_hooks": True,
        "enable_effect_hooks": True,
        "creature_damage_projectile_only": True,
        "enable_spawn_hooks": True,
        "enable_creature_spawn_hook": True,
        "enable_creature_death_hook": True,
        "enable_bonus_spawn_hook": True,
        "enable_creature_lifecycle_digest": True,
        "enable_creature_micro_hooks": True,
        "creature_micro_slots": [],
        "creature_micro_tick_start": -1,
        "creature_micro_tick_end": -1,
        "creature_micro_max_head_per_tick": 256,
    }
    row.update(kwargs)
    return row


def _snapshot_globals(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "config_game_mode": int(GameMode.SURVIVAL),
        "config_player_mode_flags": [0],
        "config_aim_scheme": [None],
        "game_state_prev": 0,
        "game_state_id": 0,
        "game_state_pending": 0,
        "frame_dt": None,
        "frame_dt_ms_i32": None,
        "frame_dt_ms_f32": None,
        "time_played_ms": 0,
        "creature_active_count": 0,
        "creature_kill_count": 0,
        "perk_pending_count": 0,
        "perk_choices_dirty": 0,
        "shock_chain_links_left": 0,
        "shock_chain_projectile_id": 0,
        "quest_spawn_timeline": 0,
        "quest_stage_major": -1,
        "quest_stage_minor": -1,
        "quest_spawn_stall_timer_ms": 0,
        "quest_transition_timer_ms": 0,
        "quest_stage_banner_timer_ms": 0,
        "ui_elements_timeline": 0.0,
        "ui_transition_direction": 0,
        "ui_transition_alpha": 0.0,
        "pause_keybind_help_alpha_ms": 0,
        "player_alt_weapon_swap_cooldown_ms": 0,
        "perk_jinxed_proc_timer_s": 0.0,
        "perk_lean_mean_exp_tick_timer_s": 0.0,
        "perk_doctor_target_creature_id": -1,
        "bonus_reflex_boost_timer": 0.0,
        "bonus_freeze_timer": 0.0,
        "bonus_weapon_power_up_timer": 0.0,
        "bonus_energizer_timer": 0.0,
        "bonus_double_xp_timer": 0.0,
    }
    row.update(kwargs)
    return row


def _snapshot_status(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "quest_unlock_index": 0,
        "quest_unlock_index_full": 0,
        "weapon_usage_counts": [],
    }
    row.update(kwargs)
    return row


def _snapshot_input(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "console_open": 0,
        "primary_latch": 0,
        "mouse_x": 0.0,
        "mouse_y": 0.0,
        "aim_screen": [{"player_index": 0, "x": 0.0, "y": 0.0}],
    }
    row.update(kwargs)
    return row


def _snapshot_input_bindings(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "players": [
            {
                "player_index": 0,
                "move_forward": 0,
                "move_backward": 0,
                "turn_left": 0,
                "turn_right": 0,
                "fire": 0,
                "aim_left": 0,
                "aim_right": 0,
                "axis_aim_x": 0,
                "axis_aim_y": 0,
                "axis_move_x": 0,
                "axis_move_y": 0,
            },
        ],
        "alternate_single": {
            "move_forward": 0,
            "move_backward": 0,
            "turn_left": 0,
            "turn_right": 0,
            "fire": 0,
        },
    }
    row.update(kwargs)
    return row


def _timing_diagnostics(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "gameplay_frame": 0,
        "gameplay_frame_delta_prev_tick": None,
        "elapsed_ms_before": 0,
        "elapsed_ms_after": 0,
        "elapsed_delta_in_tick_ms": 0,
        "elapsed_delta_prev_tick_ms": None,
        "frame_dt_before": None,
        "frame_dt_after": None,
        "frame_dt_ms_before_i32": None,
        "frame_dt_ms_after_i32": None,
        "frame_dt_ms_before_f32": None,
        "frame_dt_ms_after_f32": None,
        "frame_dt_source_before": "none",
        "frame_dt_source_after": "none",
        "mode_tick_event_count": 0,
        "mode_tick_sample_count": 0,
        "mode_tick_mode_fn_head": [],
        "mode_tick_present": False,
    }
    row.update(kwargs)
    return row


def _spawn_diagnostics(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "before_creature_count": 0,
        "after_creature_count": 0,
        "creature_count_delta": 0,
        "event_count_template": 0,
        "event_count_low_level": 0,
        "event_count_creature_damage": 0,
        "event_count_projectile_find_query": 0,
        "event_count_projectile_find_hit": 0,
        "event_count_projectile_find_query_miss": 0,
        "event_count_projectile_find_query_owner_collision": 0,
        "event_count_death": 0,
        "top_template_callers": [],
        "top_low_level_callers": [],
        "top_low_level_sources": [],
        "top_creature_damage_callers": [],
        "top_projectile_find_query_callers": [],
        "top_projectile_find_hit_callers": [],
        "top_death_callers": [],
        "event_count_blood_splatter": 0,
        "blood_splatter_rng_draws": 0,
        "blood_splatter_projectile_update_calls": 0,
        "top_blood_splatter_callers": [],
        "top_blood_splatter_rng_draw_callers": [],
        "event_count_bonus_spawn": 0,
        "top_bonus_spawn_callers": [],
        "mode_samples": [],
    }
    row.update(kwargs)
    return row


def _rng_diagnostics(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "seq_first": None,
        "seq_last": None,
        "seed_epoch_enter": None,
        "seed_epoch_last": None,
        "outside_before_calls": 0,
        "outside_before_dropped": 0,
        "outside_before_head": [],
        "mirror_mismatch_total_enter": 0,
        "mirror_mismatch_total_leave": 0,
        "mirror_unknown_total_enter": 0,
        "mirror_unknown_total_leave": 0,
        "roll_log_emitted_total": 0,
        "roll_log_dropped_total": 0,
    }
    row.update(kwargs)
    return row


def _player_fire_diagnostics(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "event_count_player_fire": 0,
        "top_direct_events_by_player": [],
        "top_fallback_events_by_player": [],
        "top_player_projectile_spawns_by_player": [],
    }
    row.update(kwargs)
    return row


def _event_counts_dict(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "state_transition": 0,
        "player_fire": 0,
        "weapon_assign": 0,
        "bonus_apply": 0,
        "bonus_spawn": 0,
        "projectile_spawn": 0,
        "projectile_find_query": 0,
        "projectile_find_hit": 0,
        "secondary_projectile_spawn": 0,
        "player_damage": 0,
        "creature_damage": 0,
        "creature_spawn": 0,
        "creature_spawn_low": 0,
        "creature_death": 0,
        "creature_lifecycle": 0,
        "creature_update_micro": 0,
        "perk_apply": 0,
        "sfx": 0,
        "perk_delta": 0,
        "quest_timeline_delta": 0,
        "mode_tick": 0,
        "input_primary_edge": 0,
        "input_primary_down": 0,
        "input_any_key": 0,
    }
    row.update(kwargs)
    return row


def _rng_head_entry(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "seq": None,
        "seed_epoch": None,
        "tick_index": None,
        "tick_call_index": None,
        "outside_tick": None,
        "value": None,
        "value_u32": None,
        "value_15": None,
        "branch_id": None,
        "caller": None,
        "caller_static": None,
        "state_before_u32": None,
        "state_after_u32": None,
        "state_before_hex": None,
        "state_after_hex": None,
        "expected_value_15": None,
        "mirror_match": None,
    }
    row.update(kwargs)
    return row


def _rng_summary_dict(**kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "calls": 0,
        "last_value": None,
        "hash": "",
        "head": [],
        "callers": [],
        "caller_overflow": 0,
        "seq_first": None,
        "seq_last": None,
        "seed_epoch_enter": None,
        "seed_epoch_last": None,
        "outside_before_calls": 0,
        "outside_before_dropped": 0,
        "outside_before_head": [],
        "mirror_mismatch_total": 0,
        "mirror_unknown_total": 0,
    }
    row.update(kwargs)
    return row


def _input_player_keys(player_index: int, **kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "player_index": int(player_index),
        "move_forward_pressed": None,
        "move_backward_pressed": None,
        "turn_left_pressed": None,
        "turn_right_pressed": None,
        "fire_down": None,
        "fire_pressed": None,
        "reload_pressed": None,
    }
    row.update(kwargs)
    return row


def _sample_creature(index: int, **kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "index": int(index),
        "active": 1,
        "state_flag": 1,
        "collision_flag": 1,
        "hitbox_size": 16.0,
        "pos": {"x": 10.0, "y": 20.0},
        "hp": 100.0,
        "type_id": 2,
        "target_player": 0,
        "flags": 0,
        "link_index": None,
        "ai_mode": None,
        "heading": None,
        "target_heading": None,
        "orbit_angle": None,
        "orbit_radius": None,
        "ai7_timer_ms": None,
    }
    row.update(kwargs)
    return row


def _sample_projectile(index: int, **kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "index": int(index),
        "active": 1,
        "angle": 0.0,
        "pos": {"x": 0.0, "y": 0.0},
        "vel": {"x": 0.0, "y": 0.0},
        "type_id": 1,
        "life_timer": 1.0,
        "speed_scale": 1.0,
        "damage_pool": 1.0,
        "hit_radius": 2.0,
        "base_damage": 1.0,
        "owner_id": 0,
    }
    row.update(kwargs)
    return row


def _sample_secondary_projectile(index: int, **kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "index": int(index),
        "active": 1,
        "pos": {"x": 15.0, "y": 25.0},
        "life_timer": 0.9,
        "angle": 0.0,
        "vel": {"x": 0.0, "y": 0.0},
        "trail_timer": 0.0,
        "type_id": 1,
        "target_id": -1,
    }
    row.update(kwargs)
    return row


def _sample_bonus(index: int, **kwargs: object) -> dict[str, object]:
    row: dict[str, object] = {
        "index": int(index),
        "bonus_id": 0,
        "state": 0,
        "time_left": 0.0,
        "time_max": 0.0,
        "pos": {"x": 0.0, "y": 0.0},
        "amount_f32": 0.0,
        "amount_i32": 0,
    }
    row.update(kwargs)
    return row


def _capture_tick(
    *,
    tick: int,
    rng_rand_calls: int = 0,
    rng_head: list[dict[str, object]] | None = None,
    rng_callers: list[dict[str, object]] | None = None,
    event_counts: dict[str, int] | None = None,
    spawn: dict[str, object] | None = None,
    event_heads: list[dict[str, object]] | None = None,
    sample_counts: dict[str, int] | None = None,
    input_player_keys: list[dict[str, object]] | None = None,
) -> CaptureTick:
    rng_head_rows = list(rng_head or [])
    rng_caller_rows = list(rng_callers or [])
    counts_row = _event_counts_dict(**(event_counts or {}))
    spawn_row = _spawn_diagnostics(**(spawn or {}))
    sample_counts_row: dict[str, int] = {
        "creatures": 0,
        "projectiles": 0,
        "secondary_projectiles": 0,
        "bonuses": 0,
    }
    if sample_counts is not None:
        for key, value in sample_counts.items():
            sample_counts_row[str(key)] = int(value)

    row: dict[str, object] = {
        "tick_index": int(tick),
        "gameplay_frame": int(tick) + 1,
        "mode_hint": "survival_update",
        "game_mode_id": int(GameMode.SURVIVAL),
        "quest_stage_major": -1,
        "quest_stage_minor": -1,
        "focus_tick": False,
        "state_id_enter": None,
        "state_id_leave": None,
        "state_pending_enter": None,
        "state_pending_leave": None,
        "ts_enter_ms": 0,
        "ts_leave_ms": 0,
        "duration_ms": 0,
        "checkpoint": {
            "tick_index": int(tick),
            "state_hash": f"s{tick}",
            "command_hash": f"c{tick}",
            "rng_state": 0,
            "elapsed_ms": int(tick) * 16,
            "score_xp": 0,
            "kills": 0,
            "creature_count": 0,
            "perk_pending": 0,
            "players": [],
            "status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0, "weapon_usage_counts": []},
            "bonus_timers": {},
            "rng_marks": {
                "rand_calls": int(rng_rand_calls),
                "rand_hash": "",
                "rand_last": None,
                "rand_head": rng_head_rows,
                "rand_callers": rng_caller_rows,
                "rand_caller_overflow": 0,
                "rand_seq_first": None,
                "rand_seq_last": None,
                "rand_seed_epoch_enter": None,
                "rand_seed_epoch_last": None,
                "rand_outside_before_calls": 0,
                "rand_outside_before_dropped": 0,
                "rand_outside_before_head": [],
                "rand_mirror_mismatch_total": 0,
                "rand_mirror_unknown_total": 0,
            },
            "deaths": [],
            "perk": {"pending_count": 0, "choices_dirty": False, "choices": [], "player_nonzero_counts": []},
            "events": {
                "hit_count": -1,
                "pickup_count": -1,
                "sfx_count": -1,
                "sfx_head": [],
                "rng_call_count": 0,
                "input_true_count": 0,
            },
            "debug": {
                "sampling_phase": "",
                "timing": _timing_diagnostics(),
                "spawn": spawn_row,
                "rng": _rng_diagnostics(),
                "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
                "creature_lifecycle": None,
                "player_fire": _player_fire_diagnostics(),
                "before_players": [],
                "before_status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0},
            },
        },
        "event_counts": counts_row,
        "event_overflow": False,
        "event_heads": list(event_heads or []),
        "phase_markers": [],
        "input_queries": {
            "stats": {
                "primary_edge": {"calls": 0, "true_calls": 0},
                "primary_down": {"calls": 0, "true_calls": 0},
                "any_key": {"calls": 0, "true_calls": 0},
            },
            "query_hash": "",
        },
        "input_player_keys": list(input_player_keys or [_input_player_keys(player_index=0)]),
        "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
        "perk_apply_in_tick": [],
        "rng": _rng_summary_dict(calls=int(rng_rand_calls), head=rng_head_rows, callers=rng_caller_rows),
        "diagnostics": {
            "sampling_phase": "",
            "timing": _timing_diagnostics(),
            "spawn": _spawn_diagnostics(),
            "rng": _rng_diagnostics(),
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "player_fire": _player_fire_diagnostics(),
        },
        "input_approx": [],
        "before": {
            "globals": _snapshot_globals(),
            "status": _snapshot_status(),
            "player_count": 1,
            "players": [],
            "input": _snapshot_input(),
            "input_bindings": _snapshot_input_bindings(),
        },
        "after": {
            "globals": _snapshot_globals(),
            "status": _snapshot_status(),
            "player_count": 1,
            "players": [],
            "input": _snapshot_input(),
            "input_bindings": _snapshot_input_bindings(),
        },
        "frame_dt_ms": None,
        "frame_dt_ms_i32": None,
        "creature_lifecycle": None,
        "samples": {
            "creatures": [_sample_creature(index=i) for i in range(max(0, int(sample_counts_row["creatures"])))],
            "projectiles": [_sample_projectile(index=i) for i in range(max(0, int(sample_counts_row["projectiles"])))],
            "secondary_projectiles": [
                _sample_secondary_projectile(index=i)
                for i in range(max(0, int(sample_counts_row["secondary_projectiles"])))
            ],
            "bonuses": [_sample_bonus(index=i) for i in range(max(0, int(sample_counts_row["bonuses"])))],
        },
    }
    return msgspec.convert(row, type=CaptureTick, strict=True)


def _step_crt_state(state: int, calls: int) -> int:
    value = int(state) & 0xFFFFFFFF
    for _ in range(max(0, int(calls))):
        value = (value * 214013 + 2531011) & 0xFFFFFFFF
    return value


def _crt_rand_values(state: int, calls: int) -> list[int]:
    value = int(state) & 0xFFFFFFFF
    out: list[int] = []
    for _ in range(max(0, int(calls))):
        value = (value * 214013 + 2531011) & 0xFFFFFFFF
        out.append((value >> 16) & 0x7FFF)
    return out


def _checkpoint(
    *,
    tick: int,
    rng_marks: dict[str, int],
    kills: int = 0,
    creature_count: int = 0,
    deaths: list[ReplayDeathLedgerEntry] | None = None,
    events: ReplayEventSummary | None = None,
) -> ReplayCheckpoint:
    return ReplayCheckpoint(
        tick_index=int(tick),
        rng_state=int(rng_marks.get("after_wave_spawns", rng_marks.get("after_world_step", 0))),
        elapsed_ms=0,
        score_xp=0,
        kills=int(kills),
        creature_count=int(creature_count),
        perk_pending=0,
        players=[
            ReplayPlayerCheckpoint(
                pos=Vec2(0.0, 0.0),
                health=100.0,
                weapon_id=1,
                ammo=12.0,
                experience=0,
                level=1,
            ),
        ],
        bonus_timers={},
        state_hash="state",
        command_hash="cmd",
        rng_marks=dict(rng_marks),
        deaths=list(deaths or []),
        perk=ReplayPerkSnapshot(),
        events=events if events is not None else ReplayEventSummary(),
    )


def test_run_actual_checkpoints_quest_uses_capture_inter_tick_rand_draw_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _load_report_module()
    replay = SimpleNamespace(
        header=SimpleNamespace(
            game_mode_id=int(GameMode.QUESTS),
            tick_rate=60,
        ),
    )
    seen_inter_tick_rand_draws = -1
    seen_inter_tick_rand_draws_by_tick: dict[int, int] = {}

    class _Stop(RuntimeError):
        pass

    monkeypatch.setattr(
        report,
        "convert_capture_to_checkpoints",
        lambda _capture: SimpleNamespace(checkpoints=[]),
    )
    monkeypatch.setattr(
        report,
        "convert_capture_to_replay",
        lambda _capture, seed=None, aim_scheme_overrides_by_player=None: replay,
    )
    monkeypatch.setattr(
        report,
        "build_capture_dt_frame_overrides",
        lambda _capture, tick_rate: {},
    )
    monkeypatch.setattr(
        report,
        "build_capture_dt_frame_ms_i32_overrides",
        lambda _capture: {},
    )
    monkeypatch.setattr(
        report,
        "build_capture_inter_tick_rand_draws_overrides",
        lambda _capture: {0: 24021, 1: 1},
    )

    def _fake_run_quest_replay(*_args: object, **kwargs: object):
        nonlocal seen_inter_tick_rand_draws, seen_inter_tick_rand_draws_by_tick
        inter_tick_draws_obj = kwargs.get("inter_tick_rand_draws", -1)
        seen_inter_tick_rand_draws = int(inter_tick_draws_obj) if isinstance(inter_tick_draws_obj, int) else -1
        seen_inter_tick_rand_draws_by_tick = cast("dict[int, int]", kwargs.get("inter_tick_rand_draws_by_tick", {}))
        raise _Stop("stop after capturing kwargs")

    monkeypatch.setattr(report, "run_quest_replay", _fake_run_quest_replay)

    with pytest.raises(_Stop):
        report._run_actual_checkpoints(
            object(),
            max_ticks=None,
            seed=None,
            inter_tick_rand_draws=1,
        )

    assert seen_inter_tick_rand_draws == 1
    assert seen_inter_tick_rand_draws_by_tick == {0: 24021, 1: 1}


def test_infer_rand_calls_between_states_and_stage_breakdown() -> None:
    report = _load_report_module()
    start = 0x12345678
    s1 = _step_crt_state(start, 1)
    s9 = _step_crt_state(start, 9)
    s10 = _step_crt_state(start, 10)
    s12 = _step_crt_state(start, 12)

    assert report._infer_rand_calls_between_states(start, s1) == 1
    assert report._infer_rand_calls_between_states(start, start) == 0
    assert report._infer_rand_calls_between_states(-1, s1) is None

    ckpt = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "ws_after_creatures": s1,
            "ws_after_projectiles": s1,
            "ws_after_secondary_projectiles": s9,
            "ws_after_death_sfx": s10,
            "after_world_step": s10,
            "after_stage_spawns": s12,
            "after_wave_spawns": s12,
        },
    )
    assert report._actual_rand_calls_for_checkpoint(ckpt) == 12
    assert report._actual_rand_stage_calls(ckpt) == {
        "creatures": 1,
        "projectiles": 0,
        "secondary_projectiles": 8,
        "death_sfx_preplan": 1,
        "world_step_tail": 0,
        "survival_stage_spawns": 2,
        "survival_wave_spawns": 0,
    }


def test_actual_rand_calls_prefers_non_stale_after_mark() -> None:
    report = _load_report_module()
    start = 0x3AB51475
    after_world = _step_crt_state(start, 36)

    ckpt = _checkpoint(
        tick=570,
        rng_marks={
            "before_world_step": start,
            "before_events": start,
            "after_events": start,
            "ws_after_creatures": start,
            "ws_after_projectiles": start,
            "ws_after_secondary_projectiles": start,
            "ws_after_death_sfx": start,
            "after_world_step": after_world,
            "after_stage_spawns": start,
            "after_wave_spawns": start,
        },
    )

    assert report._actual_rand_calls_for_checkpoint(ckpt) == 36
    assert report._rng_changed(ckpt) is True


def test_actual_rand_calls_prefers_late_event_after_mark() -> None:
    report = _load_report_module()
    start = 0xE199E00E
    after_world = _step_crt_state(start, 1)
    after_post_events = _step_crt_state(start, 11)

    ckpt = _checkpoint(
        tick=1247,
        rng_marks={
            "before_events": start,
            "before_world_step": start,
            "after_world_step": after_world,
            "after_stage_spawns": after_world,
            "after_wave_spawns": after_world,
            "before_post_events": after_world,
            "after_events": after_post_events,
            "after_post_events": after_post_events,
        },
    )

    assert report._actual_rand_calls_for_checkpoint(ckpt) == 11
    assert report._rng_changed(ckpt) is True


def test_window_rows_include_actual_rand_calls_and_delta() -> None:
    report = _load_report_module()
    start = 0x0BADF00D
    after = _step_crt_state(start, 10)

    expected_ckpt = _checkpoint(
        tick=5,
        rng_marks={"rand_calls": 2},
    )
    actual_ckpt = _checkpoint(
        tick=5,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after,
            "after_wave_spawns": after,
        },
        deaths=[
            ReplayDeathLedgerEntry(
                creature_index=25,
                type_id=2,
                reward_value=41.0,
                xp_awarded=41,
                owner_id=-1,
            ),
        ],
    )

    rows = report._build_window_rows(
        expected_by_tick={5: expected_ckpt},
        actual_by_tick={5: actual_ckpt},
        raw_debug_by_tick={5: _capture_tick(tick=5, rng_rand_calls=2)},
        focus_tick=5,
        window=0,
    )

    assert len(rows) == 1
    row = rows[0]
    assert int(row["expected_rand_calls"]) == 2
    assert int(row["actual_rand_calls"]) == 10
    assert int(row["rand_calls_delta"]) == 8
    assert int(row["actual_deaths"]) == 1
    assert int(row["rng_stream_prefix_match"]) == 0
    assert int(row["rng_stream_compared"]) == 0
    assert row["rng_stream_first_mismatch_idx"] is None


def test_window_rows_include_rng_stream_mismatch_details() -> None:
    report = _load_report_module()
    start = 0x0BADF00D
    values = _crt_rand_values(start, 3)
    after = _step_crt_state(start, 3)

    expected_ckpt = _checkpoint(
        tick=6,
        rng_marks={"rand_calls": 3},
    )
    actual_ckpt = _checkpoint(
        tick=6,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after,
            "after_wave_spawns": after,
        },
    )

    rows = report._build_window_rows(
        expected_by_tick={6: expected_ckpt},
        actual_by_tick={6: actual_ckpt},
        raw_debug_by_tick={
            6: _capture_tick(
                tick=6,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1] ^ 1, branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
            ),
        },
        focus_tick=6,
        window=0,
    )

    assert len(rows) == 1
    row = rows[0]
    assert int(row["rng_stream_prefix_match"]) == 1
    assert int(row["rng_stream_compared"]) == 3
    assert int(row["rng_stream_first_mismatch_idx"]) == 1
    assert row["rng_stream_first_mismatch_reason"] == "value"
    assert row["rng_stream_first_mismatch_capture_branch_id"] == "0x00420fd7"
    assert int(row["rng_stream_missing_tail"]) == 0


def test_find_first_divergence_prefers_rng_stream_before_checkpoint_fields() -> None:
    report = _load_report_module()
    start = 0x10203040
    values = _crt_rand_values(start, 2)
    after_two = _step_crt_state(start, 2)

    expected_ckpt = _checkpoint(
        tick=9,
        rng_marks={
            "rand_calls": 2,
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )
    actual_ckpt = _checkpoint(
        tick=9,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    divergence = report._find_first_divergence(
        [expected_ckpt],
        [actual_ckpt],
        float_abs_tol=1e-3,
        max_field_diffs=16,
        raw_debug_by_tick={
            9: _capture_tick(
                tick=9,
                rng_head=[
                    _rng_head_entry(
                        seq=11,
                        tick_call_index=1,
                        value_15=values[0] ^ 1,
                        state_before_u32=start,
                        state_after_u32=_step_crt_state(start, 1),
                        branch_id="0x00420fd7",
                        caller_static="0x00420fd7",
                    ),
                    _rng_head_entry(
                        seq=12,
                        tick_call_index=2,
                        value_15=values[1],
                        state_before_u32=_step_crt_state(start, 1),
                        state_after_u32=after_two,
                        branch_id="0x00420fd7",
                        caller_static="0x00420fd7",
                    ),
                ],
            ),
        },
    )

    assert divergence is not None
    assert int(divergence.tick_index) == 9
    assert divergence.kind == "rng_stream_mismatch"
    assert divergence.field_diffs == tuple()


def test_find_first_divergence_ignores_one_tick_kills_lag() -> None:
    report = _load_report_module()

    expected = [
        _checkpoint(tick=5169, rng_marks={"rand_calls": 0}, kills=486, creature_count=51),
        _checkpoint(tick=5170, rng_marks={"rand_calls": 0}, kills=487, creature_count=51),
        _checkpoint(tick=5171, rng_marks={"rand_calls": 0}, kills=487, creature_count=51),
    ]
    actual = [
        _checkpoint(tick=5169, rng_marks={"rand_calls": 0}, kills=486, creature_count=51),
        _checkpoint(tick=5170, rng_marks={"rand_calls": 0}, kills=486, creature_count=51),
        _checkpoint(tick=5171, rng_marks={"rand_calls": 0}, kills=487, creature_count=51),
    ]

    divergence = report._find_first_divergence(
        expected,
        actual,
        float_abs_tol=1e-3,
        max_field_diffs=16,
    )

    assert divergence is None


def test_find_first_divergence_allows_one_tick_creature_count_sample_lag() -> None:
    report = _load_report_module()

    expected = [
        _checkpoint(tick=5178, rng_marks={"rand_calls": 0}, creature_count=52),
        _checkpoint(tick=5179, rng_marks={"rand_calls": 0}, creature_count=52),
        _checkpoint(tick=5180, rng_marks={"rand_calls": 0}, creature_count=51),
    ]
    actual = [
        _checkpoint(tick=5178, rng_marks={"rand_calls": 0}, creature_count=51),
        _checkpoint(tick=5179, rng_marks={"rand_calls": 0}, creature_count=51),
        _checkpoint(tick=5180, rng_marks={"rand_calls": 0}, creature_count=51),
    ]

    divergence = report._find_first_divergence(
        expected,
        actual,
        float_abs_tol=1e-3,
        max_field_diffs=16,
        capture_sample_creature_counts={5178: 52, 5179: 51, 5180: 51},
    )

    assert divergence is None


def test_load_raw_tick_debug_tracks_sample_coverage(tmp_path: Path) -> None:
    report = _load_report_module()
    capture_path = tmp_path / "capture.json"
    tick = {
        "tick_index": 42,
        "gameplay_frame": 43,
        "mode_hint": "survival_update",
        "game_mode_id": 6,
        "quest_stage_major": -1,
        "quest_stage_minor": -1,
        "focus_tick": False,
        "state_id_enter": None,
        "state_id_leave": None,
        "state_pending_enter": None,
        "state_pending_leave": None,
        "ts_enter_ms": 0,
        "ts_leave_ms": 0,
        "duration_ms": 0,
        "checkpoint": {
            "tick_index": 42,
            "state_hash": "s",
            "command_hash": "c",
            "rng_state": 0,
            "elapsed_ms": 0,
            "score_xp": 0,
            "kills": 0,
            "creature_count": 0,
            "perk_pending": 0,
            "players": [],
            "status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0, "weapon_usage_counts": []},
            "bonus_timers": {},
            "rng_marks": {
                "rand_calls": 0,
                "rand_hash": "",
                "rand_last": None,
                "rand_head": [],
                "rand_callers": [],
                "rand_caller_overflow": 0,
                "rand_seq_first": None,
                "rand_seq_last": None,
                "rand_seed_epoch_enter": None,
                "rand_seed_epoch_last": None,
                "rand_outside_before_calls": 0,
                "rand_outside_before_dropped": 0,
                "rand_outside_before_head": [],
                "rand_mirror_mismatch_total": 0,
                "rand_mirror_unknown_total": 0,
            },
            "deaths": [],
            "perk": {"pending_count": 0, "choices_dirty": False, "choices": [], "player_nonzero_counts": []},
            "events": {
                "hit_count": -1,
                "pickup_count": -1,
                "sfx_count": -1,
                "sfx_head": [],
                "rng_call_count": 0,
                "input_true_count": 0,
            },
            "debug": {
                "sampling_phase": "",
                "timing": _timing_diagnostics(),
                "spawn": _spawn_diagnostics(
                    event_count_projectile_find_query=3,
                    event_count_projectile_find_query_miss=1,
                    event_count_projectile_find_query_owner_collision=1,
                    top_projectile_find_query_callers=[{"key": "0x00420e52", "count": 3}],
                ),
                "rng": _rng_diagnostics(),
                "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
                "creature_lifecycle": None,
                "player_fire": _player_fire_diagnostics(),
                "before_players": [],
                "before_status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0},
            },
        },
        "event_counts": {
            "state_transition": 0,
            "player_fire": 0,
            "weapon_assign": 0,
            "bonus_apply": 0,
            "bonus_spawn": 0,
            "projectile_spawn": 0,
            "projectile_find_query": 3,
            "projectile_find_hit": 2,
            "secondary_projectile_spawn": 0,
            "player_damage": 0,
            "creature_damage": 0,
            "creature_spawn": 0,
            "creature_spawn_low": 0,
            "creature_death": 0,
            "creature_lifecycle": 0,
            "creature_update_micro": 0,
            "perk_apply": 0,
            "sfx": 0,
            "perk_delta": 0,
            "quest_timeline_delta": 0,
            "mode_tick": 0,
            "input_primary_edge": 0,
            "input_primary_down": 0,
            "input_any_key": 0,
        },
        "event_overflow": False,
        "event_heads": [
            {
                "type": "projectile_find_query",
                "data": {
                    "result_creature_index": None,
                    "result_kind": "miss",
                    "start_index": None,
                    "radius_f32": None,
                    "query_pos": {"x": 0.0, "y": 0.0},
                    "projectile_index": None,
                    "projectile_owner_id": None,
                    "projectile_type_id": None,
                    "projectile_hit_radius": None,
                    "owner_collision": False,
                    "player_find_skipped": False,
                    "shock_chain_projectile_id": None,
                    "shock_chain_links_left": None,
                    "caller": None,
                    "caller_static": "0x00420e52",
                    "backtrace": None,
                },
            },
            {
                "type": "projectile_find_query",
                "data": {
                    "result_creature_index": 19,
                    "result_kind": "owner_collision",
                    "start_index": None,
                    "radius_f32": None,
                    "query_pos": {"x": 0.0, "y": 0.0},
                    "projectile_index": None,
                    "projectile_owner_id": None,
                    "projectile_type_id": None,
                    "projectile_hit_radius": None,
                    "owner_collision": True,
                    "player_find_skipped": False,
                    "shock_chain_projectile_id": None,
                    "shock_chain_links_left": None,
                    "caller": None,
                    "caller_static": "0x00420e52",
                    "backtrace": None,
                },
            },
            {
                "type": "projectile_find_hit",
                "data": {
                    "result_creature_index": 19,
                    "result_kind": "hit",
                    "start_index": None,
                    "radius_f32": None,
                    "query_pos": {"x": 0.0, "y": 0.0},
                    "projectile_index": None,
                    "projectile_owner_id": None,
                    "projectile_type_id": None,
                    "projectile_hit_radius": None,
                    "owner_collision": False,
                    "player_find_skipped": False,
                    "shock_chain_projectile_id": None,
                    "shock_chain_links_left": None,
                    "caller": None,
                    "caller_static": "0x00420e52",
                    "backtrace": None,
                    "creature_index": 19,
                    "creature": None,
                    "corpse_hit": None,
                },
            },
        ],
        "phase_markers": [],
        "input_queries": {
            "stats": {
                "primary_edge": {"calls": 0, "true_calls": 0},
                "primary_down": {"calls": 0, "true_calls": 0},
                "any_key": {"calls": 0, "true_calls": 0},
            },
            "query_hash": "",
        },
        "input_player_keys": [
            {
                "player_index": 0,
                "move_forward_pressed": None,
                "move_backward_pressed": None,
                "turn_left_pressed": None,
                "turn_right_pressed": None,
                "fire_down": None,
                "fire_pressed": None,
                "reload_pressed": None,
            },
        ],
        "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
        "perk_apply_in_tick": [],
        "rng": {
            "calls": 0,
            "last_value": None,
            "hash": "",
            "head": [],
            "callers": [],
            "caller_overflow": 0,
            "seq_first": None,
            "seq_last": None,
            "seed_epoch_enter": None,
            "seed_epoch_last": None,
            "outside_before_calls": 0,
            "outside_before_dropped": 0,
            "outside_before_head": [],
            "mirror_mismatch_total": 0,
            "mirror_unknown_total": 0,
        },
        "diagnostics": {
            "sampling_phase": "",
            "timing": _timing_diagnostics(),
            "spawn": _spawn_diagnostics(),
            "rng": _rng_diagnostics(),
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "player_fire": _player_fire_diagnostics(),
        },
        "input_approx": [
            {
                "player_index": 0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": None,
                "move_mode": None,
                "aim_scheme": None,
                "fired_events": 0,
                "moving": None,
                "reload_active": None,
                "weapon_id": None,
                "move_forward_pressed": None,
                "move_backward_pressed": None,
                "turn_left_pressed": None,
                "turn_right_pressed": None,
                "fire_down": None,
                "fire_pressed": None,
                "reload_pressed": None,
            },
        ],
        "before": {
            "globals": _snapshot_globals(),
            "status": _snapshot_status(),
            "player_count": 1,
            "players": [],
            "input": _snapshot_input(),
            "input_bindings": _snapshot_input_bindings(),
        },
        "after": {
            "globals": _snapshot_globals(),
            "status": _snapshot_status(),
            "player_count": 1,
            "players": [],
            "input": _snapshot_input(),
            "input_bindings": _snapshot_input_bindings(),
        },
        "frame_dt_ms": None,
        "frame_dt_ms_i32": None,
        "creature_lifecycle": None,
        "samples": {
            "creatures": [
                {
                    "index": 5,
                    "active": 1,
                    "state_flag": 1,
                    "collision_flag": 1,
                    "hitbox_size": 16.0,
                    "pos": {"x": 10.0, "y": 20.0},
                    "hp": 100.0,
                    "type_id": 2,
                    "target_player": 0,
                    "flags": 0,
                    "link_index": None,
                    "ai_mode": None,
                    "heading": None,
                    "target_heading": None,
                    "orbit_angle": None,
                    "orbit_radius": None,
                    "ai7_timer_ms": None,
                },
            ],
            "projectiles": [],
            "secondary_projectiles": [
                {
                    "index": 7,
                    "active": 1,
                    "pos": {"x": 15.0, "y": 25.0},
                    "life_timer": 0.9,
                    "angle": 0.0,
                    "vel": {"x": 0.0, "y": 0.0},
                    "trail_timer": 0.0,
                    "type_id": 1,
                    "target_id": -1,
                },
            ],
            "bonuses": [],
        },
    }
    capture_obj = {
        "capture_format_version": int(CAPTURE_FORMAT_VERSION),
        "script": "gameplay_diff_capture",
        "session_id": "s",
        "out_path": "capture.json",
        "config": _base_config(),
        "session_fingerprint": {"session_id": "s", "module_hash": "a", "ptrs_hash": "b"},
        "process": {"pid": 1, "platform": "windows", "arch": "x86", "frida_version": "16", "runtime": "v8"},
        "exe": {"base": "0x400000", "size": 1, "path": "crimsonland.exe"},
        "grim": None,
        "pointers_resolved": {},
        "ticks": [tick],
    }
    meta = {k: v for k, v in capture_obj.items() if k != "ticks"}
    meta["ticks"] = []
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True),
    ]
    capture_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    raw = report._load_raw_tick_debug(capture_path, {42})
    assert 42 in raw
    tick = raw[42]
    assert len(tick.samples.creatures) == 1
    assert len(tick.samples.secondary_projectiles) == 1
    assert int(tick.samples.secondary_projectiles[0].index) == 7
    assert int(tick.samples.creatures[0].index) == 5
    assert int(tick.event_counts.projectile_find_query) == 3
    assert int(tick.checkpoint.debug.spawn.event_count_projectile_find_query_miss) == 1
    assert int(tick.checkpoint.debug.spawn.event_count_projectile_find_query_owner_collision) == 1
    assert [
        {"key": str(item.key), "count": int(item.count)}
        for item in tick.checkpoint.debug.spawn.top_projectile_find_query_callers
    ] == [{"key": "0x00420e52", "count": 3}]


def test_investigation_leads_flag_missing_focus_samples() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(
        tick=5,
        rng_marks={"rand_calls": 0},
    )
    actual_ckpt = _checkpoint(
        tick=5,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
    )
    divergence = report.Divergence(
        tick_index=5,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=5,
        lookback_ticks=32,
        float_abs_tol=1e-3,
        expected_by_tick={5: expected_ckpt},
        actual_by_tick={5: actual_ckpt},
        raw_debug_by_tick={},
        native_ranges=tuple(),
    )
    assert any(lead.title == "Capture lacks entity samples at the focus tick" for lead in leads)


def test_investigation_leads_flag_focus_micro_head_cap() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(
        tick=5,
        rng_marks={"rand_calls": 0},
    )
    actual_ckpt = _checkpoint(
        tick=5,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
    )
    divergence = report.Divergence(
        tick_index=5,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=5,
        lookback_ticks=32,
        float_abs_tol=1e-3,
        expected_by_tick={5: expected_ckpt},
        actual_by_tick={5: actual_ckpt},
        raw_debug_by_tick={
            5: _capture_tick(
                tick=5,
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
                event_counts={"creature_update_micro": 128},
            ),
        },
        native_ranges=tuple(),
        capture_config={
            "creature_micro_max_head_per_tick": 128,
            "creature_micro_slots": [],
            "creature_micro_tick_start": -1,
            "creature_micro_tick_end": -1,
        },
    )

    lead = next(
        (
            item
            for item in leads
            if item.title == "Capture creature-update micro telemetry likely head-capped at focus tick"
        ),
        None,
    )
    assert lead is not None
    assert any("count=128 cap=128" in line for line in lead.evidence)


def test_divergence_category_prefers_projectile_hit_shortfall_signature() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(tick=10, rng_marks={"rand_calls": 0})
    actual_ckpt = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": 0x12345678,
            "after_world_step": 0x12345678,
            "after_wave_spawns": 0x12345678,
        },
        events=ReplayEventSummary(hit_count=1, pickup_count=0, sfx_count=0, sfx_head=[]),
    )
    divergence = report.Divergence(
        tick_index=10,
        kind="rng_stream_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    category = report._classify_divergence_category(
        divergence=divergence,
        leads=[],
        focus_raw=_capture_tick(tick=10, event_counts={"projectile_find_hit": 2}),
        focus_actual_ckpt=actual_ckpt,
    )

    assert category.id == "rng.projectile_hit_resolution_shortfall"


def test_divergence_category_ignores_owner_collision_queries_for_shortfall_signature() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(tick=10, rng_marks={"rand_calls": 0})
    actual_ckpt = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": 0x12345678,
            "after_world_step": 0x12345678,
            "after_wave_spawns": 0x12345678,
        },
        events=ReplayEventSummary(hit_count=1, pickup_count=0, sfx_count=0, sfx_head=[]),
    )
    divergence = report.Divergence(
        tick_index=10,
        kind="rng_stream_mismatch",
        field_diffs=tuple(),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    category = report._classify_divergence_category(
        divergence=divergence,
        leads=[],
        focus_raw=_capture_tick(
            tick=10,
            event_counts={"projectile_find_hit": 3},
            spawn={"event_count_projectile_find_query_owner_collision": 2},
        ),
        focus_actual_ckpt=actual_ckpt,
    )

    assert category.id == "rng.stream_mismatch"


def test_divergence_category_marks_player_motion_precision_drift() -> None:
    report = _load_report_module()
    expected_ckpt = _checkpoint(tick=12, rng_marks={"rand_calls": 0})
    actual_ckpt = _checkpoint(
        tick=12,
        rng_marks={
            "before_world_step": 0x87654321,
            "after_world_step": 0x87654321,
            "after_wave_spawns": 0x87654321,
        },
    )
    divergence = report.Divergence(
        tick_index=12,
        kind="state_mismatch",
        field_diffs=(report.ReplayFieldDiff(field="players[0].pos.x", expected=10.0, actual=10.125),),
        expected=expected_ckpt,
        actual=actual_ckpt,
    )

    category = report._classify_divergence_category(
        divergence=divergence,
        leads=[],
        focus_raw=None,
        focus_actual_ckpt=actual_ckpt,
    )

    assert category.id == "state.player_motion_precision_drift"


def test_find_first_rng_head_shortfall_detects_pre_focus_gap() -> None:
    report = _load_report_module()
    start = 0x10203040
    values = _crt_rand_values(start, 3)
    after_two = _step_crt_state(start, 2)

    expected_ckpt = _checkpoint(
        tick=7,
        rng_marks={"rand_calls": 3},
    )
    actual_ckpt = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    shortfall = report._find_first_rng_head_shortfall(
        expected_by_tick={7: expected_ckpt},
        actual_by_tick={7: actual_ckpt},
        raw_debug_by_tick={
            7: _capture_tick(
                tick=7,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[{"caller_static": "0x00420fd7", "calls": 3}],
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 7
    assert int(shortfall["expected_head_len"]) == 3
    assert int(shortfall["actual_rand_calls"]) == 2
    assert int(shortfall["missing_draws"]) == 1


def test_find_first_rng_head_shortfall_detects_stream_value_mismatch() -> None:
    report = _load_report_module()
    start = 0x21436587
    values = _crt_rand_values(start, 3)
    after_three = _step_crt_state(start, 3)

    expected_ckpt = _checkpoint(
        tick=8,
        rng_marks={"rand_calls": 3},
    )
    actual_ckpt = _checkpoint(
        tick=8,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )

    shortfall = report._find_first_rng_head_shortfall(
        expected_by_tick={8: expected_ckpt},
        actual_by_tick={8: actual_ckpt},
        raw_debug_by_tick={
            8: _capture_tick(
                tick=8,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0] ^ 1, branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[{"caller_static": "0x00420fd7", "calls": 3}],
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 8
    assert int(shortfall["stream_first_mismatch_idx"]) == 0
    assert int(shortfall["stream_first_mismatch_capture"]) != int(shortfall["stream_first_mismatch_actual"])
    assert int(shortfall["stream_missing_tail"]) == 0
    assert int(shortfall["missing_draws"]) == 0


def test_investigation_leads_include_rng_head_shortfall() -> None:
    report = _load_report_module()
    start = 0x55667788
    values = _crt_rand_values(start, 3)
    after_two = _step_crt_state(start, 2)

    expected_shortfall = _checkpoint(
        tick=7,
        rng_marks={"rand_calls": 3},
    )
    actual_shortfall = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    expected_focus = _checkpoint(
        tick=10,
        rng_marks={"rand_calls": 0},
    )
    actual_focus = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": after_two,
            "after_world_step": after_two,
            "after_wave_spawns": after_two,
        },
    )

    divergence = report.Divergence(
        tick_index=10,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_focus,
        actual=actual_focus,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=10,
        lookback_ticks=8,
        float_abs_tol=1e-3,
        expected_by_tick={7: expected_shortfall, 10: expected_focus},
        actual_by_tick={7: actual_shortfall, 10: actual_focus},
        raw_debug_by_tick={
            7: _capture_tick(
                tick=7,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[{"caller_static": "0x00420fd7", "calls": 3}],
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
            10: _capture_tick(
                tick=10,
                rng_rand_calls=0,
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
        },
        native_ranges=(report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),),
    )

    lead = next(
        (item for item in leads if item.title == "Pre-focus RNG-head shortfall indicates missing RNG-consuming branch"),
        None,
    )
    assert lead is not None
    assert "projectile_update" in lead.native_functions


def test_investigation_leads_include_rng_stream_mismatch() -> None:
    report = _load_report_module()
    start = 0x55667788
    values = _crt_rand_values(start, 3)
    after_three = _step_crt_state(start, 3)

    expected_shortfall = _checkpoint(
        tick=7,
        rng_marks={"rand_calls": 3},
    )
    actual_shortfall = _checkpoint(
        tick=7,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )

    expected_focus = _checkpoint(
        tick=10,
        rng_marks={"rand_calls": 0},
    )
    actual_focus = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": after_three,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )

    divergence = report.Divergence(
        tick_index=10,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_focus,
        actual=actual_focus,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=10,
        lookback_ticks=8,
        float_abs_tol=1e-3,
        expected_by_tick={7: expected_shortfall, 10: expected_focus},
        actual_by_tick={7: actual_shortfall, 10: actual_focus},
        raw_debug_by_tick={
            7: _capture_tick(
                tick=7,
                rng_rand_calls=3,
                rng_head=[
                    _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=2, value_15=values[1] ^ 1, branch_id="0x00420fd7"),
                    _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7"),
                ],
                rng_callers=[{"caller_static": "0x00420fd7", "calls": 3}],
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
            10: _capture_tick(
                tick=10,
                rng_rand_calls=0,
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
            ),
        },
        native_ranges=(report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),),
    )

    lead = next(
        (item for item in leads if item.title == "Pre-focus RNG stream mismatch indicates branch divergence"), None,
    )
    assert lead is not None
    assert "projectile_update" in lead.native_functions


def test_find_first_projectile_hit_shortfall_detects_gap() -> None:
    report = _load_report_module()
    actual_ckpt = _checkpoint(
        tick=12,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
        events=ReplayEventSummary(hit_count=4, pickup_count=0, sfx_count=0, sfx_head=[]),
    )

    shortfall = report._find_first_projectile_hit_shortfall(
        actual_by_tick={12: actual_ckpt},
        raw_debug_by_tick={
            12: _capture_tick(
                tick=12,
                event_counts={"projectile_find_hit": 6, "projectile_find_query": 8},
                spawn={
                    "event_count_projectile_find_query_miss": 2,
                    "event_count_projectile_find_query_owner_collision": 1,
                    "top_projectile_find_query_callers": [{"key": "0x00420e52", "count": 8}],
                    "top_projectile_find_hit_callers": [{"key": "0x00420fd7", "count": 5}],
                },
                event_heads=[
                    {
                        "type": "projectile_find_hit",
                        "data": {
                            "result_creature_index": 19,
                            "result_kind": "hit",
                            "start_index": None,
                            "radius_f32": None,
                            "query_pos": {"x": 0.0, "y": 0.0},
                            "projectile_index": None,
                            "projectile_owner_id": None,
                            "projectile_type_id": None,
                            "projectile_hit_radius": None,
                            "owner_collision": False,
                            "player_find_skipped": False,
                            "shock_chain_projectile_id": None,
                            "shock_chain_links_left": None,
                            "caller": None,
                            "caller_static": "0x00420fd7",
                            "backtrace": None,
                            "creature_index": 19,
                            "creature": None,
                            "corpse_hit": True,
                        },
                    },
                ],
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is not None
    assert int(shortfall["tick"]) == 12
    assert int(shortfall["capture_hits"]) == 5
    assert int(shortfall["capture_hits_raw"]) == 6
    assert int(shortfall["actual_hits"]) == 4
    assert int(shortfall["missing_hits"]) == 1
    assert int(shortfall["query_counts"]) == 8
    assert int(shortfall["query_miss_count"]) == 2
    assert int(shortfall["query_owner_collision_count"]) == 1


def test_find_first_projectile_hit_shortfall_ignores_owner_collision_queries() -> None:
    report = _load_report_module()
    actual_ckpt = _checkpoint(
        tick=12,
        rng_marks={
            "before_world_step": 0x11111111,
            "after_world_step": 0x11111111,
            "after_wave_spawns": 0x11111111,
        },
        events=ReplayEventSummary(hit_count=3, pickup_count=0, sfx_count=0, sfx_head=[]),
    )

    shortfall = report._find_first_projectile_hit_shortfall(
        actual_by_tick={12: actual_ckpt},
        raw_debug_by_tick={
            12: _capture_tick(
                tick=12,
                event_counts={"projectile_find_hit": 5},
                spawn={"event_count_projectile_find_query_owner_collision": 2},
            ),
        },
        start_tick=0,
        end_tick=16,
    )

    assert shortfall is None


def test_investigation_leads_include_projectile_hit_shortfall() -> None:
    report = _load_report_module()
    expected_focus = _checkpoint(
        tick=10,
        rng_marks={"rand_calls": 0},
    )
    actual_focus = _checkpoint(
        tick=10,
        rng_marks={
            "before_world_step": 0x12345678,
            "after_world_step": 0x12345678,
            "after_wave_spawns": 0x12345678,
        },
        events=ReplayEventSummary(hit_count=4, pickup_count=0, sfx_count=0, sfx_head=[]),
    )
    divergence = report.Divergence(
        tick_index=10,
        kind="state_mismatch",
        field_diffs=tuple(),
        expected=expected_focus,
        actual=actual_focus,
    )

    leads = report._build_investigation_leads(
        divergence=divergence,
        focus_tick=10,
        lookback_ticks=8,
        float_abs_tol=1e-3,
        expected_by_tick={10: expected_focus},
        actual_by_tick={10: actual_focus},
        raw_debug_by_tick={
            10: _capture_tick(
                tick=10,
                rng_rand_calls=0,
                event_counts={"projectile_find_hit": 7, "projectile_find_query": 9},
                spawn={
                    "event_count_projectile_find_query_miss": 2,
                    "event_count_projectile_find_query_owner_collision": 1,
                    "top_projectile_find_query_callers": [{"key": "0x00420e52", "count": 9}],
                    "top_projectile_find_hit_callers": [{"key": "0x00420fd7", "count": 6}],
                },
                sample_counts={"creatures": 1, "projectiles": 1, "secondary_projectiles": 0, "bonuses": 0},
                event_heads=[
                    {
                        "type": "projectile_find_hit",
                        "data": {
                            "result_creature_index": 19,
                            "result_kind": "hit",
                            "start_index": None,
                            "radius_f32": None,
                            "query_pos": {"x": 0.0, "y": 0.0},
                            "projectile_index": None,
                            "projectile_owner_id": None,
                            "projectile_type_id": None,
                            "projectile_hit_radius": None,
                            "owner_collision": False,
                            "player_find_skipped": False,
                            "shock_chain_projectile_id": None,
                            "shock_chain_links_left": None,
                            "caller": None,
                            "caller_static": "0x00420fd7",
                            "backtrace": None,
                            "creature_index": 19,
                            "creature": None,
                            "corpse_hit": True,
                        },
                    },
                    {
                        "type": "projectile_find_hit",
                        "data": {
                            "result_creature_index": 20,
                            "result_kind": "hit",
                            "start_index": None,
                            "radius_f32": None,
                            "query_pos": {"x": 0.0, "y": 0.0},
                            "projectile_index": None,
                            "projectile_owner_id": None,
                            "projectile_type_id": None,
                            "projectile_hit_radius": None,
                            "owner_collision": False,
                            "player_find_skipped": False,
                            "shock_chain_projectile_id": None,
                            "shock_chain_links_left": None,
                            "caller": None,
                            "caller_static": "0x00420fd7",
                            "backtrace": None,
                            "creature_index": 20,
                            "creature": None,
                            "corpse_hit": True,
                        },
                    },
                ],
            ),
        },
        native_ranges=(report.NativeFunctionRange(name="projectile_update", start=0x00420B90, end=0x00422C70),),
    )

    lead = next(
        (item for item in leads if item.title == "Native projectile hit resolves exceed rewrite hit events"), None,
    )
    assert lead is not None
    assert "projectile_update" in lead.native_functions
