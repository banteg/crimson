from __future__ import annotations

import json
from pathlib import Path

from crimson.game_modes import GameMode
from crimson.original.schema import CAPTURE_FORMAT_VERSION
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
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


def _event_counts_dict(**kwargs: object) -> dict[str, object]:
    row = {
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


def _rng_summary_dict(**kwargs: object) -> dict[str, object]:
    row = {
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


def _input_player_keys(**kwargs: object) -> dict[str, object]:
    row = {
        "player_index": 0,
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


def _input_approx(**kwargs: object) -> dict[str, object]:
    row = {
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


def _checkpoint_tick(
    tick: int, *, level: int, weapon_id: int, experience: int, perk_pairs: list[list[int]],
) -> dict[str, object]:
    return {
        "tick_index": int(tick),
        "state_hash": f"s{tick}",
        "command_hash": f"c{tick}",
        "rng_state": 0,
        "elapsed_ms": int(tick) * 16,
        "score_xp": int(experience),
        "kills": 0,
        "creature_count": 0,
        "perk_pending": 0,
        "players": [
            {
                "pos": {"x": 0.0, "y": 0.0},
                "health": 100.0,
                "weapon_id": int(weapon_id),
                "ammo": 12.0,
                "experience": int(experience),
                "level": int(level),
                "bonus_timers": {},
            },
        ],
        "status": {
            "quest_unlock_index": 0,
            "quest_unlock_index_full": 0,
            "weapon_usage_counts": [],
        },
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
        "perk": {
            "pending_count": 0,
            "choices_dirty": False,
            "choices": [],
            "player_nonzero_counts": [perk_pairs],
        },
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
            "spawn": _spawn_diagnostics(),
            "rng": _rng_diagnostics(),
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "player_fire": _player_fire_diagnostics(),
            "before_players": [],
            "before_status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0},
        },
    }


def _capture_tick(
    tick: int,
    *,
    level: int,
    weapon_id: int,
    experience: int,
    perk_pairs: list[list[int]],
    event_heads: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "tick_index": int(tick),
        "gameplay_frame": int(tick) + 1,
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
        "checkpoint": _checkpoint_tick(
            tick,
            level=int(level),
            weapon_id=int(weapon_id),
            experience=int(experience),
            perk_pairs=perk_pairs,
        ),
        "event_counts": _event_counts_dict(),
        "event_overflow": False,
        "event_heads": list(event_heads),
        "phase_markers": [],
        "input_queries": {
            "stats": {
                "primary_edge": {"calls": 0, "true_calls": 0},
                "primary_down": {"calls": 0, "true_calls": 0},
                "any_key": {"calls": 0, "true_calls": 0},
            },
            "query_hash": "",
        },
        "input_player_keys": [_input_player_keys(player_index=0)],
        "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
        "perk_apply_in_tick": [],
        "rng": _rng_summary_dict(),
        "diagnostics": {
            "sampling_phase": "",
            "timing": _timing_diagnostics(),
            "spawn": _spawn_diagnostics(),
            "rng": _rng_diagnostics(),
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "player_fire": _player_fire_diagnostics(),
        },
        "input_approx": [_input_approx(player_index=0, aim_x=0.0, aim_y=0.0)],
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
            "creatures": [],
            "projectiles": [],
            "secondary_projectiles": [],
            "bonuses": [],
        },
    }


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    return {
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
        "ticks": ticks,
    }


def _write_capture_stream(path: Path, capture: dict[str, object]) -> None:
    meta = {k: v for k, v in capture.items() if k != "ticks"}
    meta["ticks"] = []
    ticks_obj = capture.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_run_summary_events_from_raw_capture(tmp_path: Path) -> None:
    report = _load_report_module()
    capture_path = tmp_path / "capture.json"
    capture = _capture_obj(
        ticks=[
            _capture_tick(
                0,
                level=1,
                weapon_id=1,
                experience=0,
                perk_pairs=[],
                event_heads=[
                    {
                        "type": "bonus_apply",
                        "data": {
                            "player_index": 0,
                            "bonus_id": 3,
                            "entry_state": None,
                            "amount_i32": 12,
                            "amount_f32": 12.0,
                            "caller": None,
                        },
                    },
                    {
                        "type": "weapon_assign",
                        "data": {
                            "player_index": 0,
                            "weapon_id": 12,
                            "weapon_before": 1,
                            "weapon_after": 12,
                            "caller": None,
                        },
                    },
                    {"type": "state_transition", "data": {"before": {"id": 9}, "after": {"id": 6}}},
                ],
            ),
            _capture_tick(
                1,
                level=2,
                weapon_id=12,
                experience=120,
                perk_pairs=[[20, 1]],
                event_heads=[],
            ),
        ],
    )
    _write_capture_stream(capture_path, capture)

    events = report._build_run_summary_events_from_raw_capture(capture_path)

    assert any(event.kind == "bonus_pickup" and "Weapon (3)" in event.detail for event in events)
    assert any(event.kind == "weapon_assign" and "Pistol (1)" in event.detail for event in events)
    assert any(event.kind == "state_transition" and "state 9 -> 6" in event.detail for event in events)
    assert any(event.kind == "level_up" and "level 1 -> 2" in event.detail for event in events)
    assert any(event.kind == "perk_pick" and "Telekinetic (20)" in event.detail for event in events)


def test_run_summary_events_fall_back_to_checkpoints() -> None:
    report = _load_report_module()
    expected = [
        ReplayCheckpoint(
            tick_index=0,
            rng_state=1,
            elapsed_ms=0,
            score_xp=0,
            kills=0,
            creature_count=0,
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
            state_hash="a",
            command_hash="a",
            rng_marks={},
            deaths=[],
            perk=ReplayPerkSnapshot(player_nonzero_counts=[[]]),
            events=ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1),
        ),
        ReplayCheckpoint(
            tick_index=1,
            rng_state=2,
            elapsed_ms=16,
            score_xp=100,
            kills=0,
            creature_count=0,
            perk_pending=0,
            players=[
                ReplayPlayerCheckpoint(
                    pos=Vec2(1.0, 1.0),
                    health=100.0,
                    weapon_id=12,
                    ammo=4.0,
                    experience=100,
                    level=2,
                ),
            ],
            bonus_timers={},
            state_hash="b",
            command_hash="b",
            rng_marks={},
            deaths=[],
            perk=ReplayPerkSnapshot(player_nonzero_counts=[[[20, 1]]]),
            events=ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1),
        ),
    ]

    events = report._build_run_summary_events(Path("capture.json.gz"), expected=expected)

    assert any(event.kind == "weapon_assign" and "Pistol (1)" in event.detail for event in events)
    assert any(event.kind == "level_up" and "level 1 -> 2" in event.detail for event in events)
    assert any(event.kind == "perk_pick" and "Telekinetic (20)" in event.detail for event in events)


def test_build_short_run_summary_events_prefers_key_kinds() -> None:
    report = _load_report_module()
    events = [
        report.RunSummaryEvent(tick_index=10, kind="weapon_assign", detail="weapon change"),
        report.RunSummaryEvent(tick_index=11, kind="perk_pick", detail="perk pick"),
        report.RunSummaryEvent(tick_index=12, kind="debug_note", detail="ignored detail"),
        report.RunSummaryEvent(tick_index=13, kind="bonus_pickup", detail="bonus"),
        report.RunSummaryEvent(tick_index=14, kind="state_transition", detail="state"),
    ]

    short_events = report._build_short_run_summary_events(events, max_rows=3)

    assert [event.kind for event in short_events] == [
        "weapon_assign",
        "perk_pick",
        "bonus_pickup",
    ]


def test_build_focus_run_summary_events_uses_short_kinds_around_focus() -> None:
    report = _load_report_module()
    events = [
        report.RunSummaryEvent(tick_index=90, kind="debug_note", detail="ignored"),
        report.RunSummaryEvent(tick_index=95, kind="bonus_pickup", detail="bonus"),
        report.RunSummaryEvent(tick_index=98, kind="weapon_assign", detail="weapon"),
        report.RunSummaryEvent(tick_index=100, kind="debug_note", detail="ignored focus"),
        report.RunSummaryEvent(tick_index=101, kind="perk_pick", detail="perk"),
        report.RunSummaryEvent(tick_index=106, kind="level_up", detail="lvl"),
        report.RunSummaryEvent(tick_index=110, kind="state_transition", detail="state"),
    ]

    focus_events = report._build_focus_run_summary_events(
        events,
        focus_tick=100,
        before_rows=2,
        after_rows=2,
    )

    assert [(event.tick_index, event.kind) for event in focus_events] == [
        (95, "bonus_pickup"),
        (98, "weapon_assign"),
        (101, "perk_pick"),
        (106, "level_up"),
    ]


def test_build_focus_run_summary_events_falls_back_when_no_short_kinds() -> None:
    report = _load_report_module()
    events = [
        report.RunSummaryEvent(tick_index=10, kind="debug_note", detail="a"),
        report.RunSummaryEvent(tick_index=12, kind="debug_note", detail="b"),
        report.RunSummaryEvent(tick_index=15, kind="debug_note", detail="c"),
    ]

    focus_events = report._build_focus_run_summary_events(
        events,
        focus_tick=12,
        before_rows=1,
        after_rows=1,
    )

    assert [(event.tick_index, event.kind, event.detail) for event in focus_events] == [
        (12, "debug_note", "b"),
        (15, "debug_note", "c"),
    ]
