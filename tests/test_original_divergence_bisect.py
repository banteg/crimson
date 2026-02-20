from __future__ import annotations

from typing import cast

import msgspec

from crimson.game_modes import GameMode
from crimson.original import divergence_bisect
from crimson.original.schema import CaptureTick
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from grim.geom import Vec2


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
    deaths: list[ReplayDeathLedgerEntry] | None = None,
    events: ReplayEventSummary | None = None,
) -> ReplayCheckpoint:
    return ReplayCheckpoint(
        tick_index=int(tick),
        rng_state=int(rng_marks.get("after_wave_spawns", rng_marks.get("after_world_step", 0))),
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
        state_hash="state",
        command_hash="cmd",
        rng_marks=dict(rng_marks),
        deaths=list(deaths or []),
        perk=ReplayPerkSnapshot(),
        events=events if events is not None else ReplayEventSummary(),
    )


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


def _capture_tick_for_repro(
    *,
    tick: int,
    rng_rand_calls: int,
    rng_head: list[dict[str, object]],
    event_heads: list[dict[str, object]],
) -> CaptureTick:
    row: dict[str, object] = {
        "tick_index": int(tick),
        "gameplay_frame": int(tick) + 1,
        "before": {
            "globals": {
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
            },
            "status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0, "weapon_usage_counts": []},
            "player_count": 1,
            "players": [],
            "input": {
                "console_open": 0,
                "primary_latch": 0,
                "mouse_x": 0.0,
                "mouse_y": 0.0,
                "aim_screen": [{"player_index": 0, "x": 0.0, "y": 0.0}],
            },
            "input_bindings": {
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
            },
        },
        "after": {
            "globals": {
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
            },
            "status": {"quest_unlock_index": 0, "quest_unlock_index_full": 0, "weapon_usage_counts": []},
            "player_count": 1,
            "players": [],
            "input": {
                "console_open": 0,
                "primary_latch": 0,
                "mouse_x": 0.0,
                "mouse_y": 0.0,
                "aim_screen": [{"player_index": 0, "x": 0.0, "y": 0.0}],
            },
            "input_bindings": {
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
            },
        },
        "samples": {"creatures": [], "projectiles": [], "secondary_projectiles": [], "bonuses": []},
        "focus_tick": False,
        "state_id_enter": None,
        "state_id_leave": None,
        "state_pending_enter": None,
        "state_pending_leave": None,
        "mode_hint": "survival_update",
        "game_mode_id": int(GameMode.SURVIVAL),
        "quest_stage_major": -1,
        "quest_stage_minor": -1,
        "ts_enter_ms": 0,
        "ts_leave_ms": 0,
        "duration_ms": 0,
        "checkpoint": {
            "tick_index": int(tick),
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
                "rand_calls": int(rng_rand_calls),
                "rand_hash": "",
                "rand_last": None,
                "rand_head": list(rng_head),
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
                "timing": {
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
                },
                "spawn": {
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
                },
                "rng": {
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
                },
                "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
                "creature_lifecycle": None,
                "player_fire": {
                    "event_count_player_fire": 0,
                    "top_direct_events_by_player": [],
                    "top_fallback_events_by_player": [],
                    "top_player_projectile_spawns_by_player": [],
                },
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
        },
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
        "input_player_keys": [],
        "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
        "perk_apply_in_tick": [],
        "rng": {
            "calls": int(rng_rand_calls),
            "last_value": None,
            "hash": "",
            "head": list(rng_head),
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
            "timing": {
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
            },
            "spawn": {
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
            },
            "rng": {
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
            },
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "player_fire": {
                "event_count_player_fire": 0,
                "top_direct_events_by_player": [],
                "top_fallback_events_by_player": [],
                "top_player_projectile_spawns_by_player": [],
            },
        },
        "input_approx": [],
        "frame_dt_ms": None,
        "frame_dt_ms_i32": None,
        "creature_lifecycle": None,
    }
    return msgspec.convert(row, type=CaptureTick, strict=True)


def test_binary_search_first_bad_tick() -> None:
    first = divergence_bisect._binary_search_first_bad_tick(
        start_tick=0,
        end_tick=32,
        is_bad=lambda tick: int(tick) >= 11,
    )
    assert first == 11

    none = divergence_bisect._binary_search_first_bad_tick(
        start_tick=0,
        end_tick=32,
        is_bad=lambda _tick: False,
    )
    assert none is None


def test_build_repro_tick_row_includes_rng_stream_and_branch_events() -> None:
    start = 0x55667788
    values = _crt_rand_values(start, 3)
    after_three = _step_crt_state(start, 3)

    expected = _checkpoint(
        tick=25,
        rng_marks={
            "rand_calls": 3,
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )
    actual = _checkpoint(
        tick=25,
        rng_marks={
            "before_world_step": start,
            "after_world_step": after_three,
            "after_wave_spawns": after_three,
        },
    )
    raw = _capture_tick_for_repro(
        tick=25,
        rng_rand_calls=3,
        rng_head=[
            _rng_head_entry(tick_call_index=1, value_15=values[0], branch_id="0x00420fd7", caller_static="0x00420fd7"),
            _rng_head_entry(
                tick_call_index=2,
                value_15=values[1] ^ 1,
                branch_id="0x00420fd7",
                caller_static="0x00420fd7",
            ),
            _rng_head_entry(tick_call_index=3, value_15=values[2], branch_id="0x00420fd7", caller_static="0x00420fd7"),
        ],
        event_heads=[
            {
                "type": "creature_damage",
                "data": {
                    "creature_index": 3,
                    "damage_f32": None,
                    "damage_type": None,
                    "impulse_x": None,
                    "impulse_y": None,
                    "hp_before": None,
                    "hp_after": None,
                    "hp_delta": None,
                    "killed": None,
                    "kill_return": None,
                    "active_before": None,
                    "active_after": None,
                    "caller": None,
                    "caller_static": "0x004207c0",
                    "backtrace": None,
                },
            },
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
                "type": "projectile_find_hit",
                "data": {
                    "result_creature_index": 3,
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
                    "creature_index": 3,
                    "creature": None,
                    "corpse_hit": None,
                },
            },
        ],
    )

    row = divergence_bisect._build_repro_tick_row(
        tick=25,
        expected=expected,
        actual=actual,
        raw=raw,
        rng_row_limit=8,
        branch_event_limit=4,
    )

    assert int(row["tick"]) == 25
    align = row["rng_stream_alignment"]
    first_mismatch_idx = align["first_mismatch_idx"]
    assert first_mismatch_idx is not None
    assert first_mismatch_idx == 1
    assert align["first_mismatch_reason"] == "value"
    assert align["first_mismatch_capture_branch_id"] == "0x00420fd7"
    capture_rows = row["capture_rng_stream_rows"]
    assert isinstance(capture_rows, list)
    assert str(capture_rows[0]["branch_id"]) == "0x00420fd7"
    branch_events = row["capture_branch_events"]
    assert isinstance(branch_events, dict)
    creature_damage_head = branch_events["creature_damage_head"]
    assert isinstance(creature_damage_head, list)
    first_event = creature_damage_head[0]
    assert isinstance(first_event, dict)
    first_event_map = cast("dict[str, object]", first_event)
    creature_index = first_event_map.get("creature_index")
    caller_static = first_event_map.get("caller_static")
    assert isinstance(creature_index, int)
    assert creature_index == 3
    assert isinstance(caller_static, str)
    assert caller_static == "0x004207c0"
