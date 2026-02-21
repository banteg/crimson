from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

import msgspec

from crimson.original.schema import (
    CaptureCheckpoint,
    CaptureCheckpointDebug,
    CaptureCheckpointDebugStatus,
    CaptureConfig,
    CaptureDiagnostics,
    CaptureEventCounts,
    CaptureEventSummary,
    CaptureInputQueries,
    CaptureInputQueryCounter,
    CaptureInputQueryStats,
    CapturePerkApplyOutsideBefore,
    CapturePerkSnapshot,
    CapturePlayerFireDiagnostics,
    CaptureRngDiagnostics,
    CaptureRngMarks,
    CaptureRngSummary,
    CaptureSnapshotGlobals,
    CaptureSnapshotInput,
    CaptureSnapshotInputAimScreen,
    CaptureSnapshotInputBindingAlternateSingle,
    CaptureSnapshotInputBindingPlayer,
    CaptureSnapshotInputBindings,
    CaptureSnapshotStatus,
    CaptureSpawnDiagnostics,
    CaptureStatusSnapshot,
    CaptureTimingDiagnostics,
    ModuleInfo,
    ProcessInfo,
    SessionFingerprint,
)


def _empty_snapshot() -> CaptureSnapshot:
    return CaptureSnapshot(
        globals=CaptureSnapshotGlobals(
            config_game_mode=int(GameMode.SURVIVAL),
            config_player_mode_flags=[0],
            config_aim_scheme=[None],
            game_state_prev=0,
            game_state_id=0,
            game_state_pending=0,
            frame_dt=None,
            frame_dt_ms_i32=None,
            frame_dt_ms_f32=None,
            time_played_ms=0,
            creature_active_count=0,
            creature_kill_count=0,
            perk_pending_count=0,
            perk_choices_dirty=0,
            shock_chain_links_left=0,
            shock_chain_projectile_id=0,
            quest_spawn_timeline=0,
            quest_stage_major=-1,
            quest_stage_minor=-1,
            quest_spawn_stall_timer_ms=0,
            quest_transition_timer_ms=0,
            quest_stage_banner_timer_ms=0,
            ui_elements_timeline=0.0,
            ui_transition_direction=0,
            ui_transition_alpha=0.0,
            pause_keybind_help_alpha_ms=0,
            player_alt_weapon_swap_cooldown_ms=0,
            perk_jinxed_proc_timer_s=0.0,
            perk_lean_mean_exp_tick_timer_s=0.0,
            perk_doctor_target_creature_id=-1,
            bonus_reflex_boost_timer=0.0,
            bonus_freeze_timer=0.0,
            bonus_weapon_power_up_timer=0.0,
            bonus_energizer_timer=0.0,
            bonus_double_xp_timer=0.0,
        ),
        status=CaptureSnapshotStatus(
            quest_unlock_index=0,
            quest_unlock_index_full=0,
            weapon_usage_counts=[],
        ),
        player_count=1,
        players=[],
        input=CaptureSnapshotInput(
            console_open=0,
            primary_latch=0,
            mouse_x=0.0,
            mouse_y=0.0,
            aim_screen=[CaptureSnapshotInputAimScreen(player_index=0, x=0.0, y=0.0)],
        ),
        input_bindings=CaptureSnapshotInputBindings(
            players=[
                CaptureSnapshotInputBindingPlayer(
                    player_index=0,
                    move_forward=0,
                    move_backward=0,
                    turn_left=0,
                    turn_right=0,
                    fire=0,
                    aim_left=0,
                    aim_right=0,
                    axis_aim_x=0,
                    axis_aim_y=0,
                    axis_move_x=0,
                    axis_move_y=0,
                ),
            ],
            alternate_single=CaptureSnapshotInputBindingAlternateSingle(
                move_forward=0,
                move_backward=0,
                turn_left=0,
                turn_right=0,
                fire=0,
            ),
        ),
    )


def _empty_samples() -> CaptureSamples:
    return CaptureSamples(creatures=[], projectiles=[], secondary_projectiles=[], bonuses=[])


def _empty_debug() -> CaptureCheckpointDebug:
    return CaptureCheckpointDebug(
        sampling_phase="",
        timing=CaptureTimingDiagnostics(
            gameplay_frame=0,
            gameplay_frame_delta_prev_tick=None,
            elapsed_ms_before=0,
            elapsed_ms_after=0,
            elapsed_delta_in_tick_ms=0,
            elapsed_delta_prev_tick_ms=None,
            frame_dt_before=None,
            frame_dt_after=None,
            frame_dt_ms_before_i32=None,
            frame_dt_ms_after_i32=None,
            frame_dt_ms_before_f32=None,
            frame_dt_ms_after_f32=None,
            frame_dt_source_before="none",
            frame_dt_source_after="none",
            mode_tick_event_count=0,
            mode_tick_sample_count=0,
            mode_tick_mode_fn_head=[],
            mode_tick_present=False,
        ),
        spawn=CaptureSpawnDiagnostics(
            before_creature_count=0,
            after_creature_count=0,
            creature_count_delta=0,
            event_count_template=0,
            event_count_low_level=0,
            event_count_creature_damage=0,
            event_count_projectile_find_query=0,
            event_count_projectile_find_hit=0,
            event_count_projectile_find_query_miss=0,
            event_count_projectile_find_query_owner_collision=0,
            event_count_death=0,
            top_template_callers=[],
            top_low_level_callers=[],
            top_low_level_sources=[],
            top_creature_damage_callers=[],
            top_projectile_find_query_callers=[],
            top_projectile_find_hit_callers=[],
            top_death_callers=[],
            event_count_blood_splatter=0,
            blood_splatter_rng_draws=0,
            blood_splatter_projectile_update_calls=0,
            top_blood_splatter_callers=[],
            top_blood_splatter_rng_draw_callers=[],
            event_count_bonus_spawn=0,
            top_bonus_spawn_callers=[],
            mode_samples=[],
        ),
        rng=CaptureRngDiagnostics(
            seq_first=None,
            seq_last=None,
            seed_epoch_enter=None,
            seed_epoch_last=None,
            outside_before_calls=0,
            outside_before_dropped=0,
            outside_before_head=[],
            mirror_mismatch_total_enter=0,
            mirror_mismatch_total_leave=0,
            mirror_unknown_total_enter=0,
            mirror_unknown_total_leave=0,
            roll_log_emitted_total=0,
            roll_log_dropped_total=0,
        ),
        perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
        creature_lifecycle=None,
        player_fire=CapturePlayerFireDiagnostics(
            event_count_player_fire=0,
            top_direct_events_by_player=[],
            top_fallback_events_by_player=[],
            top_player_projectile_spawns_by_player=[],
        ),
        before_players=[],
        before_status=CaptureCheckpointDebugStatus(quest_unlock_index=0, quest_unlock_index_full=0),
    )


def _empty_event_counts() -> CaptureEventCounts:
    return CaptureEventCounts(
        state_transition=0,
        player_fire=0,
        weapon_assign=0,
        bonus_apply=0,
        bonus_spawn=0,
        projectile_spawn=0,
        projectile_find_query=0,
        projectile_find_hit=0,
        secondary_projectile_spawn=0,
        player_damage=0,
        creature_damage=0,
        creature_spawn=0,
        creature_spawn_low=0,
        creature_death=0,
        creature_lifecycle=0,
        creature_update_micro=0,
        perk_apply=0,
        sfx=0,
        perk_delta=0,
        quest_timeline_delta=0,
        mode_tick=0,
        input_primary_edge=0,
        input_primary_down=0,
        input_any_key=0,
    )


def _empty_input_queries() -> CaptureInputQueries:
    return CaptureInputQueries(
        stats=CaptureInputQueryStats(
            primary_edge=CaptureInputQueryCounter(0, 0),
            primary_down=CaptureInputQueryCounter(0, 0),
            any_key=CaptureInputQueryCounter(0, 0),
        ),
        query_hash="",
    )


def _empty_rng_summary() -> CaptureRngSummary:
    return CaptureRngSummary(
        calls=0,
        last_value=None,
        hash="",
        head=[],
        callers=[],
        caller_overflow=0,
        seq_first=None,
        seq_last=None,
        seed_epoch_enter=None,
        seed_epoch_last=None,
        outside_before_calls=0,
        outside_before_dropped=0,
        outside_before_head=[],
        mirror_mismatch_total=0,
        mirror_unknown_total=0,
    )


def _empty_diagnostics() -> CaptureDiagnostics:
    debug = _empty_debug()
    return CaptureDiagnostics(
        sampling_phase="",
        timing=debug.timing,
        spawn=debug.spawn,
        rng=debug.rng,
        perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
        creature_lifecycle=None,
        player_fire=debug.player_fire,
    )


def _empty_config() -> CaptureConfig:
    return CaptureConfig(
        out_path="",
        split_quest_files=True,
        quest_out_dir="",
        quest_out_prefix="",
        capture_profile="",
        config_env_overrides=[],
        log_mode="truncate",
        console_all_events=False,
        console_events=[],
        include_caller=True,
        include_backtrace=False,
        emit_ticks_outside_tracked_states=False,
        tracked_states=[],
        player_count_override=0,
        focus_tick=-1,
        focus_radius=0,
        heartbeat_ms=1000,
        max_head_per_kind=-1,
        max_events_per_tick=-1,
        max_rng_head_per_tick=-1,
        max_rng_caller_kinds=-1,
        enable_rng_state_mirror=True,
        max_creature_delta_ids=32,
        creature_sample_limit=-1,
        projectile_sample_limit=-1,
        secondary_projectile_sample_limit=-1,
        bonus_sample_limit=-1,
        enable_input_hooks=True,
        enable_rng_hooks=True,
        enable_sfx_hooks=True,
        enable_damage_hooks=True,
        enable_effect_hooks=True,
        creature_damage_projectile_only=True,
        enable_spawn_hooks=True,
        enable_creature_spawn_hook=True,
        enable_creature_death_hook=True,
        enable_bonus_spawn_hook=True,
        enable_creature_lifecycle_digest=True,
        enable_creature_micro_hooks=True,
        creature_micro_slots=[],
        creature_micro_tick_start=-1,
        creature_micro_tick_end=-1,
        creature_micro_max_head_per_tick=256,
    )


def _empty_config_dict() -> dict[str, object]:
    return cast(dict[str, object], msgspec.to_builtins(_empty_config()))


def _empty_session_fingerprint() -> SessionFingerprint:
    return SessionFingerprint(session_id="", module_hash=None, ptrs_hash=None)


def _empty_process_info() -> ProcessInfo:
    return ProcessInfo(pid=0, platform="", arch="", frida_version="", runtime="")


def _empty_module_info() -> ModuleInfo:
    return ModuleInfo(base="", size=0, path="")


def _rng_head_entry(**kwargs: object) -> dict[str, object]:
    row = {
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


def _sample_creature_dict(**kwargs: object) -> dict[str, object]:
    row = {
        "index": 0,
        "active": 1,
        "state_flag": 0,
        "collision_flag": 0,
        "hitbox_size": 16.0,
        "pos": {"x": 100.0, "y": 100.0},
        "hp": 20.0,
        "type_id": 7,
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


from crimson.game_modes import GameMode
from crimson.original import divergence_report, focus_trace
from crimson.original.diagnostics_cache import (
    CaptureSession,
    SessionRegistry,
    _FocusRuntime,
    build_focus_key,
    cache_enabled,
)
from crimson.original.focus_trace import (
    FocusTraceReport,
    RngAlignmentSummary,
)
from crimson.original.schema import CAPTURE_FORMAT_VERSION, CaptureFile, CaptureSamples, CaptureSnapshot, CaptureTick
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def _checkpoint_tick(
    tick: int, *, level: int, weapon_id: int, experience: int, perk_pairs: list[list[int]],
) -> dict[str, object]:
    debug = cast(dict[str, object], msgspec.to_builtins(_empty_debug()))
    return {
        "tick_index": int(tick),
        "state_hash": f"s{tick}",
        "command_hash": f"c{tick}",
        "rng_state": 0,
        "elapsed_ms": int(tick) * 16,
        "score_xp": int(experience),
        "kills": 0,
        "creature_count": 1,
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
            "rand_head": [_rng_head_entry(state_before_u32=0)],
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
        "debug": debug,
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
    diagnostics = cast(dict[str, object], msgspec.to_builtins(_empty_diagnostics()))
    before_snapshot = cast(dict[str, object], msgspec.to_builtins(_empty_snapshot()))
    after_snapshot = cast(dict[str, object], msgspec.to_builtins(_empty_snapshot()))
    return {
        "tick_index": int(tick),
        "gameplay_frame": int(tick) + 1,
        "mode_hint": "survival_update",
        "game_mode_id": 1,
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
        "samples": {
            "creatures": [_sample_creature_dict()],
            "projectiles": [],
            "secondary_projectiles": [],
            "bonuses": [],
        },
        "input_queries": {
            "stats": {
                "primary_edge": {"calls": 0, "true_calls": 0},
                "primary_down": {"calls": 0, "true_calls": 0},
                "any_key": {"calls": 0, "true_calls": 0},
            },
            "query_hash": "",
        },
        "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
        "perk_apply_in_tick": [],
        "rng": _rng_summary_dict(head=[_rng_head_entry(state_before_u32=0)]),
        "diagnostics": diagnostics,
        "input_player_keys": [_input_player_keys(player_index=0)],
        "input_approx": [_input_approx(player_index=0, aim_x=0.0, aim_y=0.0)],
        "before": before_snapshot,
        "after": after_snapshot,
        "frame_dt_ms": None,
        "frame_dt_ms_i32": None,
        "creature_lifecycle": None,
    }


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    return {
        "capture_format_version": int(CAPTURE_FORMAT_VERSION),
        "script": "gameplay_diff_capture",
        "session_id": "s",
        "out_path": "capture.json",
        "config": _empty_config_dict(),
        "session_fingerprint": {"session_id": "s", "module_hash": "a", "ptrs_hash": "b"},
        "process": {"pid": 1, "platform": "windows", "arch": "x86", "frida_version": "16", "runtime": "v8"},
        "exe": {"base": "0x400000", "size": 1, "path": "crimsonland.exe"},
        "grim": None,
        "pointers_resolved": {},
        "ticks": ticks,
    }


def _write_capture_stream(path: Path, capture: dict[str, object]) -> None:
    meta = {key: value for key, value in capture.items() if key != "ticks"}
    meta["ticks"] = []
    ticks_obj = capture.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _build_minimal_focus_report(tick: int = 0) -> FocusTraceReport:
    return FocusTraceReport(
        tick=int(tick),
        hits=0,
        deaths=0,
        sfx=0,
        rand_calls_total=0,
        rng_callsites_top=[],
        rng_callsites_head=[],
        collision_hits=[],
        collision_near_misses=[],
        pre_projectiles=[],
        post_projectiles=[],
        capture_projectiles=[],
        capture_creatures=[],
        creature_diffs_top=[],
        creature_capture_only=[],
        creature_rewrite_only=[],
        projectile_diffs_top=[],
        projectile_capture_only=[],
        projectile_rewrite_only=[],
        decal_hook_rows=[],
        rng_alignment=RngAlignmentSummary(
            capture_calls=0,
            capture_head_len=0,
            rewrite_calls=0,
            value_prefix_match=0,
            first_value_mismatch_index=None,
            first_value_mismatch_capture=None,
            first_value_mismatch_rewrite=None,
            missing_native_tail_count=0,
            missing_native_tail_callers_top=[],
            missing_native_tail_inferred_callsites_top=[],
            missing_native_tail_preview=[],
            capture_caller_counts=[],
            rewrite_callsite_counts=[],
            caller_static_to_rewrite_callsite=[],
        ),
        native_caller_gaps_top=[],
        fire_bullets_loop_parity=None,
    )


def _write_fixture_capture(path: Path) -> None:
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
                    {
                        "type": "state_transition",
                        "data": {
                            "target_state": 6,
                            "before": {"prev": None, "id": 9, "pending": None},
                            "after": {"prev": None, "id": 6, "pending": None},
                            "caller": None,
                            "backtrace": None,
                        },
                    },
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
    _write_capture_stream(path, capture)


def test_cache_enabled_env(monkeypatch) -> None:
    monkeypatch.delenv("CRIMSON_ORIGINAL_CACHE", raising=False)
    assert cache_enabled() is True

    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE", "0")
    assert cache_enabled() is False

    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE", "false")
    assert cache_enabled() is False

    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE", "1")
    assert cache_enabled() is True


def test_strip_no_cache_flag() -> None:
    from crimson import cli

    args, no_cache = cli._strip_no_cache_flag(
        [
            "capture.json",
            "--window",
            "24",
            "--no-cache",
            "--json-out",
            "out.json",
        ],
    )

    assert no_cache is True
    assert args == ["capture.json", "--window", "24", "--json-out", "out.json"]


def test_capture_session_builds_sidecars_and_indexes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))

    capture_path = tmp_path / "capture.json"
    _write_fixture_capture(capture_path)

    session = CaptureSession(capture_path)

    cache_capture_blobs = list((tmp_path / "cache").glob("*/capture.msgpack.gz"))
    cache_meta_files = list((tmp_path / "cache").glob("*/meta.json"))
    assert cache_capture_blobs
    assert cache_meta_files
    meta_payload = json.loads(cache_meta_files[0].read_text(encoding="utf-8"))
    assert "schema_version" in meta_payload
    assert "v" not in meta_payload

    sample_counts = session.get_sample_creature_counts()
    assert sample_counts[0] == 1
    assert sample_counts[1] == 1

    raw_debug = session.get_raw_debug_by_tick()
    assert len(raw_debug[0].samples.creatures) == 1

    run_summary = session.get_run_summary_events()
    assert any(item.kind == "weapon_assign" for item in run_summary)
    assert any(item.kind == "level_up" for item in run_summary)


def test_session_registry_reloads_when_capture_changes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))

    capture_path = tmp_path / "capture.json"
    _write_fixture_capture(capture_path)

    registry = SessionRegistry()
    first = registry.get_session(capture_path)

    st = capture_path.stat()
    os.utime(capture_path, ns=(int(st.st_atime_ns), int(st.st_mtime_ns) + 1_000_000))

    second = registry.get_session(capture_path)
    assert first is not second


def test_focus_report_cache_short_circuits_runtime(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))

    capture_path = tmp_path / "capture.json"
    _write_fixture_capture(capture_path)
    session = CaptureSession(capture_path)

    key = build_focus_key(inter_tick_rand_draws=1, aim_scheme_overrides_by_player={})
    report = _build_minimal_focus_report(tick=1)

    class _StubRuntime:
        def __init__(self, value: FocusTraceReport) -> None:
            self.value = value
            self.calls: list[tuple[int, float]] = []

        def trace_tick(self, *, tick: int, near_miss_threshold: float) -> FocusTraceReport:
            self.calls.append((int(tick), float(near_miss_threshold)))
            return self.value

    stub = _StubRuntime(report)
    session._focus_runtime_by_key[key] = stub  # pyright: ignore[reportAttributeAccessIssue]

    a = session.get_focus_report(key=key, tick=1, near_miss_threshold=0.35)
    b = session.get_focus_report(key=key, tick=1, near_miss_threshold=0.35)

    assert a is report
    assert b is report
    assert stub.calls == [(1, 0.35)]


def test_focus_runtime_traces_quest_tick() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.QUESTS),
        seed=101,
        quest_level="1.1",
        tick_rate=60,
        player_count=1,
    )
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    replay = rec.finish()

    capture = CaptureFile(
        script="gameplay_diff_capture",
        session_id="quest-focus-runtime",
        out_path="capture.json",
        capture_format_version=5,
        config=_empty_config(),
        session_fingerprint=_empty_session_fingerprint(),
        process=_empty_process_info(),
        exe=_empty_module_info(),
        grim=None,
        pointers_resolved={},
        ticks=[
            CaptureTick(
                tick_index=0,
                gameplay_frame=1,
                before=_empty_snapshot(),
                after=_empty_snapshot(),
                samples=_empty_samples(),
                mode_hint="quest_mode_update",
                game_mode_id=int(GameMode.QUESTS),
                quest_stage_major=1,
                quest_stage_minor=1,
                focus_tick=False,
                state_id_enter=None,
                state_id_leave=None,
                state_pending_enter=None,
                state_pending_leave=None,
                ts_enter_ms=0,
                ts_leave_ms=0,
                duration_ms=0,
                checkpoint=CaptureCheckpoint(
                    tick_index=0,
                    state_hash="",
                    command_hash="",
                    rng_state=0,
                    elapsed_ms=0,
                    score_xp=0,
                    kills=0,
                    creature_count=0,
                    perk_pending=0,
                    players=[],
                    status=CaptureStatusSnapshot(
                        quest_unlock_index=-1, quest_unlock_index_full=-1, weapon_usage_counts=[],
                    ),
                    bonus_timers={},
                    rng_marks=CaptureRngMarks(
                        rand_calls=0,
                        rand_hash="",
                        rand_last=None,
                        rand_head=[],
                        rand_callers=[],
                        rand_caller_overflow=0,
                        rand_seq_first=None,
                        rand_seq_last=None,
                        rand_seed_epoch_enter=None,
                        rand_seed_epoch_last=None,
                        rand_outside_before_calls=0,
                        rand_outside_before_dropped=0,
                        rand_outside_before_head=[],
                        rand_mirror_mismatch_total=0,
                        rand_mirror_unknown_total=0,
                    ),
                    deaths=[],
                    perk=CapturePerkSnapshot(
                        pending_count=0, choices_dirty=False, choices=[], player_nonzero_counts=[],
                    ),
                    events=CaptureEventSummary(
                        hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[], rng_call_count=0, input_true_count=0,
                    ),
                    debug=_empty_debug(),
                ),
                event_counts=_empty_event_counts(),
                event_overflow=False,
                event_heads=[],
                phase_markers=[],
                input_queries=_empty_input_queries(),
                input_player_keys=[],
                perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
                perk_apply_in_tick=[],
                rng=_empty_rng_summary(),
                diagnostics=_empty_diagnostics(),
                input_approx=[],
                frame_dt_ms=None,
                frame_dt_ms_i32=None,
                creature_lifecycle=None,
            ),
        ],
    )

    runtime = _FocusRuntime(
        capture=capture,
        replay=replay,
        inter_tick_rand_draws=0,
    )
    report = runtime.trace_tick(tick=0, near_miss_threshold=0.35)

    assert int(report.tick) == 0


def test_divergence_and_focus_main_accept_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))

    capture_path = tmp_path / "capture.json"
    _write_fixture_capture(capture_path)
    session = CaptureSession(capture_path)

    divergence_code = divergence_report.main(
        [
            str(capture_path),
            "--window",
            "0",
            "--lead-lookback",
            "0",
            "--max-ticks",
            "1",
        ],
        session=session,
    )
    assert divergence_code in {0, 1}

    focus_code = focus_trace.main(
        [
            str(capture_path),
            "--tick",
            "0",
            "--near-miss-threshold",
            "0.35",
        ],
        session=session,
    )
    assert focus_code == 0
