from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
import zstandard as zstd

from crimson.dbg.canonical_channels import entity_uid
from crimson.dbg.frida_finalize import (
    FRIDA_CAPTURE_FORMAT_VERSION,
    FRIDA_RUNTIME_VERSION,
    FridaFinalizeError,
    finalize_frida_jsonl_to_traces,
    load_frida_evidence_file,
)
from crimson.dbg.trace import load_trace
from crimson.persistence.save_status import QUEST_PLAY_COUNT, UNKNOWN_TAIL_SIZE, WEAPON_USAGE_COUNT
from crimson.replay.codec import load_replay_file
from crimson.replay.types import quantize_f32
from crimson.sim.input_providers import (
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    PerkPickCommand,
)

CAPTURE_FORMAT_VERSION = FRIDA_CAPTURE_FORMAT_VERSION


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row))
            handle.write("\n")
    return path


def _session_fingerprint_stub() -> dict[str, object]:
    return {
        "session_id": "session-test",
        "module_hash": "cafebabe",
        "ptrs_hash": "deadbeef",
    }


def _session_config_stub() -> dict[str, object]:
    return {
        "out_path": "C:\\share\\frida\\gameplay_diff_capture.jsonl",
        "out_path_source": "host",
        "capture_profile": "exhaustive_default",
        "config_env_overrides": [],
        "console_all_events": False,
        "console_events": ["start", "ready", "capture_shutdown", "error", "hook_error", "hook_skip", "tickless_event"],
        "include_caller": True,
        "include_backtrace": False,
        "emit_ticks_outside_tracked_states": False,
        "tracked_states": [6, 7, 8, 9, 10, 12, 14, 18],
        "player_count_override": 0,
        "focus_tick": -1,
        "focus_radius": 0,
        "heartbeat_ms": 1000,
        "max_head_per_kind": -1,
        "max_events_per_tick": -1,
        "max_rng_head_per_tick": -1,
        "max_rng_caller_kinds": -1,
        "enable_rng_roll_log": True,
        "max_rng_roll_log_events": -1,
        "max_rng_outside_tick_head": -1,
        "enable_rng_state_mirror": True,
        "max_creature_delta_ids": -1,
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
        "creature_micro_max_head_per_tick": -1,
    }


def _status_stub() -> dict[str, object]:
    weapon_usage_counts = [0] * int(WEAPON_USAGE_COUNT)
    weapon_usage_counts[1] = 17
    quest_play_counts = [0] * int(QUEST_PLAY_COUNT)
    quest_play_counts[3] = 9
    return {
        "quest_unlock_index": 7,
        "quest_unlock_index_full": 11,
        "weapon_usage_counts": weapon_usage_counts,
        "quest_play_counts": quest_play_counts,
        "mode_play_survival": 2,
        "mode_play_rush": 3,
        "mode_play_typo": 4,
        "mode_play_other": 5,
        "game_sequence_id": 1234,
        "unknown_tail": list(range(int(UNKNOWN_TAIL_SIZE))),
    }


def _run_settings_stub(
    *,
    tick_rate: int = 60,
    quest_fail_retry_count: int = 0,
    hardcore: bool = False,
    detail_preset: int = 5,
    violence_disabled: int = 0,
    world_size: float = 1024.0,
    status: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "tick_rate": int(tick_rate),
        "quest_fail_retry_count": int(quest_fail_retry_count),
        "hardcore": bool(hardcore),
        "detail_preset": int(detail_preset),
        "violence_disabled": int(violence_disabled),
        "world_size": float(world_size),
        "status": _status_stub() if status is None else status,
    }


def _session_start_row(*, capture_format_version: int = CAPTURE_FORMAT_VERSION) -> dict[str, object]:
    return {
        "event": "session_start",
        "capture_format_version": int(capture_format_version),
        "session_id": "session-test",
        "out_path": "C:\\share\\frida\\gameplay_diff_capture.jsonl",
        "platform": "windows",
        "arch": "x86",
        "frida_version": FRIDA_RUNTIME_VERSION,
        "script_version": str(CAPTURE_FORMAT_VERSION),
        "config": _session_config_stub(),
        "session_fingerprint": _session_fingerprint_stub(),
    }


def _checkpoint_player_stub(*, index: int = 0) -> dict[str, object]:
    return {
        "pos": {
            "x": float(index),
            "y": float(index) + 1.0,
        },
        "health": 100.0,
        "weapon_id": 1,
        "ammo": 12.0,
        "experience": 0,
        "level": 1,
    }


def _sim_player_stub(*, index: int = 0) -> dict[str, object]:
    return {
        "index": int(index),
        "pos": {
            "x": float(index),
            "y": float(index) + 1.0,
        },
        "heading": 0.0,
        "move_speed": 0.0,
        "move_phase": 0.0,
        "aim": {"x": 0.0, "y": 0.0},
        "aim_heading": 0.0,
        "health": 100.0,
        "weapon": {
            "weapon_id": 1,
            "ammo": 12.0,
            "clip_size": 12,
            "reload_active": False,
            "reload_timer": 0.0,
            "reload_timer_max": 0.0,
            "shot_cooldown": 0.0,
        },
        "experience": 0,
        "level": 1,
    }


def _timing_sample_stub(
    *,
    tick_index: int,
    gameplay_frame: int | None = None,
    phase: str = "gpur_enter",
    write_kind: str = "snapshot",
    dt_ms_i32: int = 16,
    dt: float | None = None,
) -> dict[str, object]:
    frame_dt = quantize_f32(float(dt_ms_i32) / 1000.0 if dt is None else float(dt))
    return {
        "tick_index": int(tick_index),
        "gameplay_frame": None if gameplay_frame is None else int(gameplay_frame),
        "phase": str(phase),
        "write_kind": str(write_kind),
        "frame_dt_f32": frame_dt,
        "frame_dt_ms_i32": int(dt_ms_i32),
        "frame_dt_ms_f32": float(dt_ms_i32),
        "time_scale_active_entry": None,
        "time_scale_active_current": None,
        "time_scale_factor": None,
        "bonus_reflex_boost_timer": None,
        "mode_fn": "gameplay_update_and_render",
        "player_index": None,
    }


def _checkpoint_stub(*, tick_index: int, elapsed_ms: int, player_count: int = 1) -> dict[str, object]:
    return {
        "tick_index": int(tick_index),
        "rng_state": 0,
        "elapsed_ms": int(elapsed_ms),
        "score_xp": 0,
        "kills": 0,
        "creature_count": 0,
        "perk_pending": 0,
        "players": [_checkpoint_player_stub(index=i) for i in range(max(0, int(player_count)))],
        "bonus_timers": {},
        "deaths": [],
        "perk": {
            "pending_count": 0,
            "choices_dirty": True,
            "choices": [0] * 7,
            "player_nonzero_counts": [[] for _ in range(max(0, int(player_count)))],
        },
        "events": {
            "hit_count": 0,
            "pickup_count": 0,
            "sfx_count": 0,
            "sfx_head": [],
            "hit_head": [],
        },
        "tutorial": None,
        "typo": None,
    }


def _sim_state_stub(
    *,
    mode_id: int,
    player_count: int = 1,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
) -> dict[str, object]:
    return {
        "gameplay": {
            "mode_id": int(mode_id),
            "quest_stage_major": int(quest_stage_major),
            "quest_stage_minor": int(quest_stage_minor),
            "perk_pending_count": 0,
            "perk_choices_dirty": True,
            "bonus_timers": {
                "weapon_power_up_ms": 0,
                "reflex_boost_ms": 0,
                "energizer_ms": 0,
                "double_experience_ms": 0,
                "freeze_ms": 0,
            },
        },
        "players": [_sim_player_stub(index=i) for i in range(max(0, int(player_count)))],
    }


def _entity_samples_stub(
    *,
    creatures: list[dict[str, object]] | None = None,
    projectiles: list[dict[str, object]] | None = None,
    secondary_projectiles: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "creatures": list(creatures or []),
        "projectiles": list(projectiles or []),
        "secondary_projectiles": list(secondary_projectiles or []),
        "bonuses": [],
    }


def _rng_stream_row_stub(
    *,
    tick_call_index: int = 1,
    value_15: int = 28052,
    state_before_u32: int = 2427270273,
    state_after_u32: int = 3985917248,
    caller: int | None = 0x00430B88,
) -> dict[str, object]:
    return {
        "tick_call_index": int(tick_call_index),
        "value_15": int(value_15),
        "state_before_u32": int(state_before_u32),
        "state_after_u32": int(state_after_u32),
        "caller": caller,
    }


def _creature_sample(
    *,
    uid: int,
    generation: int,
    index: int,
    active: bool = True,
) -> dict[str, object]:
    return {
        "uid": int(uid),
        "generation": int(generation),
        "pool_kind": "creature",
        "index": int(index),
        "active": bool(active),
        "type_id": 0,
        "hp": 1.0,
        "pos": {"x": 0.0, "y": 0.0},
        "flags": 0,
        "ai_mode": 0,
        "link_index": -1,
        "force_target": 1,
        "target": {"x": 5.0, "y": 6.0},
        "target_player": 0,
        "target_offset": {"x": 0.25, "y": -0.5},
        "heading": 0.0,
        "target_heading": 0.0,
        "collision_timer": 0.125,
        "attack_cooldown": 0.75,
        "orbit_angle": 0.0,
        "orbit_radius": 0.0,
        "lifecycle_stage": 0.0,
        "vel": {"x": 0.0, "y": 0.0},
        "move_speed": 0.0,
    }


def _projectile_sample(*, uid: int, generation: int, index: int, owner_id: int) -> dict[str, object]:
    return {
        "uid": int(uid),
        "generation": int(generation),
        "pool_kind": "projectile",
        "index": int(index),
        "active": True,
        "type_id": 4,
        "angle": 0.25,
        "pos": {"x": 1.0, "y": 2.0},
        "vel": {"x": 3.0, "y": 4.0},
        "life_timer": 0.5,
        "speed_scale": 1.0,
        "damage_pool": 8.0,
        "hit_radius": 1.5,
        "travel_budget": 9.0,
        "owner_id": int(owner_id),
    }


def _channels_stub(
    *,
    tick_index: int,
    elapsed_ms: int,
    mode_id: int,
    dt_ms_i32: int = 16,
    dt: float | None = None,
    player_count: int = 1,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
    creatures: list[dict[str, object]] | None = None,
    projectiles: list[dict[str, object]] | None = None,
    secondary_projectiles: list[dict[str, object]] | None = None,
    checkpoint_overrides: dict[str, object] | None = None,
    prelude: list[dict[str, object]] | None = None,
    postlude: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    checkpoint = _checkpoint_stub(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        player_count=int(player_count),
    )
    if checkpoint_overrides:
        checkpoint.update(dict(checkpoint_overrides))
    return {
        "replay_step": {
            "dt": quantize_f32(float(dt_ms_i32) / 1000.0 if dt is None else float(dt)),
            "inputs": _replay_inputs_stub(player_count=player_count),
            "prelude": list(prelude or []),
            "postlude": list(postlude or []),
            "commands": [],
        },
        "checkpoint": checkpoint,
        "sim_state": _sim_state_stub(
            mode_id=int(mode_id),
            player_count=int(player_count),
            quest_stage_major=int(quest_stage_major),
            quest_stage_minor=int(quest_stage_minor),
        ),
        "entity_samples": _entity_samples_stub(
            creatures=creatures,
            projectiles=projectiles,
            secondary_projectiles=secondary_projectiles,
        ),
        "rng_stream": [],
        "timing_samples": [_timing_sample_stub(tick_index=int(tick_index), dt_ms_i32=int(dt_ms_i32), dt=dt)],
    }


def _replay_inputs_stub(*, player_count: int = 1) -> list[dict[str, float | int]]:
    return [
        {"move_x": 0.0, "move_y": 0.0, "aim_x": 0.0, "aim_y": 0.0, "flags": 0} for _ in range(max(0, int(player_count)))
    ]


def _run_start_row(
    *,
    run_id: int,
    mode_id: int,
    seed: int = 0,
    player_count: int = 1,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
    rng_state_before_bootstrap: int | None = None,
    rng_state_after_bootstrap: int | None = None,
    rng_bootstrap_calls: int = 0,
    include_rng_state_before_bootstrap: bool = True,
    global_tick_index: int = 0,
    pool_residue: list[dict[str, object]] | None = None,
    settings: dict[str, object] | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "event": "run_start",
        "run_id": int(run_id),
        "reason": "run_start",
        "mode_id": int(mode_id),
        "player_count": int(player_count),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
        "global_tick_index": int(global_tick_index),
        "pool_residue": [_pool_residue_slot_stub(0)] if pool_residue is None else list(pool_residue),
        "settings": _run_settings_stub() if settings is None else settings,
    }
    if include_rng_state_before_bootstrap:
        before = int(seed if rng_state_before_bootstrap is None else rng_state_before_bootstrap)
        row["rng_state_before_bootstrap"] = before
        row["rng_state_after_bootstrap"] = int(
            before if rng_state_after_bootstrap is None else rng_state_after_bootstrap,
        )
        row["rng_bootstrap_calls"] = int(rng_bootstrap_calls)
    return row


def _tick_evidence_stub(
    *,
    raw_hit_count: int = 0,
    owner_collision_count: int = 0,
    pickup_count: int = 0,
    raw_sfx_count: int = 0,
    deaths: list[dict[str, object]] | None = None,
    sfx_head: list[str] | None = None,
    hit_head: list[dict[str, object]] | None = None,
    time_played_ms_raw: int = 0,
    quest_spawn_timeline_raw: int = 0,
    summed_replay_clock_ms: int = 0,
    canonical_elapsed_ms: int = 0,
) -> dict[str, object]:
    return {
        "event_counts": {
            "projectile_find_hit": int(raw_hit_count),
            "projectile_find_owner_collision": int(owner_collision_count),
            "bonus_apply": int(pickup_count),
            "sfx": int(raw_sfx_count),
        },
        "event_overflow": False,
        "event_heads": {},
        "diagnostics": {},
        "input_queries": {},
        "input_player_keys": [],
        "input_approx": [],
        "before": {},
        "after": {},
        "samples": {},
        "frame_dt_ms": 16,
        "frame_dt_ms_i32": 16,
        "checkpoint_private": {
            "elapsed_ms": int(time_played_ms_raw),
            "deaths": list(deaths or []),
            "events": {
                "hit_count": int(raw_hit_count),
                "pickup_count": int(pickup_count),
                "sfx_count": int(raw_sfx_count),
                "sfx_head": list(sfx_head or []),
                "hit_head": list(hit_head or []),
            },
        },
        "clocks": {
            "time_played_ms_raw": int(time_played_ms_raw),
            "quest_spawn_timeline_raw": int(quest_spawn_timeline_raw),
            "summed_replay_clock_ms": int(summed_replay_clock_ms),
            "canonical_elapsed_ms": int(canonical_elapsed_ms),
        },
    }


def _rng_accounting_stub(*, rng_calls: int = 0) -> dict[str, object]:
    return {
        "rng_calls": int(rng_calls),
        "rng_outside_before": _rng_outside_bag_stub(),
        "rng_state_enter_u32": 0,
        "rng_state_leave_u32": 0,
        "evidence": _tick_evidence_stub(),
    }


def _tick_identity_stub(*, tick_index: int = 0, global_tick_index: int | None = None) -> dict[str, object]:
    return {
        "tick_index": int(tick_index),
        "global_tick_index": int(tick_index if global_tick_index is None else global_tick_index),
        "quest_stage_major": 0,
        "quest_stage_minor": 0,
    }


def _rng_outside_bag_stub(
    *,
    calls: int = 0,
    dropped: int = 0,
    caller_counts: dict[str, int] | None = None,
    head: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "calls": int(calls),
        "dropped": int(dropped),
        "caller_counts": {} if caller_counts is None else caller_counts,
        "head": [] if head is None else head,
    }


def _tick_row(
    *,
    run_id: int,
    tick_index: int,
    elapsed_ms: int,
    dt_ms_i32: int,
    dt: float,
    mode_id: int,
    player_count: int = 1,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
    channels: dict[str, object] | None = None,
    rng_calls: int | None = None,
    rng_outside_before: dict[str, object] | None = None,
    rng_state_enter_u32: int | None = 0,
    rng_state_leave_u32: int | None = 0,
    include_rng_accounting: bool = True,
    global_tick_index: int | None = None,
) -> dict[str, object]:
    resolved_channels = (
        _channels_stub(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            mode_id=int(mode_id),
            dt_ms_i32=int(dt_ms_i32),
            dt=float(dt),
            player_count=int(player_count),
            quest_stage_major=int(quest_stage_major),
            quest_stage_minor=int(quest_stage_minor),
        )
        if channels is None
        else channels
    )
    row: dict[str, object] = {
        "event": "tick",
        "run_id": int(run_id),
        "tick_index": int(tick_index),
        "global_tick_index": int(tick_index if global_tick_index is None else global_tick_index),
        "elapsed_ms": int(elapsed_ms),
        "dt_ms_i32": int(dt_ms_i32),
        "mode_id": int(mode_id),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
        "channels": resolved_channels,
        "evidence": _tick_evidence_stub(
            time_played_ms_raw=int(elapsed_ms),
            summed_replay_clock_ms=int(elapsed_ms),
            canonical_elapsed_ms=int(elapsed_ms),
        ),
    }
    if include_rng_accounting:
        stream = cast(list[object], resolved_channels.get("rng_stream") or [])
        row["rng_calls"] = len(stream) if rng_calls is None else int(rng_calls)
        row["rng_outside_before"] = _rng_outside_bag_stub() if rng_outside_before is None else rng_outside_before
        row["rng_state_enter_u32"] = rng_state_enter_u32
        row["rng_state_leave_u32"] = rng_state_leave_u32
    return row


def _run_end_row(
    *,
    run_id: int,
    mode_id: int = -1,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
    ticks_written: int = 0,
    reason: str = "run_end",
    trailing_prelude: list[dict[str, object]] | None = None,
    rng_outside_tail: dict[str, object] | None = None,
    include_rng_outside_tail: bool = True,
    global_tick_index: int | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "event": "run_end",
        "run_id": int(run_id),
        "reason": str(reason),
        "mode_id": int(mode_id),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
        "ticks_written": int(ticks_written),
        "global_tick_index": int(max(0, int(ticks_written) - 1) if global_tick_index is None else global_tick_index),
        "trailing_prelude": [] if trailing_prelude is None else trailing_prelude,
    }
    if include_rng_outside_tail:
        row["rng_outside_tail"] = _rng_outside_bag_stub() if rng_outside_tail is None else rng_outside_tail
    return row


def test_finalize_frida_jsonl_to_traces_writes_trace_and_replay_and_deletes_raw(tmp_path: Path) -> None:
    frame_state_1 = (777 * 214013 + 2531011) & 0xFFFFFFFF
    frame_state_2 = (frame_state_1 * 214013 + 2531011) & 0xFFFFFFFF
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {
                **_session_start_row(),
            },
            _run_start_row(
                run_id=1,
                mode_id=1,
                seed=777,
                player_count=1,
                global_tick_index=100,
                settings=_run_settings_stub(
                    quest_fail_retry_count=3,
                    hardcore=True,
                    detail_preset=2,
                    violence_disabled=1,
                    world_size=2048.0,
                ),
            ),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "rng_outside_before": _rng_outside_bag_stub(
                    calls=2,
                    caller_counts={"0x0040cac7": 2},
                    head=[
                        {
                            "state_before_u32": 777,
                            "state_after_u32": frame_state_1,
                            "value_15": (frame_state_1 >> 16) & 0x7FFF,
                            "caller_static": "0x0040cac7",
                            "replay_operation_index": 0,
                        },
                        {
                            "state_before_u32": frame_state_1,
                            "state_after_u32": frame_state_2,
                            "value_15": (frame_state_2 >> 16) & 0x7FFF,
                            "caller_static": "0x0040cac7",
                            "replay_operation_index": 0,
                        },
                    ],
                ),
                "rng_state_enter_u32": frame_state_2,
                "rng_state_leave_u32": frame_state_2,
                **_tick_identity_stub(tick_index=0, global_tick_index=100),
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=0,
                    mode_id=1,
                    creatures=[
                        _creature_sample(
                            uid=entity_uid(pool_kind="creature", index=5, generation=1),
                            generation=1,
                            index=5,
                            active=True,
                        ),
                    ],
                    projectiles=[
                        _projectile_sample(
                            uid=entity_uid(pool_kind="projectile", index=2, generation=1),
                            generation=1,
                            index=2,
                            owner_id=-100,
                        ),
                    ],
                    prelude=[
                        {"type": "game_frame_rng_advance", "frames": 2},
                    ],
                    postlude=[{"type": "perk_menu_open", "player_index": 0}],
                    checkpoint_overrides={
                        "deaths": [],
                        "events": {
                            "hit_count": 2,
                            "pickup_count": 2,
                            "sfx_count": 0,
                            "sfx_head": [],
                            "hit_head": [],
                        },
                    },
                ),
                "evidence": _tick_evidence_stub(
                    raw_hit_count=3,
                    owner_collision_count=1,
                    pickup_count=2,
                    raw_sfx_count=0,
                    deaths=[
                        {
                            "creature_index": 7,
                            "type_id": 18,
                            "reward_value": 75.0,
                            "xp_awarded": 10,
                            "owner_id": -1,
                        },
                    ],
                    sfx_head=[],
                    hit_head=[],
                ),
            },
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "rng_state_enter_u32": frame_state_2,
                "rng_state_leave_u32": frame_state_2,
                **_tick_identity_stub(tick_index=1, global_tick_index=101),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "channels": _channels_stub(
                    tick_index=1,
                    elapsed_ms=16,
                    mode_id=1,
                    prelude=[{"type": "perk_pick", "player_index": 0, "choice_index": 1}],
                    creatures=[
                        _creature_sample(
                            uid=entity_uid(pool_kind="creature", index=5, generation=1),
                            generation=1,
                            index=5,
                            active=True,
                        ),
                    ],
                ),
            },
            _run_end_row(run_id=1, mode_id=1, ticks_written=2, global_tick_index=101),
        ],
    )

    raw_sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=True)

    assert result.deleted_raw is True
    assert not raw_path.exists()
    assert len(result.traces) == 1

    out_trace = result.traces[0]
    assert out_trace.tick_count == 2
    assert out_trace.replay_path.is_file()

    replay = load_replay_file(out_trace.replay_path)
    assert replay.header.game_mode_id == 1
    assert replay.header.seed == 777
    assert replay.header.player_count == 1
    assert replay.header.preserve_bugs is True
    assert replay.header.quest_fail_retry_count == 3
    assert replay.header.hardcore is True
    assert replay.header.detail_preset == 2
    assert replay.header.violence_disabled == 1
    assert replay.header.world_size == 2048.0
    assert replay.header.status.quest_unlock_index == 7
    assert replay.header.status.weapon_usage_counts[1] == 17
    assert replay.header.status.quest_play_counts[3] == 9
    assert replay.header.status.unknown_tail == bytes(range(int(UNKNOWN_TAIL_SIZE)))
    assert len(replay.ticks) == 2

    meta, ticks, footer = load_trace(out_trace.out_path)
    assert footer.tick_count == 2
    assert meta.producer.impl == "frida_original"
    assert meta.source.kind == "capture"
    assert meta.source.player_count == 1
    assert meta.source.tick_rate == replay.header.tick_rate
    assert meta.source.replay_sha256 == hashlib.sha256(out_trace.replay_path.read_bytes()).hexdigest()
    assert ticks[0].channels.checkpoint.tick_index == 0
    assert ticks[1].channels.checkpoint.tick_index == 1
    assert ticks[0].channels.replay_step.dt == quantize_f32(0.016)
    assert ticks[0].channels.replay_step.prelude == [
        GameFrameRngAdvanceOperation(frames=2),
    ]
    assert ticks[0].channels.replay_step.postlude == [PerkMenuOpenCommand(player_index=0)]
    assert ticks[1].channels.replay_step.prelude == [PerkPickCommand(player_index=0, choice_index=1)]
    assert ticks[0].channels.replay_step.inputs[0].flags == 0
    assert replay.ticks[0].dt == ticks[0].channels.replay_step.dt
    assert replay.ticks[0].inputs[0] == [0.0, 0.0, 0.0, 0.0, 0]
    assert replay.ticks[0].prelude == ticks[0].channels.replay_step.prelude
    assert replay.ticks[0].postlude == ticks[0].channels.replay_step.postlude
    assert replay.ticks[1].prelude == ticks[1].channels.replay_step.prelude

    player0 = ticks[0].channels.sim_state.players[0]
    assert player0.heading == 0.0
    assert player0.move_speed == 0.0
    assert player0.move_phase == 0.0
    assert player0.aim.x == 0.0
    assert player0.aim.y == 0.0
    assert player0.aim_heading == 0.0

    creatures0 = ticks[0].channels.entity_samples.creatures
    creatures1 = ticks[1].channels.entity_samples.creatures
    assert isinstance(creatures0[0].uid, int)
    assert creatures0[0].generation == 1
    assert creatures1[0].generation == 1
    assert ticks[0].channels.entity_samples.projectiles[0].owner_id == -100
    assert creatures0[0].force_target == 1
    assert creatures0[0].target.x == 5.0
    assert creatures0[0].target_offset.y == -0.5
    assert creatures0[0].collision_timer == 0.125
    assert creatures0[0].attack_cooldown == 0.75
    assert ticks[0].channels.checkpoint.deaths == []
    assert ticks[0].channels.checkpoint.events.hit_count == 2
    assert ticks[0].channels.checkpoint.events.pickup_count == 2
    assert ticks[0].channels.checkpoint.events.sfx_count == 0
    assert ticks[0].channels.checkpoint.events.sfx_head == []
    assert ticks[0].channels.checkpoint.events.hit_head == []

    evidence = load_frida_evidence_file(out_trace.evidence_path)
    assert evidence.header.capture_format_version == CAPTURE_FORMAT_VERSION
    assert evidence.header.frida_version == FRIDA_RUNTIME_VERSION
    assert evidence.header.session_id == "session-test"
    assert evidence.header.ptrs_hash == "deadbeef"
    assert evidence.header.module_hash == "cafebabe"
    assert evidence.header.raw_sha256 == raw_sha256
    assert evidence.header.trace_sha256 == hashlib.sha256(out_trace.out_path.read_bytes()).hexdigest()
    assert evidence.header.replay_sha256 == hashlib.sha256(out_trace.replay_path.read_bytes()).hexdigest()
    assert evidence.footer.global_tick_first == 100
    assert evidence.footer.global_tick_last == 101
    private = evidence.ticks[0].evidence.checkpoint_private
    assert cast(dict[str, object], private.deaths[0])["owner_id"] == -1
    assert private.events.sfx_count == 0
    assert private.events.sfx_head == []

    # The producer emits run-local timing rows directly; finalize preserves them.
    timing0 = ticks[0].channels.timing_samples[0]
    timing1 = ticks[1].channels.timing_samples[0]
    assert timing0.tick_index == 0
    assert timing1.tick_index == 1
    assert timing0.mode_fn == "gameplay_update_and_render"
    assert timing1.mode_fn == "gameplay_update_and_render"


def test_finalize_frida_jsonl_to_traces_preserves_menu_postlude_then_next_tick_pick(
    tmp_path: Path,
) -> None:
    tick0_channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=1,
        postlude=[{"type": "perk_menu_open", "player_index": 0}],
    )
    tick1_channels = _channels_stub(
        tick_index=1,
        elapsed_ms=32,
        mode_id=1,
        prelude=[{"type": "perk_pick", "player_index": 0, "choice_index": 4}],
    )
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, player_count=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
                channels=tick0_channels,
            ),
            _tick_row(
                run_id=1,
                tick_index=1,
                elapsed_ms=32,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
                channels=tick1_channels,
            ),
            _run_end_row(run_id=1, mode_id=1, ticks_written=2, global_tick_index=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    replay = load_replay_file(result.traces[0].replay_path)
    _meta, ticks, _footer = load_trace(result.traces[0].out_path)
    menu_open = PerkMenuOpenCommand(player_index=0)
    pick = PerkPickCommand(player_index=0, choice_index=4)
    assert ticks[0].channels.replay_step.prelude == []
    assert ticks[0].channels.replay_step.postlude == [menu_open]
    assert ticks[1].channels.replay_step.prelude == [pick]
    assert ticks[1].channels.replay_step.postlude == []
    assert replay.ticks[0].postlude == [menu_open]
    assert replay.ticks[1].prelude == [pick]


def test_finalize_frida_jsonl_to_traces_preserves_numeric_rng_caller(tmp_path: Path) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1)
    channels["rng_stream"] = [_rng_stream_row_stub()]
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, seed=2427270273, player_count=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=0,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
                player_count=1,
                channels=channels,
                rng_state_enter_u32=2427270273,
                rng_state_leave_u32=3985917248,
            ),
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    _meta, ticks, _footer = load_trace(result.traces[0].out_path)
    assert ticks[0].channels.rng_stream[0].caller == 0x00430B88


def test_finalize_frida_jsonl_to_traces_accepts_eof_after_run_end(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, player_count=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1),
            },
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    assert result.traces[0].tick_count == 1


def test_finalize_frida_jsonl_to_traces_rejects_active_run_when_capture_abruptly_ends(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=4, mode_id=2, player_count=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 4,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "mode_id": 2,
                "channels": _channels_stub(tick_index=0, elapsed_ms=33, mode_id=2, dt_ms_i32=33, dt=0.033),
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="ended with active run 4"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert not list((tmp_path / "out").glob("*.cdt"))
    assert not list((tmp_path / "out").glob("*.crd"))


def test_finalize_frida_jsonl_to_traces_rejects_noncontiguous_local_tick_index(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, global_tick_index=40),
            _tick_row(
                run_id=1,
                tick_index=1,
                global_tick_index=40,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
            ),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="tick_index=1 does not match expected local tick 0"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert not list((tmp_path / "out").glob("*.cdt"))
    assert not list((tmp_path / "out").glob("*.crd"))


def test_finalize_frida_jsonl_to_traces_rejects_noncontiguous_global_tick_index(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, global_tick_index=40),
            _tick_row(
                run_id=1,
                tick_index=0,
                global_tick_index=41,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
            ),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="global_tick_index=41 does not match expected global tick 40"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert not list((tmp_path / "out").glob("*.cdt"))
    assert not list((tmp_path / "out").glob("*.crd"))


def test_finalize_frida_jsonl_to_traces_rejects_capture_with_no_finalized_runs(tmp_path: Path) -> None:
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [_session_start_row()])

    with pytest.raises(FridaFinalizeError, match="had no finalized runs"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_names_runs_by_mode_not_stale_quest_stage(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 5,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=0,
                    mode_id=3,
                    quest_stage_major=1,
                    quest_stage_minor=5,
                ),
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=5, ticks_written=1),
            _run_start_row(
                run_id=2,
                mode_id=2,
                player_count=1,
                quest_stage_major=1,
                quest_stage_minor=5,
                global_tick_index=1,
            ),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(global_tick_index=1),
                "run_id": 2,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 2,
                "quest_stage_major": 1,
                "quest_stage_minor": 5,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=16,
                    mode_id=2,
                    quest_stage_major=1,
                    quest_stage_minor=5,
                ),
            },
            _run_end_row(
                run_id=2,
                mode_id=2,
                quest_stage_major=1,
                quest_stage_minor=5,
                ticks_written=1,
                global_tick_index=1,
            ),
            _run_start_row(
                run_id=3,
                mode_id=1,
                player_count=1,
                quest_stage_major=1,
                quest_stage_minor=5,
                global_tick_index=2,
            ),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(global_tick_index=2),
                "run_id": 3,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "mode_id": 1,
                "quest_stage_major": 1,
                "quest_stage_minor": 5,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=33,
                    mode_id=1,
                    dt_ms_i32=33,
                    dt=0.033,
                    quest_stage_major=1,
                    quest_stage_minor=5,
                ),
            },
            _run_end_row(
                run_id=3,
                mode_id=1,
                quest_stage_major=1,
                quest_stage_minor=5,
                ticks_written=1,
                global_tick_index=2,
            ),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 3
    names = sorted(trace.out_path.name for trace in result.traces)
    assert names == [
        "capture.quest_1_5.run1.cdt",
        "capture.rush.run1.cdt",
        "capture.survival.run1.cdt",
    ]
    replay_names = sorted(trace.replay_path.name for trace in result.traces)
    assert replay_names == [
        "capture.quest_1_5.run1.crd",
        "capture.rush.run1.crd",
        "capture.survival.run1.crd",
    ]


def test_finalize_frida_jsonl_to_traces_rejects_legacy_rng_marks_channel(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, seed=51, player_count=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "channels": {
                    **_channels_stub(tick_index=123, elapsed_ms=0, mode_id=1),
                    "checkpoint": {
                        "tick_index": 123,
                        "rng_state": 777,
                        "elapsed_ms": 0,
                        "score_xp": 0,
                        "kills": 0,
                        "creature_count": 0,
                        "perk_pending": 0,
                        "players": [],
                        "bonus_timers": {},
                    },
                    "rng_marks": {
                        "rand_calls": 3,
                        "rand_last": 99,
                        "rand_seq_first": 1,
                        "rand_seq_last": 3,
                    },
                },
            },
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="invalid capture row"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_null_run_start_seed_with_actionable_error(tmp_path: Path) -> None:
    run_start = _run_start_row(run_id=1, mode_id=1)
    run_start["rng_state_before_bootstrap"] = None
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            run_start,
        ],
    )

    with pytest.raises(
        FridaFinalizeError,
        match=r"Expected `int`, got `null` - at `\$\.rng_state_before_bootstrap`",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_legacy_bootstrap_kind_field(tmp_path: Path) -> None:
    run_start = _run_start_row(run_id=1, mode_id=1)
    run_start["bootstrap_kind"] = "terrain_v1"
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            run_start,
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `bootstrap_kind`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_legacy_bootstrap_seed_field(tmp_path: Path) -> None:
    run_start = _run_start_row(run_id=1, mode_id=1)
    run_start["bootstrap_seed"] = 7
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            run_start,
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `bootstrap_seed`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_previous_capture_format_version(
    tmp_path: Path,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(capture_format_version=CAPTURE_FORMAT_VERSION - 1),
            _run_start_row(run_id=1, mode_id=3, seed=91, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "channels": _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3),
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
        ],
    )

    with pytest.raises(
        FridaFinalizeError,
        match=rf"unsupported capture_format_version={CAPTURE_FORMAT_VERSION - 1}; expected {CAPTURE_FORMAT_VERSION}",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_other_frida_runtime(tmp_path: Path) -> None:
    session_start = _session_start_row()
    session_start["frida_version"] = "17.5.2"
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session_start])

    with pytest.raises(FridaFinalizeError, match=r"frida_version='17\.5\.2'; expected '17\.15\.4'"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def _pool_residue_slot_stub(index: int, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "index": int(index),
        "active": 0,
        "phase_seed": 0.0,
        "state_flag": 0,
        "collision_flag": 0,
        "collision_timer": 0.0,
        "lifecycle_stage": 0.0,
        "pos": {"x": 0.0, "y": 0.0},
        "vel": {"x": 0.0, "y": 0.0},
        "hp": 0.0,
        "max_hp": 0.0,
        "heading": 0.0,
        "target_heading": 0.0,
        "size": 0.0,
        "hit_flash_timer": 0.0,
        "tint": {"r": 0.0, "g": 0.0, "b": 0.0, "a": 0.0},
        "force_target": 0,
        "target": {"x": 0.0, "y": 0.0},
        "contact_damage": 0.0,
        "move_speed": 0.0,
        "attack_cooldown": 0.0,
        "reward_value": 0.0,
        "type_id": 0,
        "target_player": 0,
        "link_index": 0,
        "target_offset": {"x": 0.0, "y": 0.0},
        "orbit_angle": 0.0,
        "orbit_radius_u32": 0,
        "flags": 0,
        "ai_mode": 0,
        "anim_phase": 0.0,
    }
    row.update(overrides)
    return row


def _current_session_start_row() -> dict[str, object]:
    return _session_start_row()


def test_finalize_frida_jsonl_to_traces_carries_pool_residue_into_replay_header(tmp_path: Path) -> None:
    run_start = _run_start_row(
        run_id=1,
        mode_id=1,
        player_count=1,
    )
    run_start["pool_residue"] = [
        _pool_residue_slot_stub(0, link_index=3, target_heading=4.044, type_id=2),
        _pool_residue_slot_stub(1),
    ]
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _current_session_start_row(),
            run_start,
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "channels": _channels_stub(tick_index=0, elapsed_ms=16, mode_id=1),
            },
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    replay = load_replay_file(result.traces[0].replay_path)
    pool = replay.header.initial_creature_pool
    assert pool is not None
    assert len(pool) == 2
    assert pool[0].link_index == 3
    assert pool[0].type_id == 2
    assert abs(pool[0].target_heading - 4.044) < 1e-6
    assert pool[1].link_index == 0


def test_finalize_frida_jsonl_to_traces_requires_pool_residue(tmp_path: Path) -> None:
    run_start = _run_start_row(run_id=1, mode_id=1, seed=91, player_count=1, rng_state_before_bootstrap=777)
    run_start.pop("pool_residue")
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _current_session_start_row(),
            run_start,
        ],
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `pool_residue`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_active_pool_residue_slot(tmp_path: Path) -> None:
    run_start = _run_start_row(run_id=1, mode_id=1, seed=91, player_count=1, rng_state_before_bootstrap=777)
    run_start["pool_residue"] = [_pool_residue_slot_stub(0, active=1)]
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [_current_session_start_row(), run_start],
    )

    with pytest.raises(FridaFinalizeError, match="active at run start"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_trimmed_entity_samples(tmp_path: Path) -> None:
    config = _session_config_stub()
    config["creature_sample_limit"] = 64
    session_start = _session_start_row()
    session_start["config"] = config
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session_start])

    with pytest.raises(FridaFinalizeError, match=r"trimmed streams \{'creature_sample_limit': 64\}"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_trimmed_diagnostic_streams(tmp_path: Path) -> None:
    session_start = _session_start_row()
    config = dict(_session_config_stub())
    config["max_rng_outside_tick_head"] = 256
    config["max_creature_delta_ids"] = 256
    session_start["config"] = config
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session_start])

    with pytest.raises(
        FridaFinalizeError,
        match=r"trimmed streams \{'max_rng_outside_tick_head': 256, 'max_creature_delta_ids': 256\}",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_focus_mode_capture(tmp_path: Path) -> None:
    config = _session_config_stub()
    config["focus_tick"] = 1200
    session_start = _session_start_row()
    session_start["config"] = config
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session_start])

    with pytest.raises(FridaFinalizeError, match=r"focus mode \(focus_tick=1200\)"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_keeps_large_first_tick_elapsed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 25_000,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=25_000,
                    mode_id=3,
                    quest_stage_major=1,
                    quest_stage_minor=1,
                ),
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    assert result.deleted_raw is False
    assert len(result.traces) == 1
    assert result.traces[0].tick_count == 1
    _meta, ticks, _footer = load_trace(result.traces[0].out_path)
    assert ticks[0].elapsed_ms == 25_000
    assert ticks[0].channels.checkpoint.elapsed_ms == 25_000


def test_finalize_frida_jsonl_to_traces_rejects_missing_required_canonical_channel(
    tmp_path: Path,
) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3)
    channels.pop("sim_state", None)
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=93, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "channels": channels,
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `sim_state`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_extra_non_canonical_channel(
    tmp_path: Path,
) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3)
    channels["event_heads"] = []
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=94, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "channels": channels,
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `event_heads`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_session_start_config_out_path_mismatch(tmp_path: Path) -> None:
    session_start = _session_start_row()
    config = dict(_session_config_stub())
    config["out_path"] = "C:\\share\\frida\\wrong.jsonl"
    session_start["config"] = config
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session_start])

    with pytest.raises(FridaFinalizeError, match="config.out_path must match out_path"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_session_start_fingerprint_session_id_mismatch(tmp_path: Path) -> None:
    session_start = _session_start_row()
    fingerprint = dict(_session_fingerprint_stub())
    fingerprint["session_id"] = "session-other"
    session_start["session_fingerprint"] = fingerprint
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session_start])

    with pytest.raises(FridaFinalizeError, match="session_fingerprint.session_id must match session_id"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_removed_run_start_seed_source(tmp_path: Path) -> None:
    run_start = _run_start_row(
        run_id=1,
        mode_id=3,
        seed=101,
        player_count=1,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    run_start["seed_source"] = "thread_rng_sample"
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            run_start,
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `seed_source`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_tick_mode_mismatch(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=102, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=2,
                quest_stage_major=1,
                quest_stage_minor=1,
            ),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="tick mode_id=2 does not match active run 3"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_missing_timing_samples_field(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    channels.pop("timing_samples", None)
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=103, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "channels": channels,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `timing_samples`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_empty_checkpoint_players(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    checkpoint = cast(dict[str, object], channels["checkpoint"])
    checkpoint["players"] = []
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=104, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "channels": channels,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match=r"channels\.checkpoint\.players must be non-empty"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_invalid_checkpoint_rng_state(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    checkpoint = cast(dict[str, object], channels["checkpoint"])
    checkpoint["rng_state"] = -1
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=105, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "channels": channels,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match=r"channels\.checkpoint\.rng_state must be a uint32"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_empty_timing_samples(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    channels["timing_samples"] = []
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=106, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "channels": channels,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match=r"channels\.timing_samples must be non-empty"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_missing_gpur_enter_timing_sample(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    channels["timing_samples"] = [_timing_sample_stub(tick_index=0, phase="mode_enter", dt_ms_i32=16)]
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=107, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=3,
                player_count=1,
                quest_stage_major=1,
                quest_stage_minor=1,
                channels=channels,
            ),
        ],
    )

    with pytest.raises(
        FridaFinalizeError,
        match=r"channels\.timing_samples must include phase `gpur_enter`",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_dt_mismatch_with_gpur_enter(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    replay_step = cast(dict[str, object], channels["replay_step"])
    replay_step["dt"] = quantize_f32(0.017)
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=3,
                player_count=1,
                quest_stage_major=1,
                quest_stage_minor=1,
                channels=channels,
            ),
        ],
    )

    with pytest.raises(
        FridaFinalizeError,
        match=r"channels\.timing_samples\.gpur_enter\.frame_dt_f32=.*does not match replay_step\.dt",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_noncanonical_replay_step_f32(tmp_path: Path) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=16, mode_id=1)
    replay_step = cast(dict[str, object], channels["replay_step"])
    replay_step["dt"] = 0.016
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
                channels=channels,
            ),
        ],
    )

    with pytest.raises(FridaFinalizeError, match=r"channels\.replay_step\.dt must already be canonical f32"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_dt_ms_i32_mismatch_with_gpur_enter(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=109, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=17,
                dt=0.016,
                mode_id=3,
                player_count=1,
                quest_stage_major=1,
                quest_stage_minor=1,
                channels=channels,
            ),
        ],
    )

    with pytest.raises(
        FridaFinalizeError,
        match=r"channels\.timing_samples\.gpur_enter\.frame_dt_ms_i32=16 does not match tick\.dt_ms_i32 17",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_sim_state_player_count_mismatch(tmp_path: Path) -> None:
    channels = _channels_stub(
        tick_index=0,
        elapsed_ms=16,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    sim_state = cast(dict[str, object], channels["sim_state"])
    sim_state["players"] = []
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=107, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                **_tick_identity_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "channels": channels,
            },
        ],
    )

    with pytest.raises(
        FridaFinalizeError,
        match=r"channels\.sim_state\.players length 0 does not match checkpoint\.players length 1",
    ):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_run_end_tick_count_mismatch(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=3,
                quest_stage_major=1,
                quest_stage_minor=1,
            ),
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=0),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="run_end.ticks_written=0 does not match active run tick_count 1"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_capture_error_row(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            {
                "event": "error",
                "error": "missing_run_start_seed",
                "run_id": 1,
                "global_tick_index": 77,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="capture error='missing_run_start_seed' global_tick_index=77"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_run_error_without_partial_outputs(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
            ),
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
            _run_start_row(run_id=2, mode_id=1, global_tick_index=1),
            {
                "event": "run_error",
                "error": "samples.secondary_projectiles[0].speed must be finite",
                "run_id": 2,
                "mode_id": 1,
                "quest_stage_major": 0,
                "quest_stage_minor": 0,
                "global_tick_index": 1,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="run error='samples.secondary_projectiles"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert not list((tmp_path / "out").glob("*.cdt"))
    assert not list((tmp_path / "out").glob("*.crd"))


def test_finalize_frida_jsonl_to_traces_rejects_removed_session_end_row(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            {"event": "session_end", "session_id": "session-test", "ticks_written": 0},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="invalid capture row"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_missing_capture_format_version(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
        ],
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `capture_format_version`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def _single_tick_rows(
    *,
    run_start: dict[str, object],
    tick_overrides: dict[str, object] | None = None,
    run_end: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    tick: dict[str, object] = {
        "event": "tick",
        **_rng_accounting_stub(),
        **_tick_identity_stub(),
        "run_id": 1,
        "elapsed_ms": 0,
        "dt_ms_i32": 16,
        "mode_id": 1,
        "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1),
    }
    tick.update(tick_overrides or {})
    return [
        _session_start_row(),
        run_start,
        tick,
        _run_end_row(run_id=1, mode_id=1, ticks_written=1) if run_end is None else run_end,
    ]


def test_finalize_frida_jsonl_to_traces_seeds_replay_from_pre_bootstrap_rng_state(tmp_path: Path) -> None:
    state_before = 999
    state_after = (state_before * 214013 + 2531011) & 0xFFFFFFFF
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(
                run_id=1,
                mode_id=1,
                seed=123,
                player_count=1,
                rng_state_before_bootstrap=state_before,
                rng_state_after_bootstrap=state_after,
                rng_bootstrap_calls=1,
            ),
            tick_overrides={"rng_state_enter_u32": state_after, "rng_state_leave_u32": state_after},
        ),
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    replay = load_replay_file(result.traces[0].replay_path)
    assert replay.header.seed == 999
    meta, _ticks, _footer = load_trace(result.traces[0].out_path)
    assert meta.source.seed == 999
    assert meta.source.run_start_seed_source == "rng_state_before_bootstrap"
    rng_evidence = json.loads(
        result.traces[0].out_path.with_suffix(".rng_evidence.json").read_text(encoding="utf-8"),
    )
    assert rng_evidence["bootstrap_state_before"] == state_before
    assert rng_evidence["bootstrap_state_after"] == state_after
    assert rng_evidence["bootstrap_calls"] == 1


def test_finalize_frida_jsonl_to_traces_rejects_inconsistent_bootstrap_rng_boundary(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(
                run_id=1,
                mode_id=1,
                rng_state_before_bootstrap=100,
                rng_state_after_bootstrap=101,
                rng_bootstrap_calls=0,
            ),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="bootstrap RNG boundary does not match"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_requires_captured_first_tick_frame_rng_advance(tmp_path: Path) -> None:
    seed = 100
    frame_after = (seed * 214013 + 2531011) & 0xFFFFFFFF
    rows = _single_tick_rows(
        run_start=_run_start_row(run_id=1, mode_id=1, rng_state_before_bootstrap=seed),
        tick_overrides={
            "rng_state_enter_u32": frame_after,
            "rng_state_leave_u32": frame_after,
            "channels": _channels_stub(
                tick_index=0,
                elapsed_ms=0,
                mode_id=1,
                prelude=[{"type": "game_frame_rng_advance", "frames": 1}],
            ),
            "rng_outside_before": _rng_outside_bag_stub(
                calls=1,
                caller_counts={"0x0040cac7": 1},
                head=[
                    {
                        "state_before_u32": seed,
                        "state_after_u32": frame_after,
                        "value_15": (frame_after >> 16) & 0x7FFF,
                        "caller_static": "0x0040cac7",
                        "replay_operation_index": 0,
                    },
                ],
            ),
        },
    )
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", rows)

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    replay = load_replay_file(result.traces[0].replay_path)
    _meta, ticks, _footer = load_trace(result.traces[0].out_path)
    assert replay.ticks[0].prelude == [GameFrameRngAdvanceOperation(frames=1)]
    assert ticks[0].channels.replay_step.prelude == replay.ticks[0].prelude


def test_finalize_frida_jsonl_to_traces_accepts_rng_owned_by_perk_operation(tmp_path: Path) -> None:
    seed = 100
    state_after = (seed * 214013 + 2531011) & 0xFFFFFFFF
    rows = _single_tick_rows(
        run_start=_run_start_row(run_id=1, mode_id=1, rng_state_before_bootstrap=seed),
        tick_overrides={
            "rng_state_enter_u32": state_after,
            "rng_state_leave_u32": state_after,
            "channels": _channels_stub(
                tick_index=0,
                elapsed_ms=0,
                mode_id=1,
                prelude=[{"type": "perk_menu_open", "player_index": 0}],
            ),
            "rng_outside_before": _rng_outside_bag_stub(
                calls=1,
                caller_counts={"0x00417f00": 1},
                head=[
                    {
                        "state_before_u32": seed,
                        "state_after_u32": state_after,
                        "value_15": (state_after >> 16) & 0x7FFF,
                        "caller_static": "0x00417f00",
                        "replay_operation_index": 0,
                    },
                ],
            ),
        },
    )
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", rows)

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    replay = load_replay_file(result.traces[0].replay_path)
    assert replay.ticks[0].prelude == [PerkMenuOpenCommand(player_index=0)]


def test_finalize_frida_jsonl_to_traces_validates_rng_owned_by_trailing_operation(tmp_path: Path) -> None:
    seed = 100
    state_after = (seed * 214013 + 2531011) & 0xFFFFFFFF
    rows = _single_tick_rows(
        run_start=_run_start_row(run_id=1, mode_id=1, rng_state_before_bootstrap=seed),
        tick_overrides={"rng_state_enter_u32": seed, "rng_state_leave_u32": seed},
        run_end=_run_end_row(
            run_id=1,
            mode_id=1,
            ticks_written=1,
            trailing_prelude=[{"type": "perk_menu_open", "player_index": 0}],
            rng_outside_tail=_rng_outside_bag_stub(
                calls=1,
                caller_counts={"0x00417f00": 1},
                head=[
                    {
                        "state_before_u32": seed,
                        "state_after_u32": state_after,
                        "value_15": (state_after >> 16) & 0x7FFF,
                        "caller_static": "0x00417f00",
                        "replay_operation_index": 0,
                    },
                ],
            ),
        ),
    )
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", rows)

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    assert result.traces[0].tick_count == 1


def test_finalize_frida_jsonl_to_traces_rejects_missing_pre_bootstrap_rng_state(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1, include_rng_state_before_bootstrap=False),
        ),
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `rng_state_before_bootstrap`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_tick_without_rng_accounting(tmp_path: Path) -> None:
    rows = _single_tick_rows(run_start=_run_start_row(run_id=1, mode_id=1))
    tick = rows[2]
    del tick["rng_outside_before"]
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", rows)

    with pytest.raises(FridaFinalizeError, match="missing required field `rng_outside_before`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_rng_calls_stream_mismatch(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1),
            tick_overrides={"rng_calls": 3},
        ),
    )

    with pytest.raises(FridaFinalizeError, match="rng_calls=3 does not match rng_stream length 0"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_run_end_without_rng_outside_tail(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1),
            run_end=_run_end_row(run_id=1, mode_id=1, ticks_written=1, include_rng_outside_tail=False),
        ),
    )

    with pytest.raises(FridaFinalizeError, match="missing required field `rng_outside_tail`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_outside_rng_caller_owned_by_wrong_operation(tmp_path: Path) -> None:
    seed = 100
    state_1 = (seed * 214013 + 2531011) & 0xFFFFFFFF
    state_2 = (state_1 * 214013 + 2531011) & 0xFFFFFFFF
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1, rng_state_before_bootstrap=seed),
            tick_overrides={
                "rng_state_enter_u32": state_2,
                "rng_state_leave_u32": state_2,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=0,
                    mode_id=1,
                    prelude=[{"type": "game_frame_rng_advance", "frames": 2}],
                ),
                "rng_outside_before": _rng_outside_bag_stub(
                    calls=2,
                    caller_counts={"0x00417f00": 2},
                    head=[
                        {
                            "state_before_u32": seed,
                            "state_after_u32": state_1,
                            "value_15": (state_1 >> 16) & 0x7FFF,
                            "caller_static": "0x00417f00",
                            "replay_operation_index": 0,
                        },
                        {
                            "state_before_u32": state_1,
                            "state_after_u32": state_2,
                            "value_15": (state_2 >> 16) & 0x7FFF,
                            "caller_static": "0x00417f00",
                            "replay_operation_index": 0,
                        },
                    ],
                ),
            },
        ),
    )

    with pytest.raises(FridaFinalizeError, match="frame operation has caller"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_out_of_order_rng_ownership(tmp_path: Path) -> None:
    seed = 100
    state_1 = (seed * 214013 + 2531011) & 0xFFFFFFFF
    state_2 = (state_1 * 214013 + 2531011) & 0xFFFFFFFF
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1, rng_state_before_bootstrap=seed),
            tick_overrides={
                "rng_state_enter_u32": state_2,
                "rng_state_leave_u32": state_2,
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=0,
                    mode_id=1,
                    prelude=[
                        {"type": "game_frame_rng_advance", "frames": 1},
                        {"type": "perk_menu_open", "player_index": 0},
                    ],
                ),
                "rng_outside_before": _rng_outside_bag_stub(
                    calls=2,
                    caller_counts={"0x0040cac7": 1, "0x00417f00": 1},
                    head=[
                        {
                            "state_before_u32": seed,
                            "state_after_u32": state_1,
                            "value_15": (state_1 >> 16) & 0x7FFF,
                            "caller_static": "0x00417f00",
                            "replay_operation_index": 1,
                        },
                        {
                            "state_before_u32": state_1,
                            "state_after_u32": state_2,
                            "value_15": (state_2 >> 16) & 0x7FFF,
                            "caller_static": "0x0040cac7",
                            "replay_operation_index": 0,
                        },
                    ],
                ),
            },
        ),
    )

    with pytest.raises(FridaFinalizeError, match="precedes prior operation"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


@pytest.mark.parametrize("mode_id", [0, 4, 8])
def test_finalize_frida_jsonl_to_traces_rejects_unsupported_replay_modes(
    tmp_path: Path,
    mode_id: int,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [_session_start_row(), _run_start_row(run_id=1, mode_id=mode_id)],
    )

    with pytest.raises(FridaFinalizeError, match=rf"unsupported mode_id={mode_id}"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_player_count_override(tmp_path: Path) -> None:
    session = _session_start_row()
    config = _session_config_stub()
    config["player_count_override"] = 2
    session["config"] = config
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [session])

    with pytest.raises(FridaFinalizeError, match="player_count_override=2"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_finalize_frida_jsonl_to_traces_rejects_drifted_nested_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    tick = _tick_row(
        run_id=1,
        tick_index=0,
        elapsed_ms=16,
        dt_ms_i32=16,
        dt=0.016,
        mode_id=1,
    )
    evidence = cast(dict[str, object], tick["evidence"])
    checkpoint = cast(dict[str, object], evidence["checkpoint_private"])
    events = cast(dict[str, object], checkpoint["events"])
    if mutation == "missing":
        del events["sfx_count"]
    else:
        events["unexpected"] = 1
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [_session_start_row(), _run_start_row(run_id=1, mode_id=1), tick],
    )

    with pytest.raises(FridaFinalizeError, match="invalid capture row"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_requires_owner_collision_event_count(tmp_path: Path) -> None:
    rows = _single_tick_rows(run_start=_run_start_row(run_id=1, mode_id=1))
    evidence = cast(dict[str, object], rows[2]["evidence"])
    event_counts = cast(dict[str, int], evidence["event_counts"])
    del event_counts["projectile_find_owner_collision"]
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", rows)

    with pytest.raises(FridaFinalizeError, match="missing required event counts"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_contract_error_run_end(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
            ),
            _run_end_row(run_id=1, mode_id=1, ticks_written=1, reason="capture_contract_error"),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="reason must be one of"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_preserves_quest_native_elapsed_clock(tmp_path: Path) -> None:
    tick = _tick_row(
        run_id=1,
        tick_index=0,
        elapsed_ms=321,
        dt_ms_i32=16,
        dt=0.016,
        mode_id=3,
        quest_stage_major=1,
        quest_stage_minor=2,
    )
    tick["evidence"] = _tick_evidence_stub(
        time_played_ms_raw=999,
        quest_spawn_timeline_raw=321,
        summed_replay_clock_ms=16,
        canonical_elapsed_ms=321,
    )
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=2),
            tick,
            _run_end_row(
                run_id=1,
                mode_id=3,
                quest_stage_major=1,
                quest_stage_minor=2,
                ticks_written=1,
            ),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    _meta, ticks, _footer = load_trace(result.traces[0].out_path)
    evidence = load_frida_evidence_file(result.traces[0].evidence_path)
    assert ticks[0].elapsed_ms == 321
    assert evidence.ticks[0].evidence.clocks.time_played_ms_raw == 999
    assert evidence.ticks[0].evidence.clocks.summed_replay_clock_ms == 16
    assert evidence.ticks[0].evidence.clocks.canonical_elapsed_ms == 321


def test_load_frida_evidence_file_rejects_trailing_bytes_and_extra_frames(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(run_start=_run_start_row(run_id=1, mode_id=1)),
    )
    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    valid = result.traces[0].evidence_path.read_bytes()
    trailing = tmp_path / "trailing.evidence.msgpack.zst"
    trailing.write_bytes(valid + b"garbage")
    extra_frame = tmp_path / "extra-frame.evidence.msgpack.zst"
    extra_frame.write_bytes(valid + zstd.ZstdCompressor().compress(b"extra"))

    for path in (trailing, extra_frame):
        with pytest.raises(FridaFinalizeError, match="trailing bytes or extra zstd frames"):
            load_frida_evidence_file(path)


def test_finalize_frida_jsonl_to_traces_rolls_back_bundle_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(run_start=_run_start_row(run_id=1, mode_id=1)),
    )
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    artifact_names = (
        "capture.survival.run1.cdt",
        "capture.survival.run1.crd",
        "capture.survival.run1.rng_evidence.json",
        "capture.survival.run1.evidence.msgpack.zst",
    )
    for name in artifact_names:
        (output_dir / name).write_bytes(b"previous-" + name.encode())

    original_replace = Path.replace
    failed = False

    def fail_second_staged_replace(source: Path, target: Path) -> Path:
        nonlocal failed
        if not failed and source.parent.name == "output" and source.suffix == ".crd":
            failed = True
            raise OSError("injected publish failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_second_staged_replace)
    with pytest.raises(FridaFinalizeError, match="failed to publish finalized artifact set"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=output_dir, delete_raw=True)

    assert raw_path.is_file()
    for name in artifact_names:
        assert (output_dir / name).read_bytes() == b"previous-" + name.encode()
