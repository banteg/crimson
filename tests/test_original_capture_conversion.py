from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import cast

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
    CAPTURE_STATE_TRANSITION_EVENT_KIND,
    CaptureError,
    apply_capture_bootstrap_payload,
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_dt_frame_overrides,
    build_capture_inter_tick_rand_draws_overrides,
    capture_bootstrap_payload_from_event_payload,
    capture_creature_spawn_added_head_from_event_payload,
    capture_creature_spawn_added_head_rows_from_event_payload,
    capture_creature_spawns_from_event_payload,
    capture_perk_apply_from_event_payload,
    capture_perk_apply_id_from_event_payload,
    capture_perk_apply_pending_bounds_from_event_payload,
    capture_perk_pending_from_event_payload,
    capture_state_transitions_from_event_payload,
    convert_capture_to_checkpoints,
    convert_capture_to_replay,
    default_capture_replay_path,
    load_capture,
    parse_player_int_overrides,
    summarize_capture_health,
)
from crimson.original.schema import (
    CAPTURE_FORMAT_VERSION,
    CaptureEventHeadPerkApply,
    CaptureEventHeadProjectileFindQuery,
    CaptureTick,
)
from crimson.replay import PerkMenuOpenEvent, Replay, UnknownEvent, unpack_input_flags, unpack_input_move_key_flags
from crimson.replay.checkpoints import dump_checkpoints, load_checkpoints
from crimson.sim.state_types import PlayerState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.builders.capture import (
    build_capture_bonus_sample,
    build_capture_creature_sample,
    build_capture_file,
    build_capture_projectile_sample,
    build_capture_rng_head_entry,
    build_capture_secondary_projectile_sample,
    build_capture_snapshot_player,
    build_capture_tick,
    capture_file_to_dict,
    capture_value_to_builtins,
)
from tests.helpers import assert_float_close


def _crt_rand_outputs(seed: int, calls: int) -> list[int]:
    state = int(seed) & 0xFFFFFFFF
    out: list[int] = []
    for _ in range(int(calls)):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        out.append((state >> 16) & 0x7FFF)
    return out


_DEFAULT_CAPTURE_FILE = capture_file_to_dict(
    build_capture_file(
        ticks=[build_capture_tick(tick_index=0, elapsed_ms=0)],
        session_id="defaults",
    ),
)
_DEFAULT_CAPTURE_TICK = cast(dict[str, object], cast(list[object], _DEFAULT_CAPTURE_FILE["ticks"])[0])
_DEFAULT_CAPTURE_SNAPSHOT_PLAYER = cast(dict[str, object], capture_value_to_builtins(build_capture_snapshot_player()))
_DEFAULT_CAPTURE_CREATURE_SAMPLE = cast(dict[str, object], capture_value_to_builtins(build_capture_creature_sample()))
_DEFAULT_CAPTURE_PROJECTILE_SAMPLE = cast(dict[str, object], capture_value_to_builtins(build_capture_projectile_sample()))
_DEFAULT_CAPTURE_SECONDARY_PROJECTILE_SAMPLE = cast(
    dict[str, object],
    capture_value_to_builtins(build_capture_secondary_projectile_sample()),
)
_DEFAULT_CAPTURE_BONUS_SAMPLE = cast(dict[str, object], capture_value_to_builtins(build_capture_bonus_sample()))
_DEFAULT_CAPTURE_RNG_HEAD_ENTRY = cast(dict[str, object], capture_value_to_builtins(build_capture_rng_head_entry()))


def _clone_dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], msgspec.json.decode(msgspec.json.encode(value)))


def _base_input_approx(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(cast(list[object], _DEFAULT_CAPTURE_TICK["input_approx"])[0])
    d["aim_x"] = 512.0
    d["aim_y"] = 512.0
    d.update(kwargs)
    return d


def _base_input_player_keys(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(cast(list[object], _DEFAULT_CAPTURE_TICK["input_player_keys"])[0])
    d.update(kwargs)
    return d


def _base_event_counts(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_TICK["event_counts"])
    d.update(kwargs)
    return d


def _base_rng_head_entry(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_RNG_HEAD_ENTRY)
    d.update(kwargs)
    return d


def _base_rng_summary(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_TICK["rng"])
    d.update(kwargs)
    return d


def _base_config(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_FILE["config"])
    d.update(kwargs)
    return d


def _base_player() -> dict[str, object]:
    checkpoint = _clone_dict(_DEFAULT_CAPTURE_TICK["checkpoint"])
    return _clone_dict(cast(list[object], checkpoint["players"])[0])


def _base_snapshot_globals(**kwargs: object) -> dict[str, object]:
    before = _clone_dict(_DEFAULT_CAPTURE_TICK["before"])
    d = _clone_dict(before["globals"])
    for key in (
        "config_game_mode",
        "game_state_prev",
        "game_state_id",
        "game_state_pending",
        "frame_dt",
        "frame_dt_ms_i32",
        "frame_dt_ms_f32",
        "time_played_ms",
        "creature_active_count",
        "creature_kill_count",
        "perk_pending_count",
        "perk_choices_dirty",
        "shock_chain_links_left",
        "shock_chain_projectile_id",
        "quest_spawn_timeline",
        "quest_stage_major",
        "quest_stage_minor",
        "quest_spawn_stall_timer_ms",
        "quest_transition_timer_ms",
        "quest_stage_banner_timer_ms",
        "ui_elements_timeline",
        "ui_transition_direction",
        "ui_transition_alpha",
        "pause_keybind_help_alpha_ms",
        "player_alt_weapon_swap_cooldown_ms",
        "perk_jinxed_proc_timer_s",
        "perk_lean_mean_exp_tick_timer_s",
        "perk_doctor_target_creature_id",
        "bonus_reflex_boost_timer",
        "bonus_freeze_timer",
        "bonus_weapon_power_up_timer",
        "bonus_energizer_timer",
        "bonus_double_xp_timer",
    ):
        d[key] = None
    d.update(kwargs)
    return d


def _base_snapshot_status(**kwargs: object) -> dict[str, object]:
    before = _clone_dict(_DEFAULT_CAPTURE_TICK["before"])
    d = _clone_dict(before["status"])
    d.update(kwargs)
    return d


def _base_snapshot_input(**kwargs: object) -> dict[str, object]:
    before = _clone_dict(_DEFAULT_CAPTURE_TICK["before"])
    d = _clone_dict(before["input"])
    d.update(kwargs)
    return d


def _base_snapshot_input_bindings(**kwargs: object) -> dict[str, object]:
    before = _clone_dict(_DEFAULT_CAPTURE_TICK["before"])
    d = _clone_dict(before["input_bindings"])
    d.update(kwargs)
    return d


def _base_snapshot_player_perk_timers(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_SNAPSHOT_PLAYER["perk_timers"])
    d.update(kwargs)
    return d


def _base_snapshot_player_bonus_timers(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_SNAPSHOT_PLAYER["bonus_timers"])
    d.update(kwargs)
    return d


def _base_snapshot_player_alt_weapon(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_SNAPSHOT_PLAYER["alt_weapon"])
    d.update(kwargs)
    return d


def _base_snapshot_player(**kwargs: object) -> dict[str, object]:
    d = _clone_dict(_DEFAULT_CAPTURE_SNAPSHOT_PLAYER)
    d.update(kwargs)
    return d


def _base_snapshot(**kwargs: object) -> dict[str, object]:
    d: dict[str, object] = {
        "globals": _base_snapshot_globals(),
        "status": _base_snapshot_status(),
        "player_count": 1,
        "players": [],
        "input": _base_snapshot_input(),
        "input_bindings": _base_snapshot_input_bindings(),
    }
    d.update(kwargs)
    return d


def _base_timing_diagnostics(**kwargs: object) -> dict[str, object]:
    checkpoint = _clone_dict(_DEFAULT_CAPTURE_TICK["checkpoint"])
    debug = _clone_dict(checkpoint["debug"])
    d = _clone_dict(debug["timing"])
    d.update(kwargs)
    return d


def _base_spawn_diagnostics(**kwargs: object) -> dict[str, object]:
    checkpoint = _clone_dict(_DEFAULT_CAPTURE_TICK["checkpoint"])
    debug = _clone_dict(checkpoint["debug"])
    d = _clone_dict(debug["spawn"])
    d.update(kwargs)
    return d


def _base_rng_diagnostics(**kwargs: object) -> dict[str, object]:
    checkpoint = _clone_dict(_DEFAULT_CAPTURE_TICK["checkpoint"])
    debug = _clone_dict(checkpoint["debug"])
    d = _clone_dict(debug["rng"])
    d.update(kwargs)
    return d


def _base_player_fire_diagnostics(**kwargs: object) -> dict[str, object]:
    checkpoint = _clone_dict(_DEFAULT_CAPTURE_TICK["checkpoint"])
    debug = _clone_dict(checkpoint["debug"])
    d = _clone_dict(debug["player_fire"])
    d.update(kwargs)
    return d


def _base_checkpoint(
    *,
    tick_index: int,
    elapsed_ms: int,
    perk_pending: int = 0,
    score_xp: int = 0,
    rng_state: int = 0,
) -> dict[str, object]:
    tick = build_capture_tick(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        score_xp=int(score_xp),
        perk_pending=int(perk_pending),
    )
    payload = msgspec.json.decode(msgspec.json.encode(tick))
    checkpoint = _as_obj_dict(cast(dict[str, object], payload).get("checkpoint"))
    checkpoint["rng_state"] = int(rng_state)
    return checkpoint


def _base_tick(
    *,
    tick_index: int,
    elapsed_ms: int,
    perk_pending: int = 0,
    score_xp: int = 0,
    rng_state: int = 0,
) -> dict[str, object]:
    tick = build_capture_tick(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        score_xp=int(score_xp),
        perk_pending=int(perk_pending),
    )
    row = cast(dict[str, object], msgspec.json.decode(msgspec.json.encode(tick)))
    checkpoint = _as_obj_dict(row.get("checkpoint"))
    checkpoint["rng_state"] = int(rng_state)
    row["input_approx"] = [_base_input_approx(**{})]
    row["input_player_keys"] = [_base_input_player_keys(**{})]
    # Keep legacy sparse snapshot defaults used by these conversion tests.
    row["before"] = _base_snapshot()
    row["after"] = _base_snapshot()
    return row


def _sample_creature(*, index: int = 5) -> dict[str, object]:
    row = _clone_dict(_DEFAULT_CAPTURE_CREATURE_SAMPLE)
    row.update(
        {
            "index": int(index),
            "pos": {"x": 10.0, "y": 20.0},
            "link_index": -733,
            "ai_mode": 7,
            "heading": 1.5,
            "target_heading": 1.6,
            "orbit_angle": 0.25,
            "orbit_radius": 10.0,
            "ai7_timer_ms": -733,
        },
    )
    return row


def _sample_projectile(*, index: int = 7) -> dict[str, object]:
    row = _clone_dict(_DEFAULT_CAPTURE_PROJECTILE_SAMPLE)
    row.update(
        {
            "index": int(index),
            "angle": 0.5,
            "pos": {"x": 15.0, "y": 25.0},
            "vel": {"x": 3.0, "y": -2.0},
            "type_id": 1,
            "life_timer": 0.9,
            "damage_pool": 12.0,
            "hit_radius": 9.0,
            "base_damage": 5.0,
        },
    )
    return row


def _sample_secondary_projectile(*, index: int = 9) -> dict[str, object]:
    row = _clone_dict(_DEFAULT_CAPTURE_SECONDARY_PROJECTILE_SAMPLE)
    row.update(
        {
            "index": int(index),
            "pos": {"x": 17.0, "y": 27.0},
            "life_timer": 0.8,
            "angle": 0.2,
            "vel": {"x": 1.0, "y": -1.0},
            "trail_timer": 0.1,
            "type_id": 3,
            "target_id": -1,
        },
    )
    return row


def _sample_bonus(*, index: int = 2) -> dict[str, object]:
    row = _clone_dict(_DEFAULT_CAPTURE_BONUS_SAMPLE)
    row.update(
        {
            "index": int(index),
            "bonus_id": 6,
            "state": 0,
            "time_left": 10.0,
            "time_max": 10.0,
            "pos": {"x": 30.0, "y": 40.0},
            "amount_f32": 0.0,
            "amount_i32": 0,
        },
    )
    return row


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    try:
        typed_ticks = [msgspec.convert(tick, type=CaptureTick, strict=True) for tick in ticks]
    except msgspec.ValidationError:
        # Some conversion tests intentionally exercise invalid/incomplete capture payloads.
        capture = build_capture_file(ticks=[], session_id="session-1")
        payload = capture_file_to_dict(capture)
        payload["ticks"] = ticks
        return payload
    capture = build_capture_file(ticks=typed_ticks, session_id="session-1")
    return capture_file_to_dict(capture)


def _normalize_rng_head_rows(rows: list[object]) -> list[object]:
    out: list[object] = []
    for row in rows:
        if isinstance(row, dict):
            out.append(_base_rng_head_entry(**cast(dict[str, object], row)))
            continue
        out.append(row)
    return out


def _int_or_default(value: object, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    return int(default)


def _base_creature_lifecycle_row(**kwargs: object) -> dict[str, object]:
    row = {
        "index": -1,
        "active": True,
        "active_flag": None,
        "state_flag": None,
        "type_id": None,
        "hp": None,
        "hitbox_size": None,
        "pos": {"x": 0.0, "y": 0.0},
        "flags": None,
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


def _normalize_event_head_for_strict_schema(head: dict[str, object]) -> dict[str, object]:
    head_type = str(head.get("type", ""))
    data_obj = head.get("data")
    data = cast(dict[str, object], data_obj) if isinstance(data_obj, dict) else {}

    if head_type == "state_transition":
        before_obj = data.get("before")
        before = cast(dict[str, object], before_obj) if isinstance(before_obj, dict) else {}
        after_obj = data.get("after")
        after = cast(dict[str, object], after_obj) if isinstance(after_obj, dict) else {}
        target_state = data.get("target_state")
        if not isinstance(target_state, int):
            if isinstance(after.get("id"), int):
                target_state = int(cast(int, after.get("id")))
            elif isinstance(before.get("id"), int):
                target_state = int(cast(int, before.get("id")))
            else:
                target_state = -1
        return {
            "type": "state_transition",
            "data": {
                "target_state": int(target_state),
                "before": {
                    "prev": before.get("prev"),
                    "id": before.get("id"),
                    "pending": before.get("pending"),
                },
                "after": {
                    "prev": after.get("prev"),
                    "id": after.get("id"),
                    "pending": after.get("pending"),
                },
                "caller": data.get("caller"),
                "backtrace": data.get("backtrace"),
            },
        }

    if head_type in {"input_primary_edge", "input_primary_down", "input_any_key"}:
        return {
            "type": head_type,
            "data": {
                "query": str(data.get("query", "")),
                "pressed": bool(data.get("pressed", False)),
                "arg0": data.get("arg0"),
                "caller": data.get("caller"),
                "caller_static": data.get("caller_static"),
                "backtrace": data.get("backtrace"),
                "console_open": data.get("console_open"),
                "primary_latch": data.get("primary_latch"),
            },
        }

    if head_type == "projectile_spawn":
        requested_type_id = data.get("requested_type_id")
        actual_type_id = data.get("actual_type_id")
        return {
            "type": "projectile_spawn",
            "data": {
                "index": _int_or_default(data.get("index"), -1),
                "requested_type_id": int(requested_type_id) if isinstance(requested_type_id, int) else 0,
                "actual_type_id": int(actual_type_id) if isinstance(actual_type_id, int) else None,
                "spawned": data.get("spawned"),
                "owner_id": _int_or_default(data.get("owner_id"), -100),
                "angle_f32": data.get("angle_f32"),
                "pos": cast(dict[str, object], data.get("pos"))
                if isinstance(data.get("pos"), dict)
                else {"x": 0.0, "y": 0.0},
                "type_overridden": data.get("type_overridden"),
                "caller": data.get("caller"),
                "caller_static": data.get("caller_static"),
            },
        }

    if head_type == "secondary_projectile_spawn":
        requested_type_id = data.get("requested_type_id")
        actual_type_id = data.get("actual_type_id")
        return {
            "type": "secondary_projectile_spawn",
            "data": {
                "index": _int_or_default(data.get("index"), -1),
                "requested_type_id": int(requested_type_id) if isinstance(requested_type_id, int) else 0,
                "actual_type_id": int(actual_type_id) if isinstance(actual_type_id, int) else None,
                "spawned": data.get("spawned"),
                "angle_f32": data.get("angle_f32"),
                "pos": cast(dict[str, object], data.get("pos"))
                if isinstance(data.get("pos"), dict)
                else {"x": 0.0, "y": 0.0},
                "type_overridden": data.get("type_overridden"),
                "caller": data.get("caller"),
            },
        }

    if head_type == "projectile_find_query":
        return {
            "type": "projectile_find_query",
            "data": {
                "result_creature_index": data.get("result_creature_index"),
                "result_kind": str(data.get("result_kind", "miss")),
                "start_index": data.get("start_index"),
                "radius_f32": data.get("radius_f32"),
                "query_pos": cast(dict[str, object], data.get("query_pos"))
                if isinstance(data.get("query_pos"), dict)
                else {"x": 0.0, "y": 0.0},
                "projectile_index": data.get("projectile_index"),
                "projectile_owner_id": data.get("projectile_owner_id"),
                "projectile_type_id": data.get("projectile_type_id"),
                "projectile_hit_radius": data.get("projectile_hit_radius"),
                "owner_collision": bool(data.get("owner_collision", False)),
                "player_find_skipped": bool(data.get("player_find_skipped", False)),
                "shock_chain_projectile_id": data.get("shock_chain_projectile_id"),
                "shock_chain_links_left": data.get("shock_chain_links_left"),
                "caller": data.get("caller"),
                "caller_static": data.get("caller_static"),
                "backtrace": data.get("backtrace"),
            },
        }

    if head_type == "projectile_find_hit":
        creature_index = data.get("creature_index")
        result_creature_index = data.get("result_creature_index")
        if not isinstance(result_creature_index, int):
            result_creature_index = int(creature_index) if isinstance(creature_index, int) else None
        if not isinstance(creature_index, int):
            creature_index = int(result_creature_index) if isinstance(result_creature_index, int) else -1
        return {
            "type": "projectile_find_hit",
            "data": {
                "result_creature_index": result_creature_index,
                "result_kind": str(data.get("result_kind", "hit")),
                "start_index": data.get("start_index"),
                "radius_f32": data.get("radius_f32"),
                "query_pos": cast(dict[str, object], data.get("query_pos"))
                if isinstance(data.get("query_pos"), dict)
                else {"x": 0.0, "y": 0.0},
                "projectile_index": data.get("projectile_index"),
                "projectile_owner_id": data.get("projectile_owner_id"),
                "projectile_type_id": data.get("projectile_type_id"),
                "projectile_hit_radius": data.get("projectile_hit_radius"),
                "owner_collision": bool(data.get("owner_collision", False)),
                "player_find_skipped": bool(data.get("player_find_skipped", False)),
                "shock_chain_projectile_id": data.get("shock_chain_projectile_id"),
                "shock_chain_links_left": data.get("shock_chain_links_left"),
                "caller": data.get("caller"),
                "caller_static": data.get("caller_static"),
                "backtrace": data.get("backtrace"),
                "creature_index": int(creature_index),
                "creature": data.get("creature"),
                "corpse_hit": data.get("corpse_hit"),
            },
        }

    if head_type == "creature_spawn":
        return {
            "type": "creature_spawn",
            "data": {
                "template_id": _int_or_default(data.get("template_id"), -1),
                "pos": cast(dict[str, object], data.get("pos")) if isinstance(data.get("pos"), dict) else {"x": 0.0, "y": 0.0},
                "heading": data.get("heading"),
                "ret_ptr": data.get("ret_ptr"),
                "caller": data.get("caller"),
                "caller_static": data.get("caller_static"),
            },
        }

    if head_type == "quest_timeline_delta":
        return {
            "type": "quest_timeline_delta",
            "data": {
                "quest_spawn_timeline": data.get("quest_spawn_timeline"),
                "quest_spawn_stall_timer_ms": data.get("quest_spawn_stall_timer_ms"),
                "creature_active_count": data.get("creature_active_count"),
                "quest_transition_timer_ms": data.get("quest_transition_timer_ms"),
            },
        }

    if head_type == "creature_lifecycle":
        added_raw = data.get("added_head")
        removed_raw = data.get("removed_head")
        added_rows = cast(list[object], added_raw) if isinstance(added_raw, list) else []
        removed_rows = cast(list[object], removed_raw) if isinstance(removed_raw, list) else []

        normalized_added: list[dict[str, object]] = []
        for row in added_rows:
            if isinstance(row, dict):
                normalized_added.append(_base_creature_lifecycle_row(**cast(dict[str, object], row)))
        normalized_removed: list[dict[str, object]] = []
        for row in removed_rows:
            if isinstance(row, dict):
                normalized_removed.append(_base_creature_lifecycle_row(**cast(dict[str, object], row)))

        return {
            "type": "creature_lifecycle",
            "data": {
                "before_count": data.get("before_count"),
                "after_count": data.get("after_count"),
                "before_hash": data.get("before_hash"),
                "after_hash": data.get("after_hash"),
                "added_total": _int_or_default(data.get("added_total"), len(normalized_added)),
                "removed_total": _int_or_default(data.get("removed_total"), len(normalized_removed)),
                "added_ids": data.get("added_ids")
                if isinstance(data.get("added_ids"), list)
                else [_int_or_default(row.get("index"), -1) for row in normalized_added],
                "removed_ids": data.get("removed_ids")
                if isinstance(data.get("removed_ids"), list)
                else [_int_or_default(row.get("index"), -1) for row in normalized_removed],
                "added_overflow": _int_or_default(data.get("added_overflow"), 0),
                "removed_overflow": _int_or_default(data.get("removed_overflow"), 0),
                "added_head": normalized_added,
                "removed_head": normalized_removed,
            },
        }

    if head_type == "creature_update_micro":
        event_kind = str(data.get("event_kind", ""))
        if event_kind == "angle_approach":
            return {
                "type": "creature_update_micro",
                "data": {
                    "event_kind": "angle_approach",
                    "slot": _int_or_default(data.get("slot"), -1),
                    "angle_ptr": data.get("angle_ptr"),
                    "angle_in": data.get("angle_in"),
                    "angle_out": data.get("angle_out"),
                    "target": data.get("target"),
                    "target_effective": data.get("target_effective"),
                    "rate": data.get("rate"),
                    "delta_to_target_direct": data.get("delta_to_target_direct"),
                    "delta_to_target_effective": data.get("delta_to_target_effective"),
                    "step_delta": data.get("step_delta"),
                    "branch": data.get("branch"),
                    "before": data.get("before"),
                    "after": data.get("after"),
                },
            }
        return {
            "type": "creature_update_micro",
            "data": {
                "event_kind": "creature_update_window",
                "slot": _int_or_default(data.get("slot"), -1),
                "before": data.get("before"),
                "after": data.get("after"),
            },
        }

    return head


def _normalize_tick_for_strict_schema(tick: dict[str, object]) -> dict[str, object]:
    normalized = dict(tick)

    event_counts_obj = normalized.get("event_counts")
    if isinstance(event_counts_obj, dict):
        normalized["event_counts"] = _base_event_counts(**cast(dict[str, object], event_counts_obj))

    input_player_keys_obj = normalized.get("input_player_keys")
    if isinstance(input_player_keys_obj, list):
        normalized["input_player_keys"] = [
            _base_input_player_keys(**cast(dict[str, object], row)) if isinstance(row, dict) else row
            for row in input_player_keys_obj
        ]

    input_approx_obj = normalized.get("input_approx")
    if isinstance(input_approx_obj, list):
        normalized["input_approx"] = [
            _base_input_approx(**cast(dict[str, object], row)) if isinstance(row, dict) else row
            for row in input_approx_obj
        ]

    event_heads_obj = normalized.get("event_heads")
    if isinstance(event_heads_obj, list):
        normalized["event_heads"] = [
            _normalize_event_head_for_strict_schema(cast(dict[str, object], row)) if isinstance(row, dict) else row
            for row in event_heads_obj
        ]

    rng_obj = normalized.get("rng")
    if isinstance(rng_obj, dict):
        rng = _base_rng_summary(**cast(dict[str, object], rng_obj))
        rng_map = cast(dict[str, object], rng_obj)
        head_obj = rng_map.get("head")
        if isinstance(head_obj, list):
            rng["head"] = _normalize_rng_head_rows(cast(list[object], head_obj))
        outside_before_head_obj = rng_map.get("outside_before_head")
        if isinstance(outside_before_head_obj, list):
            rng["outside_before_head"] = _normalize_rng_head_rows(cast(list[object], outside_before_head_obj))
        normalized["rng"] = rng

    checkpoint_obj = normalized.get("checkpoint")
    if isinstance(checkpoint_obj, dict):
        checkpoint = dict(cast(dict[str, object], checkpoint_obj))
        rng_marks_obj = checkpoint.get("rng_marks")
        if isinstance(rng_marks_obj, dict):
            rng_marks = dict(cast(dict[str, object], rng_marks_obj))
            rand_head_obj = rng_marks.get("rand_head")
            if isinstance(rand_head_obj, list):
                rng_marks["rand_head"] = _normalize_rng_head_rows(rand_head_obj)
            rand_outside_before_head_obj = rng_marks.get("rand_outside_before_head")
            if isinstance(rand_outside_before_head_obj, list):
                rng_marks["rand_outside_before_head"] = _normalize_rng_head_rows(rand_outside_before_head_obj)
            checkpoint["rng_marks"] = rng_marks
        normalized["checkpoint"] = checkpoint

    return normalized


def _write_capture(path: Path, obj: dict[str, object]) -> None:
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    meta["ticks"] = []
    ticks_obj = obj.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    normalized_ticks = [
        _normalize_tick_for_strict_schema(cast(dict[str, object], tick)) if isinstance(tick, dict) else tick
        for tick in ticks
    ]
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in normalized_ticks
    )
    encoded = ("\n".join(rows) + "\n").encode("utf-8")
    if str(path).endswith(".gz"):
        path.write_bytes(gzip.compress(encoded))
    else:
        path.write_bytes(encoded)


def _write_capture_stream(path: Path, *, meta: dict[str, object], ticks: list[dict[str, object]]) -> None:
    normalized_ticks = [_normalize_tick_for_strict_schema(tick) for tick in ticks]
    normalized_meta = dict(meta)
    normalized_meta["ticks"] = []
    rows = [json.dumps({"event": "capture_meta", "capture": normalized_meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in normalized_ticks
    )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _as_obj_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _tick_checkpoint(tick: dict[str, object]) -> dict[str, object]:
    return _as_obj_dict(tick.get("checkpoint"))


def _tick_diagnostics(tick: dict[str, object]) -> dict[str, object]:
    return _as_obj_dict(tick.get("diagnostics"))


def _tick_rng_marks(tick: dict[str, object]) -> dict[str, object]:
    checkpoint = _tick_checkpoint(tick)
    return _as_obj_dict(checkpoint.get("rng_marks"))


def _tick_player(tick: dict[str, object], player_index: int = 0) -> dict[str, object]:
    checkpoint = _tick_checkpoint(tick)
    players_obj = checkpoint.get("players")
    assert isinstance(players_obj, list)
    player = players_obj[player_index]
    return _as_obj_dict(player)


def _replay_input_flags(replay: Replay, tick_index: int, player_index: int = 0) -> int:
    raw_flags = replay.inputs[tick_index][player_index][3]
    assert isinstance(raw_flags, int | float)
    return int(raw_flags)


def _replay_input_aim_xy(replay: Replay, tick_index: int, player_index: int = 0) -> tuple[float, float]:
    aim = replay.inputs[tick_index][player_index][2]
    assert isinstance(aim, list)
    assert len(aim) >= 2
    aim_x = aim[0]
    aim_y = aim[1]
    assert isinstance(aim_x, int | float)
    assert isinstance(aim_y, int | float)
    return float(aim_x), float(aim_y)


def _minimal_strict_bootstrap_payload() -> dict[str, object]:
    return {
        "tick_index": 0,
        "elapsed_ms": 0,
        "score_xp": 0,
        "perk_pending": 0,
        "perk": {
            "pending_count": 0,
            "choices_dirty": False,
            "choices": [11, 22, 33, 44, 55, 66, 77],
            "player_nonzero_counts": [[]],
        },
        "bonus_timers_ms": {},
        "players": [
            {
                "weapon_id": 1,
                "pos": {"x": 0.0, "y": 0.0},
                "health": 100.0,
                "ammo": 12.0,
                "experience": 0,
                "level": 1,
            },
        ],
        "digital_move_enabled_by_player": [False],
    }


def test_capture_event_payload_helpers_parse_msgspec_payloads() -> None:
    bootstrap_payload = _minimal_strict_bootstrap_payload()
    bootstrap_payload["elapsed_ms"] = 123
    bootstrap = capture_bootstrap_payload_from_event_payload([bootstrap_payload])
    assert bootstrap is not None
    assert bootstrap.elapsed_ms == 123
    assert capture_perk_apply_from_event_payload([{"perk_id": 14}]) == (14, False)
    assert capture_perk_apply_from_event_payload([{"perk_id": 49, "outside_before": True}]) == (49, True)
    assert capture_perk_apply_id_from_event_payload([{"perk_id": 14}]) == 14
    assert capture_perk_pending_from_event_payload([{"perk_pending": 2}]) == 2

    import msgspec

    assert capture_bootstrap_payload_from_event_payload([]) is None
    with pytest.raises(msgspec.ValidationError):
        capture_bootstrap_payload_from_event_payload(["bad"])
    with pytest.raises(msgspec.ValidationError):
        capture_bootstrap_payload_from_event_payload([{"elapsed_ms": 123}])
    with pytest.raises(msgspec.ValidationError):
        capture_perk_apply_from_event_payload([{"perk_pending": 2}])
    with pytest.raises(msgspec.ValidationError):
        capture_perk_apply_id_from_event_payload([{"perk_pending": 2}])
    with pytest.raises(msgspec.ValidationError):
        capture_perk_pending_from_event_payload([{"perk_id": 14}])


def test_load_capture_supports_plain_json_and_gz(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])

    plain = tmp_path / "capture.json"
    zipped = tmp_path / "capture.json.gz"
    _write_capture(plain, obj)
    _write_capture(zipped, obj)

    capture_plain = load_capture(plain)
    capture_zipped = load_capture(zipped)

    assert capture_plain.script == "gameplay_diff_capture"
    assert capture_zipped.script == "gameplay_diff_capture"
    assert len(capture_plain.ticks) == 1
    assert len(capture_zipped.ticks) == 1


def test_load_capture_rejects_missing_capture_format_version(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj.pop("capture_format_version", None)
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(CaptureError, match="invalid capture file"):
        load_capture(path)


def test_load_capture_rejects_unsupported_capture_format_version(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj["capture_format_version"] = int(CAPTURE_FORMAT_VERSION) - 1
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(ValueError, match="unsupported capture format version"):
        load_capture(path)


def test_load_capture_rejects_f32_token_strings(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    player0 = _tick_player(tick)
    pos = _as_obj_dict(player0.get("pos"))
    pos["x"] = "f32:3f800000"
    player0["health"] = "f32:42c80000"
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_rejects_legacy_canonical_json(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(obj, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_accepts_projectile_find_query_event_head(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["event_counts"] = _base_event_counts(projectile_find_query=1)
    tick["event_heads"] = [
        {
            "type": "projectile_find_query",
            "data": {
                "result_creature_index": None,
                "result_kind": "miss",
                "caller_static": "0x00420e52",
            },
        },
    ]
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    assert capture.ticks[0].event_counts.projectile_find_query == 1
    assert capture.ticks[0].event_heads
    head = capture.ticks[0].event_heads[0]
    assert not isinstance(head, CaptureEventHeadPerkApply)
    assert isinstance(head, CaptureEventHeadProjectileFindQuery)
    assert head.data.result_kind == "miss"


def test_load_capture_supports_jsonl_stream_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    _write_capture_stream(path, meta=meta, ticks=[tick])

    capture = load_capture(path)

    assert capture.script == "gameplay_diff_capture"
    assert len(capture.ticks) == 1
    assert int(capture.ticks[0].tick_index) == 0


def test_load_capture_accepts_quest_stage_tick_fields(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["mode_hint"] = "quest_mode_update"
    tick["game_mode_id"] = int(GameMode.QUESTS)
    tick["quest_stage_major"] = 2
    tick["quest_stage_minor"] = 7
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    assert capture.script == "gameplay_diff_capture"
    assert len(capture.ticks) == 1
    loaded_tick = capture.ticks[0]
    assert int(loaded_tick.game_mode_id) == int(GameMode.QUESTS)
    assert int(loaded_tick.quest_stage_major) == 2
    assert int(loaded_tick.quest_stage_minor) == 7


def test_convert_capture_to_replay_infers_quest_level_from_tick_stage(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["mode_hint"] = "quest_mode_update"
    tick["game_mode_id"] = int(GameMode.QUESTS)
    tick["quest_stage_major"] = 2
    tick["quest_stage_minor"] = 4
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0xBEEF)

    assert int(replay.header.game_mode_id) == int(GameMode.QUESTS)
    assert str(replay.header.quest_level) == "2.4"


def test_convert_capture_to_replay_raises_when_game_mode_unavailable(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["mode_hint"] = ""
    tick["game_mode_id"] = -1
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    with pytest.raises(ValueError, match="cannot infer replay game_mode_id"):
        convert_capture_to_replay(capture, seed=0)


def test_convert_capture_to_replay_raises_when_status_unlock_missing(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    status = _as_obj_dict(_tick_checkpoint(tick).get("status"))
    status["quest_unlock_index"] = -1
    status["quest_unlock_index_full"] = -1
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    with pytest.raises(ValueError, match="cannot infer replay status unlock indices"):
        convert_capture_to_replay(capture, seed=0)


def test_convert_capture_to_replay_rejects_non_positive_player_count_override(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    with pytest.raises(ValueError, match="player_count must be > 0"):
        convert_capture_to_replay(capture, seed=0, player_count=0)


def test_load_capture_stream_accepts_known_config_fields(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    meta["config"] = _base_config(
        out_path="capture.json",
        split_quest_files=True,
        quest_out_dir="C:\\share\\frida",
        quest_out_prefix="gameplay_diff_capture.quest_",
        capture_profile="exhaustive_default",
        config_env_overrides=["CRIMSON_FRIDA_STATES", "CRIMSON_FRIDA_OUT_PATH"],
        log_mode="truncate",
        console_all_events=True,
        console_events=["start", "ready", "capture_shutdown"],
        include_caller=False,
    )
    _write_capture_stream(path, meta=meta, ticks=[tick])

    capture = load_capture(path)

    assert capture.script == "gameplay_diff_capture"
    assert capture.config.out_path == "capture.json"
    assert capture.config.split_quest_files is True
    assert capture.config.quest_out_dir == "C:\\share\\frida"
    assert capture.config.quest_out_prefix == "gameplay_diff_capture.quest_"
    assert capture.config.capture_profile == "exhaustive_default"
    assert capture.config.config_env_overrides == ["CRIMSON_FRIDA_STATES", "CRIMSON_FRIDA_OUT_PATH"]
    assert capture.config.console_all_events is True
    assert capture.config.console_events == ["start", "ready", "capture_shutdown"]
    assert capture.config.include_caller is False
    assert len(capture.ticks) == 1


def test_load_capture_stream_rejects_unknown_config_fields(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    config = _base_config(
        out_path="capture.json",
        log_mode="truncate",
    )
    config["future_knob"] = 12345
    meta["config"] = config
    _write_capture_stream(path, meta=meta, ticks=[tick])

    with pytest.raises(CaptureError, match="invalid capture file"):
        load_capture(path)


def test_summarize_capture_health_flags_missing_micro_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    summary = summarize_capture_health(capture)

    assert summary["ok_for_movement_root_cause"] is False
    issues = cast("list[str]", summary["issues"])
    assert "creature_update_micro_rows == 0" in issues
    assert "creature_update_micro_angle_rows == 0" in issues
    assert "creature_update_micro_window_rows == 0" in issues


def test_summarize_capture_health_counts_micro_and_lifecycle_lineage(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=7, elapsed_ms=133)
    tick["event_counts"] = _base_event_counts(mode_tick=1)
    tick["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
        },
    ]
    tick["event_heads"] = [
        {
            "type": "creature_update_micro",
            "data": {"event_kind": "angle_approach", "slot": 3},
        },
        {
            "type": "creature_update_micro",
            "data": {"event_kind": "creature_update_window", "slot": 3},
        },
        {
            "type": "creature_lifecycle",
            "data": {
                "added_head": [{"index": 3, "ai_mode": 7, "link_index": 12}],
                "removed_head": [],
            },
        },
    ]
    tick["samples"] = {
        "creatures": [_sample_creature(index=3)],
        "projectiles": [],
        "secondary_projectiles": [],
        "bonuses": [],
    }
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    summary = summarize_capture_health(capture)
    metrics = cast("dict[str, object]", summary["metrics"])

    assert summary["ok_for_movement_root_cause"] is True
    assert metrics["key_rows_with_any_signal"] == 1
    assert metrics["sample_creature_rows"] == 1
    assert metrics["sample_creature_rows_with_ai_lineage"] == 1
    assert metrics["creature_lifecycle_rows"] == 1
    assert metrics["creature_lifecycle_rows_with_ai_lineage"] == 1
    assert metrics["creature_update_micro_rows"] == 2
    assert metrics["creature_update_micro_angle_rows"] == 1
    assert metrics["creature_update_micro_window_rows"] == 1
    assert metrics["mode_tick_event_count_total"] == 1


def test_load_capture_accepts_player_fire_debug_payloads(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    debug = _as_obj_dict(_tick_checkpoint(tick).get("debug"))
    debug["player_fire"] = {
        "event_count_player_fire": 3,
        "top_direct_events_by_player": [{"key": "0", "count": 1}],
        "top_fallback_events_by_player": [{"key": "0", "count": 2}],
        "top_player_projectile_spawns_by_player": [{"key": "0", "count": 3}],
    }
    diagnostics = _tick_diagnostics(tick)
    diagnostics["player_fire"] = {
        "event_count_player_fire": 4,
        "top_direct_events_by_player": [{"key": "0", "count": 4}],
        "top_fallback_events_by_player": [],
        "top_player_projectile_spawns_by_player": [],
    }
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json.gz"
    _write_capture(path, obj)

    capture = load_capture(path)

    assert capture.ticks[0].checkpoint.debug.player_fire is not None
    assert capture.ticks[0].checkpoint.debug.player_fire.event_count_player_fire == 3
    assert capture.ticks[0].diagnostics.player_fire is not None
    assert capture.ticks[0].diagnostics.player_fire.event_count_player_fire == 4


def test_load_capture_stream_rejects_truncated_last_line(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True),
        '{"event":"tick","tick"',
    ]
    path.write_text("\n".join(rows), encoding="utf-8")

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_stream_rejects_legacy_capture_end_row(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = {k: v for k, v in obj.items() if k != "ticks"}
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "capture_end", "reason": "manual_stop", "ticks_written": 1}, separators=(",", ":")),
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_rejects_unknown_fields(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    obj["unexpected"] = 1
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_accepts_strict_typed_sample_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    tick["samples"] = {
        "creatures": [_sample_creature()],
        "projectiles": [_sample_projectile()],
        "secondary_projectiles": [_sample_secondary_projectile()],
        "bonuses": [_sample_bonus()],
    }
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)

    samples = capture.ticks[0].samples
    assert samples is not None
    assert len(samples.creatures) == 1
    assert len(samples.projectiles) == 1
    assert len(samples.secondary_projectiles) == 1
    assert len(samples.bonuses) == 1
    creature = samples.creatures[0]
    assert creature.ai_mode == 7
    assert creature.link_index == -733
    assert creature.ai7_timer_ms == -733
    assert_float_close(creature.orbit_radius, 10.0)


def test_load_capture_rejects_incomplete_sample_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    bad_creature = _sample_creature()
    del bad_creature["collision_flag"]
    tick["samples"] = {
        "creatures": [bad_creature],
        "projectiles": [],
        "secondary_projectiles": [],
        "bonuses": [],
    }
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_rejects_non_canonical_extension(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    path = tmp_path / "capture.jsonl"
    _write_capture(path, obj)

    with pytest.raises(CaptureError):
        load_capture(path)


def test_convert_capture_to_checkpoints_roundtrip(tmp_path: Path) -> None:
    obj = _capture_obj(
        ticks=[
            _base_tick(tick_index=0, elapsed_ms=16, score_xp=10, rng_state=100),
            _base_tick(tick_index=2, elapsed_ms=48, score_xp=30, rng_state=200),
        ],
    )
    path = tmp_path / "capture.json.gz"
    _write_capture(path, obj)

    capture = load_capture(path)
    checkpoints = convert_capture_to_checkpoints(capture)
    blob = dump_checkpoints(checkpoints)
    loaded = load_checkpoints(blob)

    assert loaded.sample_rate == 2
    assert len(loaded.checkpoints) == 2
    assert loaded.checkpoints[0].tick_index == 0
    assert loaded.checkpoints[1].tick_index == 2


def test_convert_capture_to_replay_from_ticks(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": True,
            "fire_pressed": True,
            "reload_pressed": False,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 1.0,
            "move_dy": -1.0,
            "aim_x": 540.0,
            "aim_y": 500.0,
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0xBEEF, tick_rate=75)

    assert replay.header.game_mode_id == int(GameMode.SURVIVAL)
    assert replay.header.seed == 0xBEEF
    assert replay.header.tick_rate == 75
    assert len(replay.inputs) == 1
    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, _reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is True


def test_convert_capture_to_replay_heading_fallback_uses_checkpoint_pos(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 0.0, "aim_y": 0.0, "aim_heading": 0.0})]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    aim_x, aim_y = _replay_input_aim_xy(replay, 0, 0)
    expected = Vec2(512.0, 512.0) + Vec2.from_heading(0.0) * 256.0
    assert_float_close(aim_x, expected.x)
    assert_float_close(aim_y, expected.y)


def test_convert_capture_to_replay_does_not_fallback_to_primary_query_stats(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_queries"] = {
        "stats": {
            "primary_edge": {"calls": 1, "true_calls": 1},
            "primary_down": {"calls": 1, "true_calls": 1},
            "any_key": {"calls": 0, "true_calls": 0},
        },
        "query_hash": "",
    }
    tick0["input_player_keys"] = [_base_input_player_keys(**{"player_index": 0})]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 540.0, "aim_y": 500.0, "reload_active": True}),
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_infers_pending_drop_events(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=2)
    tick1 = _base_tick(tick_index=1, elapsed_ms=32, perk_pending=1)
    tick2 = _base_tick(tick_index=2, elapsed_ms=48, perk_pending=1)

    obj = _capture_obj(ticks=[tick0, tick1, tick2])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    kinds = [
        type(event).__name__ if not isinstance(event, UnknownEvent) else str(event.kind) for event in replay.events
    ]
    assert CAPTURE_BOOTSTRAP_EVENT_KIND in kinds
    assert CAPTURE_PERK_PENDING_EVENT_KIND in kinds
    assert "PerkMenuOpenEvent" in kinds


def test_convert_capture_to_replay_infers_pending_drop_events_from_perk_delta(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=-1)
    tick1 = _base_tick(tick_index=1, elapsed_ms=32, perk_pending=-1)
    tick2 = _base_tick(tick_index=2, elapsed_ms=48, perk_pending=-1)

    tick0["event_heads"] = [
        {
            "type": "perk_delta",
            "data": {
                "perk_jinxed_proc_timer_s": None,
                "perk_lean_mean_exp_tick_timer_s": None,
                "perk_doctor_target_creature_id": None,
                "perk_pending_count": 1,
            },
        },
    ]
    tick1["event_heads"] = [
        {
            "type": "perk_delta",
            "data": {
                "perk_jinxed_proc_timer_s": None,
                "perk_lean_mean_exp_tick_timer_s": None,
                "perk_doctor_target_creature_id": None,
                "perk_pending_count": 0,
            },
        },
    ]
    tick2["event_heads"] = [
        {
            "type": "perk_delta",
            "data": {
                "perk_jinxed_proc_timer_s": None,
                "perk_lean_mean_exp_tick_timer_s": None,
                "perk_doctor_target_creature_id": None,
                "perk_pending_count": 0,
            },
        },
    ]

    obj = _capture_obj(ticks=[tick0, tick1, tick2])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    pending_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_PERK_PENDING_EVENT_KIND
    ]
    assert [event.tick_index for event in pending_events] == [0, 1]
    assert [capture_perk_pending_from_event_payload(list(event.payload)) for event in pending_events] == [1, 0]

    kinds = [
        type(event).__name__ if not isinstance(event, UnknownEvent) else str(event.kind) for event in replay.events
    ]
    assert "PerkMenuOpenEvent" in kinds


def test_convert_capture_to_replay_skips_menu_open_for_terminal_pending_drop_transition(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=2)
    tick0["event_heads"] = [
        {
            "type": "state_transition",
            "data": {
                "target_state": 12,
                "before": {"id": 9},
                "after": {"id": 12},
            },
        },
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32, perk_pending=0)

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    pending_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_PERK_PENDING_EVENT_KIND
    ]
    assert [event.tick_index for event in pending_events] == [0, 1]
    assert [capture_perk_pending_from_event_payload(list(event.payload)) for event in pending_events] == [2, 0]
    assert not any(isinstance(event, PerkMenuOpenEvent) for event in replay.events)


def test_convert_capture_to_replay_bootstrap_payload_includes_perk_snapshot(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=3)
    checkpoint = _tick_checkpoint(tick0)
    checkpoint["perk"] = {
        "pending_count": 3,
        "choices_dirty": False,
        "choices": [11, 22, 33, 44, 55, 66, 77],
        "player_nonzero_counts": [],
    }

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.perk_pending == 3
    assert payload.perk.pending_count == 3
    assert payload.perk.choices_dirty is False
    assert payload.perk.choices == [11, 22, 33, 44, 55, 66, 77]
    assert payload.perk.player_nonzero_counts == []


def test_apply_capture_bootstrap_payload_marks_perk_counts_unknown_when_nonzero_counts_are_missing() -> None:
    state = GameplayState()
    players = [PlayerState(index=0, pos=Vec2())]
    payload = _minimal_strict_bootstrap_payload()

    apply_capture_bootstrap_payload(payload, state=state, players=players)

    assert state.perk_selection.capture_player_perk_counts_known is False


def test_convert_capture_to_replay_bootstrap_payload_includes_quest_session_timers(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=10, elapsed_ms=1600)
    tick0["mode_hint"] = "quest_mode_update"
    tick0["game_mode_id"] = int(GameMode.QUESTS)
    tick0["event_heads"] = [
        {
            "type": "quest_timeline_delta",
            "data": {
                "quest_spawn_timeline": 1718,
                "quest_spawn_stall_timer_ms": 4745,
                "quest_transition_timer_ms": -1,
            },
        },
    ]

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.quest_session is not None
    assert_float_close(payload.quest_session.spawn_timeline_ms, 1718.0)
    assert_float_close(payload.quest_session.no_creatures_timer_ms, 4745.0)
    assert_float_close(payload.quest_session.completion_transition_ms, -1.0)


def test_convert_capture_to_replay_bootstrap_payload_prefers_before_player_runtime_snapshot(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=42, elapsed_ms=7000, perk_pending=2, score_xp=11)
    _tick_player(tick0)["ammo"] = 11.0
    _tick_player(tick0)["experience"] = 11
    tick0["before"] = _base_snapshot(
        globals=_base_snapshot_globals(
            time_played_ms=6951,
            perk_pending_count=1,
            bonus_weapon_power_up_timer=0.25,
        ),
        players=[
            {
                "index": 0,
                "pos_x": 500.0,
                "pos_y": 501.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 90.0,
                "aim_x": 300.0,
                "aim_y": 320.0,
                "aim_heading": 1.2,
                "weapon_id": 1,
                "clip_size_i32": 0x41400000,
                "clip_size_f32": 12.0,
                "ammo_i32": 0x41400000,
                "ammo_f32": 12.0,
                "reload_active_i32": 1,
                "reload_active_f32": 1.0,
                "reload_timer": 0.5,
                "reload_timer_max": 1.0,
                "shot_cooldown": 0.25,
                "spread_heat": 0.0,
                "experience": 7,
                "level": 2,
                "bonus_timers": {"speed_bonus": 1.2, "shield": 0.5, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 1.36,
                    "man_bomb": 0.0,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 4,
                    "clip_size_i32": 0x41200000,  # 10.0f
                    "reload_active_i32": 1,
                    "ammo_i32": 0x40E00000,  # 7.0f
                    "reload_timer": 0.2,
                    "shot_cooldown": 0.1,
                    "reload_timer_max": 1.2,
                },
            },
        ],
    )

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.elapsed_ms == 6951
    assert payload.perk_pending == 1
    assert payload.score_xp == 7

    assert payload.bonus_timers_ms["4"] == 250

    assert len(payload.players) == 1
    player = payload.players[0]
    assert player.ammo == 12.0
    assert player.experience == 7
    assert player.level == 2
    assert player.clip_size == 12
    assert player.reload_active is True
    assert_float_close(player.reload_timer, 0.5)
    assert_float_close(player.reload_timer_max, 1.0)
    assert_float_close(player.shot_cooldown, 0.25)
    assert_float_close(player.spread_heat, 0.0)
    assert player.bonus_timers_ms == {"speed_bonus": 1200, "shield": 500, "fire_bullets": 0}
    assert player.aim is not None
    assert_float_close(player.aim.x, 300.0)
    assert_float_close(player.aim.y, 320.0)
    assert_float_close(player.aim.heading, 1.2)
    assert player.alt_weapon is not None
    assert player.alt_weapon.weapon_id == 4
    assert player.alt_weapon.clip_size == 10
    assert_float_close(player.alt_weapon.ammo, 7.0)
    assert player.alt_weapon.reload_active is True
    assert_float_close(player.alt_weapon.reload_timer, 0.2)
    assert_float_close(player.alt_weapon.shot_cooldown, 0.1)
    assert_float_close(player.alt_weapon.reload_timer_max, 1.2)
    assert player.perk_timers is not None
    assert set(player.perk_timers.keys()) == {"hot_tempered", "man_bomb", "living_fortress", "fire_cough"}
    assert_float_close(player.perk_timers["hot_tempered"], 1.36)
    assert_float_close(player.perk_timers["man_bomb"], 0.0)
    assert_float_close(player.perk_timers["living_fortress"], 0.0)
    assert_float_close(player.perk_timers["fire_cough"], 0.0)


def test_convert_capture_to_replay_bootstrap_payload_infers_perk_intervals_from_timer_wrap(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=10, elapsed_ms=1000)
    tick1 = _base_tick(tick_index=11, elapsed_ms=1083)
    tick0["before"] = _base_snapshot(
        players=[
            {
                "index": 0,
                "pos_x": 0.0,
                "pos_y": 0.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 100.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": 0.0,
                "weapon_id": 1,
                "clip_size_i32": 0,
                "clip_size_f32": 0.0,
                "ammo_i32": 0,
                "ammo_f32": 0.0,
                "reload_active_i32": 0,
                "reload_active_f32": 0.0,
                "reload_timer": 0.0,
                "reload_timer_max": 0.0,
                "shot_cooldown": 0.0,
                "spread_heat": 0.0,
                "experience": 0,
                "level": 1,
                "bonus_timers": {"speed_bonus": 0.0, "shield": 0.0, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 1.3659999,
                    "man_bomb": 0.0,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 0,
                    "clip_size_i32": 0,
                    "reload_active_i32": 0,
                    "ammo_i32": 0,
                    "reload_timer": 0.0,
                    "shot_cooldown": 0.0,
                    "reload_timer_max": 0.0,
                },
            },
        ],
    )
    tick1["before"] = _base_snapshot(
        players=[
            {
                "index": 0,
                "pos_x": 0.0,
                "pos_y": 0.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 100.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": 0.0,
                "weapon_id": 1,
                "clip_size_i32": 0,
                "clip_size_f32": 0.0,
                "ammo_i32": 0,
                "ammo_f32": 0.0,
                "reload_active_i32": 0,
                "reload_active_f32": 0.0,
                "reload_timer": 0.0,
                "reload_timer_max": 0.0,
                "shot_cooldown": 0.0,
                "spread_heat": 0.0,
                "experience": 0,
                "level": 1,
                "bonus_timers": {"speed_bonus": 0.0, "shield": 0.0, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 0.0489999,
                    "man_bomb": 0.0,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 0,
                    "clip_size_i32": 0,
                    "reload_active_i32": 0,
                    "ammo_i32": 0,
                    "reload_timer": 0.0,
                    "shot_cooldown": 0.0,
                    "reload_timer_max": 0.0,
                },
            },
        ],
    )
    _as_obj_dict(_tick_checkpoint(tick0)["perk"])["player_nonzero_counts"] = [[[31, 1]]]
    _as_obj_dict(_tick_checkpoint(tick1)["perk"])["player_nonzero_counts"] = [[[31, 1]]]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)
    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None

    assert payload.perk_intervals is not None
    perk_intervals = payload.perk_intervals
    assert_float_close(perk_intervals["hot_tempered"], 1.4)


def test_convert_capture_to_replay_bootstrap_payload_ignores_inactive_timer_reset_interval_inference(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=10, elapsed_ms=1000)
    tick1 = _base_tick(tick_index=11, elapsed_ms=1083)
    tick0["before"] = _base_snapshot(
        players=[
            {
                "index": 0,
                "pos_x": 0.0,
                "pos_y": 0.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 100.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": 0.0,
                "weapon_id": 1,
                "clip_size_i32": 0,
                "clip_size_f32": 0.0,
                "ammo_i32": 0,
                "ammo_f32": 0.0,
                "reload_active_i32": 0,
                "reload_active_f32": 0.0,
                "reload_timer": 0.0,
                "reload_timer_max": 0.0,
                "shot_cooldown": 0.0,
                "spread_heat": 0.0,
                "experience": 0,
                "level": 1,
                "bonus_timers": {"speed_bonus": 0.0, "shield": 0.0, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 2.63,
                    "man_bomb": 0.0,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 0,
                    "clip_size_i32": 0,
                    "reload_active_i32": 0,
                    "ammo_i32": 0,
                    "reload_timer": 0.0,
                    "shot_cooldown": 0.0,
                    "reload_timer_max": 0.0,
                },
            },
        ],
    )
    tick1["before"] = _base_snapshot(
        players=[
            {
                "index": 0,
                "pos_x": 0.0,
                "pos_y": 0.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 100.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": 0.0,
                "weapon_id": 1,
                "clip_size_i32": 0,
                "clip_size_f32": 0.0,
                "ammo_i32": 0,
                "ammo_f32": 0.0,
                "reload_active_i32": 0,
                "reload_active_f32": 0.0,
                "reload_timer": 0.0,
                "reload_timer_max": 0.0,
                "shot_cooldown": 0.0,
                "spread_heat": 0.0,
                "experience": 0,
                "level": 1,
                "bonus_timers": {"speed_bonus": 0.0, "shield": 0.0, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 0.0,
                    "man_bomb": 0.0,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 0,
                    "clip_size_i32": 0,
                    "reload_active_i32": 0,
                    "ammo_i32": 0,
                    "reload_timer": 0.0,
                    "shot_cooldown": 0.0,
                    "reload_timer_max": 0.0,
                },
            },
        ],
    )
    _as_obj_dict(_tick_checkpoint(tick0)["perk"])["player_nonzero_counts"] = [[]]
    _as_obj_dict(_tick_checkpoint(tick1)["perk"])["player_nonzero_counts"] = [[]]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)
    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None

    if payload.perk_intervals is not None:
        assert "hot_tempered" not in payload.perk_intervals


def test_convert_capture_to_replay_bootstrap_payload_does_not_infer_man_bomb_from_timer_drop(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=10, elapsed_ms=1000)
    tick1 = _base_tick(tick_index=11, elapsed_ms=1076)
    tick0["before"] = _base_snapshot(
        players=[
            {
                "index": 0,
                "pos_x": 0.0,
                "pos_y": 0.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 100.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": 0.0,
                "weapon_id": 1,
                "clip_size_i32": 0,
                "clip_size_f32": 0.0,
                "ammo_i32": 0,
                "ammo_f32": 0.0,
                "reload_active_i32": 0,
                "reload_active_f32": 0.0,
                "reload_timer": 0.0,
                "reload_timer_max": 0.0,
                "shot_cooldown": 0.0,
                "spread_heat": 0.0,
                "experience": 0,
                "level": 1,
                "bonus_timers": {"speed_bonus": 0.0, "shield": 0.0, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 0.0,
                    "man_bomb": 1.225,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 0,
                    "clip_size_i32": 0,
                    "reload_active_i32": 0,
                    "ammo_i32": 0,
                    "reload_timer": 0.0,
                    "shot_cooldown": 0.0,
                    "reload_timer_max": 0.0,
                },
            },
        ],
    )
    tick1["before"] = _base_snapshot(
        players=[
            {
                "index": 0,
                "pos_x": 0.0,
                "pos_y": 0.0,
                "move_dx": 0.0,
                "move_dy": 0.0,
                "health": 100.0,
                "aim_x": 0.0,
                "aim_y": 0.0,
                "aim_heading": 0.0,
                "weapon_id": 1,
                "clip_size_i32": 0,
                "clip_size_f32": 0.0,
                "ammo_i32": 0,
                "ammo_f32": 0.0,
                "reload_active_i32": 0,
                "reload_active_f32": 0.0,
                "reload_timer": 0.0,
                "reload_timer_max": 0.0,
                "shot_cooldown": 0.0,
                "spread_heat": 0.0,
                "experience": 0,
                "level": 1,
                "bonus_timers": {"speed_bonus": 0.0, "shield": 0.0, "fire_bullets": 0.0},
                "perk_timers": {
                    "hot_tempered": 0.0,
                    "man_bomb": 0.0,
                    "living_fortress": 0.0,
                    "fire_cough": 0.0,
                },
                "alt_weapon": {
                    "weapon_id": 0,
                    "clip_size_i32": 0,
                    "reload_active_i32": 0,
                    "ammo_i32": 0,
                    "reload_timer": 0.0,
                    "shot_cooldown": 0.0,
                    "reload_timer_max": 0.0,
                },
            },
        ],
    )
    _as_obj_dict(_tick_checkpoint(tick0)["perk"])["player_nonzero_counts"] = [[[53, 1]]]
    _as_obj_dict(_tick_checkpoint(tick1)["perk"])["player_nonzero_counts"] = [[[53, 1]]]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)
    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None

    if payload.perk_intervals is not None:
        assert "man_bomb" not in payload.perk_intervals


def test_apply_capture_bootstrap_payload_applies_perk_intervals_and_player_perk_timers() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    payload = _minimal_strict_bootstrap_payload()
    payload["elapsed_ms"] = -1
    payload_players = cast(list[dict[str, object]], payload.get("players"))
    assert payload_players
    payload_players[0]["perk_timers"] = {
        "hot_tempered": 1.36,
        "man_bomb": 0.5,
        "living_fortress": 0.25,
        "fire_cough": 0.75,
    }
    payload["perk_intervals"] = {
        "hot_tempered": 1.4,
        "man_bomb": 6.0,
        "fire_cough": 3.0,
    }

    elapsed = apply_capture_bootstrap_payload(payload, state=state, players=[player])
    assert elapsed is None
    assert_float_close(player.hot_tempered_timer, 1.36)
    assert_float_close(player.man_bomb_timer, 0.5)
    assert_float_close(player.living_fortress_timer, 0.25)
    assert_float_close(player.fire_cough_timer, 0.75)
    assert_float_close(state.perk_intervals.hot_tempered, 1.4)
    assert_float_close(state.perk_intervals.man_bomb, 6.0)
    assert_float_close(state.perk_intervals.fire_cough, 3.0)


def test_convert_capture_to_replay_emits_perk_apply_events(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["perk_apply_in_tick"] = [
        {
            "perk_id": 14,
            "pending_before": 1,
            "pending_after": 0,
            "caller": None,
            "caller_static": None,
            "backtrace": None,
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    perk_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_PERK_APPLY_EVENT_KIND
    ]
    assert len(perk_events) == 1
    assert perk_events[0].tick_index == 0


def test_convert_capture_to_replay_carries_outside_before_pending_bounds(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["perk_apply_outside_before"] = {
        "calls": 1,
        "dropped": 0,
        "head": [
            {
                "perk_id": 16,
                "pending_before": 1,
                "pending_after": 4,
                "caller": None,
                "caller_static": None,
                "backtrace": None,
            },
        ],
    }
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    perk_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_PERK_APPLY_EVENT_KIND
    ]
    assert len(perk_events) == 1
    payload = list(perk_events[0].payload)
    assert capture_perk_apply_from_event_payload(payload) == (16, True)
    assert capture_perk_apply_pending_bounds_from_event_payload(payload) == (1, 4)


@pytest.mark.parametrize("caller_static", ["0x00434373", "0x00426d56"])
def test_convert_capture_to_replay_emits_quest_creature_spawn_events(
    tmp_path: Path,
    caller_static: str,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["mode_hint"] = "quest_mode_update"
    tick0["game_mode_id"] = int(GameMode.QUESTS)
    tick0["event_heads"] = [
        {
            "type": "creature_spawn",
            "data": {
                "template_id": 54,
                "pos": {"x": 434.3393859863281, "y": 455.56573486328125},
                "heading": -4.083981990814209,
                "caller_static": caller_static,
            },
        },
        {
            "type": "creature_lifecycle",
            "data": {
                "added_head": [
                    {
                        "index": 18,
                        "heading": 1.1278764009475708,
                        "target_heading": 0.621416449546814,
                        "ai_mode": 3,
                        "link_index": 0,
                        "hp": 200.0,
                        "hitbox_size": 16.0,
                        "orbit_angle": 0.25,
                        "orbit_radius": 0.5,
                        "flags": 12,
                        "type_id": 2,
                        "pos": {"x": -256.0, "y": 256.0},
                    },
                ],
            },
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    spawn_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_CREATURE_SPAWN_EVENT_KIND
    ]
    assert len(spawn_events) == 1
    assert spawn_events[0].tick_index == 0
    assert capture_creature_spawns_from_event_payload(spawn_events[0].payload) == (
        (54, 434.3393859863281, 455.56573486328125, -4.083981990814209),
    )
    assert capture_creature_spawn_added_head_from_event_payload(spawn_events[0].payload) == (
        (18, 1.1278764009475708, 0.621416449546814, 3, 0),
    )
    rows = capture_creature_spawn_added_head_rows_from_event_payload(spawn_events[0].payload)
    assert rows is not None
    assert len(rows) == 1
    row = rows[0]
    assert row.index == 18
    assert_float_close(row.heading, 1.1278764009475708)
    assert_float_close(row.target_heading, 0.621416449546814)
    assert row.ai_mode == 3
    assert row.link_index == 0
    assert_float_close(row.hp, 200.0)
    assert_float_close(row.hitbox_size, 16.0)
    assert_float_close(row.orbit_angle, 0.25)
    assert_float_close(row.orbit_radius, 0.5)
    assert row.flags == 12
    assert row.type_id == 2
    assert row.pos is not None
    assert_float_close(row.pos.x, -256.0)
    assert_float_close(row.pos.y, 256.0)


def test_convert_capture_to_replay_emits_quest_added_head_without_spawn_rows(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["mode_hint"] = "quest_mode_update"
    tick0["game_mode_id"] = int(GameMode.QUESTS)
    tick0["event_heads"] = [
        {
            "type": "creature_lifecycle",
            "data": {
                "added_head": [
                    {
                        "index": 7,
                        "heading": 0.28999999165534973,
                        "target_heading": 0.521416425704956,
                        "ai_mode": 0,
                        "link_index": 1,
                    },
                ],
            },
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    spawn_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_CREATURE_SPAWN_EVENT_KIND
    ]
    assert len(spawn_events) == 1
    assert capture_creature_spawns_from_event_payload(spawn_events[0].payload) == ()
    assert capture_creature_spawn_added_head_from_event_payload(spawn_events[0].payload) == (
        (7, 0.28999999165534973, 0.521416425704956, 0, 1),
    )


def test_convert_capture_to_replay_emits_state_transition_events(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["event_heads"] = [
        {
            "type": "state_transition",
            "data": {
                "target_state": 12,
                "before": {"id": 9},
                "after": {"id": 12},
            },
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    state_events = [
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_STATE_TRANSITION_EVENT_KIND
    ]
    assert len(state_events) == 1
    assert state_events[0].tick_index == 0
    assert capture_state_transitions_from_event_payload(state_events[0].payload) == ((12, 9, 12),)


def test_convert_capture_to_replay_emits_menu_open_on_state_6_transition(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16, perk_pending=0)
    tick0["event_heads"] = [
        {
            "type": "state_transition",
            "data": {
                "target_state": 6,
                "before": {"id": 9},
                "after": {"id": 6},
            },
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    menu_open_events = [event for event in replay.events if isinstance(event, PerkMenuOpenEvent)]
    assert len(menu_open_events) == 1
    assert menu_open_events[0].tick_index == 0


def test_default_capture_replay_path_derives_expected_name() -> None:
    checkpoints = Path("/tmp/gameplay_diff_capture.crd.chk")
    replay = default_capture_replay_path(checkpoints)
    assert replay.name == "gameplay_diff_capture.crd"


def test_default_capture_replay_path_accepts_legacy_sidecar_name() -> None:
    checkpoints = Path("/tmp/gameplay_diff_capture.checkpoints.json.gz")
    replay = default_capture_replay_path(checkpoints)
    assert replay.name == "gameplay_diff_capture.crd"


def test_build_capture_dt_frame_overrides_distributes_gaps(tmp_path: Path) -> None:
    obj = _capture_obj(
        ticks=[
            _base_tick(tick_index=0, elapsed_ms=0),
            _base_tick(tick_index=2, elapsed_ms=40),
            _base_tick(tick_index=5, elapsed_ms=100),
        ],
    )
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert_float_close(overrides[1], 0.02)
    assert_float_close(overrides[2], 0.02)
    assert_float_close(overrides[3], 0.02)
    assert_float_close(overrides[5], 0.02)


def test_build_capture_dt_frame_overrides_prefers_explicit_tick_frame_dt(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms"] = 20.0
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert_float_close(overrides[0], 0.02)


def test_build_capture_dt_frame_overrides_ignores_denormal_frame_dt_ms_and_prefers_i32(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms"] = 1.401298464324817e-43
    tick0["frame_dt_ms_i32"] = 32
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert_float_close(overrides[0], 0.032)


def test_build_capture_dt_frame_overrides_prefers_timing_frame_dt_after_over_i32(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms"] = 30.0
    tick0["frame_dt_ms_i32"] = 30
    diagnostics = _tick_diagnostics(tick0)
    timing = _as_obj_dict(diagnostics.get("timing"))
    timing["frame_dt_after"] = 0.029000001028180122
    tick1 = _base_tick(tick_index=1, elapsed_ms=29)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_overrides(capture, tick_rate=60)

    assert_float_close(overrides[0], 0.029000001028180122)


def test_build_capture_dt_frame_ms_i32_overrides_uses_explicit_values(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick0["frame_dt_ms_i32"] = 17
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_dt_frame_ms_i32_overrides(capture)

    assert overrides == {0: 17}


def test_build_capture_inter_tick_rand_draws_overrides_uses_checkpoint_marks(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=10, elapsed_ms=0)
    tick1 = _base_tick(tick_index=11, elapsed_ms=16)
    tick2 = _base_tick(tick_index=12, elapsed_ms=32)
    assert isinstance(tick0["checkpoint"], dict)
    assert isinstance(tick1["checkpoint"], dict)
    assert isinstance(tick2["checkpoint"], dict)
    assert isinstance(_tick_rng_marks(tick0), dict)
    assert isinstance(_tick_rng_marks(tick1), dict)
    assert isinstance(_tick_rng_marks(tick2), dict)
    _tick_rng_marks(tick0)["rand_outside_before_calls"] = 7
    _tick_rng_marks(tick1)["rand_outside_before_calls"] = 3
    _tick_rng_marks(tick2)["rand_outside_before_calls"] = -1
    obj = _capture_obj(ticks=[tick0, tick1, tick2])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_inter_tick_rand_draws_overrides(capture)

    assert overrides == {10: 0, 11: 3}


def test_build_capture_inter_tick_rand_draws_overrides_quest_delays_until_first_in_tick_rand(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    tick2 = _base_tick(tick_index=2, elapsed_ms=32)
    tick3 = _base_tick(tick_index=3, elapsed_ms=48)
    for tick in (tick0, tick1, tick2, tick3):
        tick["mode_hint"] = "quest_mode_update"
        tick["game_mode_id"] = int(GameMode.QUESTS)
        assert isinstance(tick["checkpoint"], dict)
        rng_marks = _tick_rng_marks(tick)
        rng_marks["rand_outside_before_calls"] = 1
        rng_marks["rand_calls"] = 0

    assert isinstance(tick0["checkpoint"], dict)
    assert isinstance(_tick_rng_marks(tick0), dict)
    _tick_rng_marks(tick0)["rand_outside_before_calls"] = 24021

    assert isinstance(tick2["checkpoint"], dict)
    assert isinstance(_tick_rng_marks(tick2), dict)
    _tick_rng_marks(tick2)["rand_calls"] = 2

    obj = _capture_obj(ticks=[tick0, tick1, tick2, tick3])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_inter_tick_rand_draws_overrides(capture)

    assert overrides == {0: 0, 1: 0, 2: 0, 3: 1}


def test_build_capture_inter_tick_rand_draws_overrides_quest_nonzero_start_zeroes_seed_tick(
    tmp_path: Path,
) -> None:
    tick10 = _base_tick(tick_index=10, elapsed_ms=0)
    tick11 = _base_tick(tick_index=11, elapsed_ms=16)
    tick12 = _base_tick(tick_index=12, elapsed_ms=32)
    tick13 = _base_tick(tick_index=13, elapsed_ms=48)
    for tick in (tick10, tick11, tick12, tick13):
        tick["mode_hint"] = "quest_mode_update"
        tick["game_mode_id"] = int(GameMode.QUESTS)
        assert isinstance(tick["checkpoint"], dict)
        rng_marks = _tick_rng_marks(tick)
        rng_marks["rand_outside_before_calls"] = 3
        rng_marks["rand_calls"] = 0

    assert isinstance(tick12["checkpoint"], dict)
    assert isinstance(_tick_rng_marks(tick12), dict)
    _tick_rng_marks(tick12)["rand_calls"] = 4

    obj = _capture_obj(ticks=[tick10, tick11, tick12, tick13])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_inter_tick_rand_draws_overrides(capture)

    assert overrides == {10: 0, 11: 0, 12: 0, 13: 3}


def test_build_capture_inter_tick_rand_draws_overrides_returns_none_when_missing(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=0)
    tick1 = _base_tick(tick_index=1, elapsed_ms=16)
    assert isinstance(tick0["checkpoint"], dict)
    assert isinstance(tick1["checkpoint"], dict)
    assert isinstance(_tick_rng_marks(tick0), dict)
    assert isinstance(_tick_rng_marks(tick1), dict)
    _tick_rng_marks(tick0)["rand_outside_before_calls"] = -1
    _tick_rng_marks(tick1)["rand_outside_before_calls"] = -1
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    overrides = build_capture_inter_tick_rand_draws_overrides(capture)

    assert overrides is None


def test_convert_capture_to_replay_raises_when_rng_state_before_missing(tmp_path: Path) -> None:
    seed = 0x1234
    outputs = _crt_rand_outputs(seed, 8)
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    rng_marks = _tick_rng_marks(tick0)
    rng_marks["rand_calls"] = 8
    rng_marks["rand_last"] = outputs[-1]
    rng_marks["rand_head"] = [{"value": int(value), "value_15": int(value)} for value in outputs]

    rng = {
        "calls": 8,
        "last_value": outputs[-1],
        "head": [{"value": int(value), "value_15": int(value)} for value in outputs],
    }
    tick0["rng"] = rng

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    with pytest.raises(ValueError, match="cannot infer replay seed"):
        convert_capture_to_replay(capture)


def test_convert_capture_to_replay_prefers_rng_state_before_seed(tmp_path: Path) -> None:
    seed = 0x8C6978CC
    outputs = _crt_rand_outputs(seed, 8)
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    rng_marks = _tick_rng_marks(tick0)
    rng_marks["rand_calls"] = 8
    rng_marks["rand_last"] = outputs[-1]
    rng_marks["rand_head"] = [
        {
            "value": int(outputs[0]),
            "value_15": int(outputs[0]),
            "state_before_u32": int(seed),
        },
    ]
    tick0["rng"] = {
        "calls": 8,
        "last_value": outputs[-1],
        "head": [
            {
                "value": int(outputs[0]),
                "value_15": int(outputs[0]),
                "state_before_u32": int(seed),
            },
        ],
    }

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture)

    assert replay.header.seed == int(seed)


def test_convert_capture_to_replay_explicit_seed_overrides_inferred_seed(tmp_path: Path) -> None:
    seed = 0x1234
    outputs = _crt_rand_outputs(seed, 8)
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    rng_marks = _tick_rng_marks(tick0)
    rng_marks["rand_calls"] = 8
    rng_marks["rand_last"] = outputs[-1]
    rng_marks["rand_head"] = [{"value": int(value), "value_15": int(value)} for value in outputs]
    tick0["rng"] = {
        "calls": 8,
        "last_value": outputs[-1],
        "head": [{"value": int(value), "value_15": int(value)} for value in outputs],
    }

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0xBEEF)

    assert replay.header.seed == 0xBEEF


def test_convert_capture_to_replay_prefers_input_player_keys_for_digital_move(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
            "move_backward_pressed": False,
            "turn_left_pressed": True,
            "turn_right_pressed": False,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -21.5,
            "move_dy": -7.6,
            "aim_x": 540.0,
            "aim_y": 500.0,
            "fired_events": 0,
            "reload_active": False,
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    move_x, move_y, _aim, _flags = replay.inputs[0][0]
    flags = _replay_input_flags(replay, 0, 0)
    assert move_x == -1.0
    assert move_y == -1.0
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False
    move_forward, move_backward, turn_left, turn_right = unpack_input_move_key_flags(flags)
    assert move_forward is True
    assert move_backward is False
    assert turn_left is True
    assert turn_right is False

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.digital_move_enabled_by_player == [True]


def test_convert_capture_to_replay_ignores_input_approx_for_digital_move_capability(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [_base_input_player_keys(**{"player_index": 0})]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 0.25,
            "move_dy": 0.5,
            "move_mode": 1,
            "move_forward_pressed": True,
            "move_backward_pressed": False,
            "turn_left_pressed": True,
            "turn_right_pressed": False,
            "aim_x": 540.0,
            "aim_y": 500.0,
            "fired_events": 0,
            "reload_active": False,
        },
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    move_x, move_y, _aim, _flags = replay.inputs[0][0]
    flags = _replay_input_flags(replay, 0, 0)
    assert_float_close(move_x, 0.25)
    assert_float_close(move_y, 0.5)
    move_forward, move_backward, turn_left, turn_right = unpack_input_move_key_flags(flags)
    assert move_forward is None
    assert move_backward is None
    assert turn_left is None
    assert turn_right is None

    bootstrap = next(
        event
        for event in replay.events
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND
    )
    payload = capture_bootstrap_payload_from_event_payload(bootstrap.payload)
    assert payload is not None
    assert payload.digital_move_enabled_by_player == [False]


def test_convert_capture_to_replay_conflicting_turn_keys_use_contextual_precedence(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": False,
            "turn_left_pressed": False,
            "turn_right_pressed": True,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 98.0,
            "move_dy": 5.0,
            "aim_x": 306.0,
            "aim_y": 309.0,
        },
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": True,
            "turn_left_pressed": True,
            "turn_right_pressed": True,
        },
    ]
    tick1["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -77.0,
            "move_dy": 11.0,
            "aim_x": 308.0,
            "aim_y": 311.0,
        },
    ]
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    move_x0, move_y0, _aim0, _flags0 = replay.inputs[0][0]
    move_x1, move_y1, _aim1, _flags1 = replay.inputs[1][0]
    flags0 = _replay_input_flags(replay, 0, 0)
    flags1 = _replay_input_flags(replay, 1, 0)
    assert_float_close(move_x0, 1.0)
    assert_float_close(move_y0, 0.0)
    assert_float_close(move_x1, -1.0)
    assert_float_close(move_y1, 1.0)
    assert unpack_input_move_key_flags(flags0) == (False, False, False, True)
    assert unpack_input_move_key_flags(flags1) == (False, True, True, True)


def test_convert_capture_to_replay_conflicting_move_keys_use_contextual_precedence(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": True,
            "turn_left_pressed": False,
            "turn_right_pressed": False,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 4.0,
            "move_dy": 66.0,
            "aim_x": 306.0,
            "aim_y": 309.0,
        },
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
            "move_backward_pressed": True,
            "turn_left_pressed": True,
            "turn_right_pressed": False,
        },
    ]
    tick1["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -8.0,
            "move_dy": -55.0,
            "aim_x": 307.0,
            "aim_y": 310.0,
        },
    ]
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    move_x0, move_y0, _aim0, _flags0 = replay.inputs[0][0]
    move_x1, move_y1, _aim1, _flags1 = replay.inputs[1][0]
    flags0 = _replay_input_flags(replay, 0, 0)
    flags1 = _replay_input_flags(replay, 1, 0)
    assert_float_close(move_x0, 0.0)
    assert_float_close(move_y0, 1.0)
    assert_float_close(move_x1, -1.0)
    assert_float_close(move_y1, -1.0)
    assert unpack_input_move_key_flags(flags0) == (False, True, False, False)
    assert unpack_input_move_key_flags(flags1) == (True, True, True, False)


def test_convert_capture_to_replay_conflicting_keys_ignore_sample_axis_sign(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": False,
            "move_backward_pressed": False,
            "turn_left_pressed": True,
            "turn_right_pressed": True,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": -92.0,
            "move_dy": 8.0,
            "aim_x": 400.0,
            "aim_y": 410.0,
        },
    ]
    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    tick1["input_player_keys"] = [
        {
            "player_index": 0,
            "move_forward_pressed": True,
            "move_backward_pressed": True,
            "turn_left_pressed": False,
            "turn_right_pressed": False,
        },
    ]
    tick1["input_approx"] = [
        {
            "player_index": 0,
            "move_dx": 12.0,
            "move_dy": -73.0,
            "aim_x": 402.0,
            "aim_y": 412.0,
        },
    ]
    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    move_x0, move_y0, _aim0, _flags0 = replay.inputs[0][0]
    move_x1, move_y1, _aim1, _flags1 = replay.inputs[1][0]
    assert_float_close(move_x0, 1.0)
    assert_float_close(move_y0, 0.0)
    assert_float_close(move_x1, 0.0)
    assert_float_close(move_y1, 1.0)


def test_convert_capture_to_replay_uses_player_key_fire_reload_edges(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": True,
            "fire_pressed": True,
            "reload_pressed": True,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "fired_events": 0}),
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is True
    assert reload_pressed is True


def test_convert_capture_to_replay_synthesizes_reload_for_alt_weapon_swap_from_before_snapshot(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = 1
    _tick_player(tick0)["ammo"] = 12.0
    tick0["input_player_keys"] = [_base_input_player_keys(**{"player_index": 0})]
    tick0["before"] = _base_snapshot(
        players=[
            _base_snapshot_player(
                weapon_id=11,
                ammo_i32=0,
                clip_size_i32=1106247680,
                reload_active_i32=1,
                reload_timer=0.9989999,
                reload_timer_max=1.3,
                shot_cooldown=0.0,
                alt_weapon=_base_snapshot_player_alt_weapon(
                    weapon_id=1,
                    clip_size_i32=1094713344,
                    reload_active_i32=0,
                    ammo_i32=1094713344,
                    reload_timer=0.0,
                    shot_cooldown=0.0,
                    reload_timer_max=1.2,
                ),
            ),
        ],
    )

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["weapon_id"] = 1
    _tick_player(tick1)["ammo"] = 12.0
    tick1["input_player_keys"] = [_base_input_player_keys(**{"player_index": 0})]
    tick1["before"] = _base_snapshot(
        players=[
            _base_snapshot_player(
                weapon_id=1,
                ammo_i32=1094713344,
                clip_size_i32=1094713344,
                reload_active_i32=0,
                reload_timer=0.0,
                reload_timer_max=1.2,
                shot_cooldown=0.1,
                alt_weapon=_base_snapshot_player_alt_weapon(
                    weapon_id=11,
                    clip_size_i32=1106247680,
                    reload_active_i32=1,
                    ammo_i32=0,
                    reload_timer=0.9409999,
                    shot_cooldown=0.0,
                    reload_timer_max=1.3,
                ),
            ),
        ],
    )

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    _fire_down0, _fire_pressed0, reload_pressed0 = unpack_input_flags(_replay_input_flags(replay, 0, 0))
    _fire_down1, _fire_pressed1, reload_pressed1 = unpack_input_flags(_replay_input_flags(replay, 1, 0))
    assert reload_pressed0 is True
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_fire_down_from_player_fire_event_with_false_key_state(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}),
    ]
    tick0["event_heads"] = [
        {
            "type": "player_fire",
            "data": {
                "player_index": 0,
                "owner_id": -100,
                "weapon_before": 29,
                "weapon_after": 11,
                "ammo_before": 2.0,
                "ammo_after": 0.0,
                "shot_cooldown_after": 0.11,
                "requested_type_id": None,
                "actual_type_id": None,
                "source": None,
                "caller": None,
                "caller_static": None,
            },
        },
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 11, "actual_type_id": 11}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_fire_down_from_zero_cooldown_player_fire_event(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}),
    ]
    tick0["event_heads"] = [
        {
            "type": "player_fire",
            "data": {
                "player_index": 0,
                "owner_id": -100,
                "weapon_before": int(WeaponId.FLAMETHROWER),
                "weapon_after": int(WeaponId.FLAMETHROWER),
                "ammo_before": 29.4,
                "ammo_after": 29.4,
                "requested_type_id": 11,
                "actual_type_id": 11,
                "shot_cooldown_after": 0.0,
                "source": None,
                "caller": None,
                "caller_static": None,
            },
        },
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 11, "actual_type_id": 11}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_computer_fire_for_zero_cooldown_player_fire_spawn(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = 11
    _tick_player(tick0)["ammo"] = 21.0
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 11, "fired_events": 1}),
    ]
    tick0["event_heads"] = [
        {
            "type": "player_fire",
            "data": {
                "player_index": 0,
                "owner_id": -100,
                "weapon_before": 11,
                "weapon_after": 11,
                "ammo_before": 21.0,
                "ammo_after": 21.0,
                "requested_type_id": 45,
                "actual_type_id": 45,
                "shot_cooldown_after": 0.0,
                "source": None,
                "caller": None,
                "caller_static": None,
            },
        },
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 45, "actual_type_id": 45}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_fire_down_from_fractional_ammo_drain(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = int(WeaponId.FLAMETHROWER)
    _tick_player(tick0)["ammo"] = 29.9
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "aim_x": 520.0,
            "aim_y": 500.0,
            "weapon_id": int(WeaponId.FLAMETHROWER),
            "fired_events": 0,
        },
    ]
    tick0["before"] = _base_snapshot(
        players=[
            _base_snapshot_player(
                weapon_id=int(WeaponId.FLAMETHROWER),
                ammo_f32=30.0,
                reload_active_i32=0,
                reload_timer=0.0,
                shot_cooldown=0.0,
            ),
        ],
    )

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    fire_down, fire_pressed, reload_pressed = unpack_input_flags(_replay_input_flags(replay, 0, 0))
    assert fire_down is True
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_fire_down_when_fractional_weapon_finishes_reload(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = int(WeaponId.FLAMETHROWER)
    _tick_player(tick0)["ammo"] = 29.9
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "aim_x": 520.0,
            "aim_y": 500.0,
            "weapon_id": int(WeaponId.FLAMETHROWER),
            "fired_events": 0,
        },
    ]
    tick0["before"] = _base_snapshot(
        players=[
            _base_snapshot_player(
                weapon_id=int(WeaponId.FLAMETHROWER),
                ammo_f32=-7.8e-5,
                clip_size_f32=30.0,
                reload_active_i32=1,
                reload_timer=0.046,
                reload_timer_max=2.0,
                shot_cooldown=0.0,
            ),
        ],
    )

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    fire_down, fire_pressed, reload_pressed = unpack_input_flags(_replay_input_flags(replay, 0, 0))
    assert fire_down is True
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_fire_down_from_fractional_weapon_fire_sfx(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = int(WeaponId.FLAMETHROWER)
    _tick_player(tick0)["ammo"] = 30.0
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["before"] = _base_snapshot(
        players=[
            _base_snapshot_player(
                weapon_id=int(WeaponId.FLAMETHROWER),
                ammo_f32=6.4,
                reload_active_i32=0,
                reload_timer=0.0,
            ),
        ],
    )
    tick0["event_heads"] = [
        {
            "type": "sfx",
            "data": {
                "kind": "sfx_play_panned",
                "id_i32": 43,
                "caller": "crimsonland.exe+0x15f1c",
                "backtrace": None,
            },
        },
        {
            "type": "bonus_apply",
            "data": {
                "bonus_id": 9,
                "player_index": 0,
                "entry_state": None,
                "amount_i32": 8,
                "amount_f32": 8.0,
                "caller": None,
            },
        },
    ]

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    fire_down, fire_pressed, reload_pressed = unpack_input_flags(_replay_input_flags(replay, 0, 0))
    assert fire_down is True
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_fire_pressed_from_primary_edge_when_reload_active(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = _base_snapshot(globals=_base_snapshot_globals(config_aim_scheme=[5]))
    tick0["input_queries"] = {
        "stats": {
            "primary_edge": {"calls": 1, "true_calls": 1},
            "primary_down": {"calls": 1, "true_calls": 0},
            "any_key": {"calls": 0, "true_calls": 0},
        },
        "query_hash": "",
    }
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": None,
            "fire_pressed": None,
            "reload_pressed": None,
        },
    ]
    tick0["input_approx"] = [
        {
            "player_index": 0,
            "aim_x": 520.0,
            "aim_y": 500.0,
            "aim_scheme": 5,
            "reload_active": True,
            "fired_events": 0,
        },
    ]

    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    fire_down, fire_pressed, reload_pressed = unpack_input_flags(_replay_input_flags(replay, 0, 0))
    assert fire_down is False
    assert fire_pressed is True
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_computer_aim_fire_down_from_projectile_spawn(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = _base_snapshot(globals=_base_snapshot_globals(config_aim_scheme=[5]))
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}),
    ]
    tick0["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is True
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_computer_fire_for_non_weapon_projectile_spawns(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = _base_snapshot(globals=_base_snapshot_globals(config_aim_scheme=[5]))
    _tick_player(tick0)["weapon_id"] = 29
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 29, "fired_events": 1}),
    ]
    tick0["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 21, "actual_type_id": 21}},
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 22, "actual_type_id": 22}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_non_computer_fire_down(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = _base_snapshot(globals=_base_snapshot_globals(config_aim_scheme=[0]))
    tick0["input_player_keys"] = [
        {
            "player_index": 0,
            "fire_down": False,
            "fire_pressed": False,
            "reload_pressed": False,
        },
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}),
    ]
    tick0["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_synthesizes_computer_fire_when_mode_missing_but_ammo_drops(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["ammo"] = 10.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "fired_events": 0}),
    ]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["ammo"] = 9.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 0}),
    ]
    tick1["event_heads"] = [{"type": "projectile_spawn", "data": {"owner_id": -100}}]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags0 = _replay_input_flags(replay, 0, 0)
    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down0, fire_pressed0, _reload_pressed0 = unpack_input_flags(flags0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down0 is False
    assert fire_pressed0 is False
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_computer_fire_when_reload_completes_then_shot(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["ammo"] = 0.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 1})]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["ammo"] = 9.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick1["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 1})]
    tick1["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}},
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_unknown_mode_fire_for_fire_bullets_projectile(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = 3
    _tick_player(tick0)["ammo"] = 9.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 3})]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["weapon_id"] = 3
    _tick_player(tick1)["ammo"] = 9.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick1["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 3})]
    tick1["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 45, "actual_type_id": 45}},
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_unknown_mode_fire_for_secondary_projectile_spawn(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = 17
    _tick_player(tick0)["ammo"] = 5.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 17})]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["weapon_id"] = 17
    _tick_player(tick1)["ammo"] = 5.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick1["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 17})]
    tick1["event_heads"] = [
        {
            "type": "secondary_projectile_spawn",
            "data": {"owner_id": -100, "requested_type_id": 2, "actual_type_id": 0},
        },
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_does_not_synthesize_computer_fire_for_bonus_projectile_spawn(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = _base_snapshot(globals=_base_snapshot_globals(config_aim_scheme=[5]))
    _tick_player(tick0)["weapon_id"] = 5
    _tick_player(tick0)["ammo"] = 12.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 5})]
    tick0["event_heads"] = [
        {
            "type": "bonus_apply",
            "data": {
                "player_index": 0,
                "bonus_id": 8,
                "entry_state": None,
                "amount_i32": None,
                "amount_f32": None,
                "caller": None,
            },
        },
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 9, "actual_type_id": 9}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_computer_fire_for_nuke_fire_bullets_override(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["before"] = _base_snapshot(globals=_base_snapshot_globals(config_aim_scheme=[5]))
    _tick_player(tick0)["weapon_id"] = 23
    _tick_player(tick0)["ammo"] = 6.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 23, "fired_events": 0}),
    ]
    tick0["event_heads"] = [
        {
            "type": "bonus_apply",
            "data": {
                "player_index": 0,
                "bonus_id": 5,
                "entry_state": None,
                "amount_i32": None,
                "amount_f32": None,
                "caller": None,
            },
        },
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 45}},
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 6, "actual_type_id": 45}},
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags = _replay_input_flags(replay, 0, 0)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(flags)
    assert fire_down is False
    assert fire_pressed is False
    assert reload_pressed is False


def test_convert_capture_to_replay_does_not_synthesize_secondary_spawn_without_owner_in_multiplayer(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_checkpoint(tick0)["players"] = [_base_player(), _base_player()]
    tick0["input_player_keys"] = [
        {"player_index": 0, "fire_down": False, "fire_pressed": False},
        {"player_index": 1, "fire_down": False, "fire_pressed": False},
    ]
    tick0["input_approx"] = [
        {"player_index": 0, "aim_x": 512.0, "aim_y": 512.0},
        {"player_index": 1, "aim_x": 256.0, "aim_y": 256.0},
    ]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_checkpoint(tick1)["players"] = [_base_player(), _base_player()]
    tick1["input_player_keys"] = [
        {"player_index": 0, "fire_down": False, "fire_pressed": False},
        {"player_index": 1, "fire_down": False, "fire_pressed": False},
    ]
    tick1["input_approx"] = [
        {"player_index": 0, "aim_x": 520.0, "aim_y": 500.0},
        {"player_index": 1, "aim_x": 250.0, "aim_y": 260.0},
    ]
    tick1["event_heads"] = [
        {"type": "secondary_projectile_spawn", "data": {"requested_type_id": 2, "actual_type_id": 0}},
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags10 = _replay_input_flags(replay, 1, 0)
    flags11 = _replay_input_flags(replay, 1, 1)
    fire_down10, fire_pressed10, reload_pressed10 = unpack_input_flags(flags10)
    fire_down11, fire_pressed11, reload_pressed11 = unpack_input_flags(flags11)
    assert fire_down10 is False
    assert fire_pressed10 is False
    assert reload_pressed10 is False
    assert fire_down11 is False
    assert fire_pressed11 is False
    assert reload_pressed11 is False


def test_convert_capture_to_replay_does_not_synthesize_fire_from_fired_events_only(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [
        _base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "fired_events": 2}),
    ]
    obj = _capture_obj(ticks=[tick0])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay_default = convert_capture_to_replay(capture, seed=0)
    replay_override = convert_capture_to_replay(capture, seed=0, aim_scheme_overrides_by_player={0: 5})

    flags_default = _replay_input_flags(replay_default, 0, 0)
    flags_override = _replay_input_flags(replay_override, 0, 0)
    fire_down_default, _fire_pressed_default, _reload_pressed_default = unpack_input_flags(flags_default)
    fire_down_override, _fire_pressed_override, _reload_pressed_override = unpack_input_flags(flags_override)
    assert fire_down_default is False
    assert fire_down_override is False


def test_parse_player_int_overrides_accepts_equals_and_colon() -> None:
    parsed = parse_player_int_overrides(["0=5", "1:4"], option_name="--aim-scheme-player")
    assert parsed == {0: 5, 1: 4}


def test_parse_player_int_overrides_rejects_bad_entry() -> None:
    with pytest.raises(ValueError):
        parse_player_int_overrides(["nope"], option_name="--aim-scheme-player")


def test_convert_capture_to_replay_does_not_synthesize_unknown_mode_without_weapon_match(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["ammo"] = 0.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 1})]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["ammo"] = 9.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick1["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 1})]
    tick1["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 7, "actual_type_id": 7}},
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is False
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_unknown_mode_fire_for_mapped_weapon_projectile(
    tmp_path: Path,
) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = 14
    _tick_player(tick0)["ammo"] = 8.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 14})]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["weapon_id"] = 14
    _tick_player(tick1)["ammo"] = 8.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick1["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 14})]
    tick1["event_heads"] = [
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 11, "actual_type_id": 11}},
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False


def test_convert_capture_to_replay_synthesizes_unknown_mode_fire_when_weapon_switches_in_tick(tmp_path: Path) -> None:
    tick0 = _base_tick(tick_index=0, elapsed_ms=16)
    _tick_player(tick0)["weapon_id"] = 1
    _tick_player(tick0)["ammo"] = 2.0
    tick0["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick0["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 512.0, "aim_y": 512.0, "weapon_id": 1})]

    tick1 = _base_tick(tick_index=1, elapsed_ms=32)
    _tick_player(tick1)["weapon_id"] = 14
    _tick_player(tick1)["ammo"] = 8.0
    tick1["input_player_keys"] = [
        _base_input_player_keys(**{"player_index": 0, "fire_down": False, "fire_pressed": False}),
    ]
    tick1["input_approx"] = [_base_input_approx(**{"player_index": 0, "aim_x": 520.0, "aim_y": 500.0, "weapon_id": 14})]
    tick1["event_heads"] = [
        {
            "type": "bonus_apply",
            "data": {
                "player_index": 0,
                "bonus_id": 3,
                "entry_state": None,
                "amount_i32": 14,
                "amount_f32": 14.0,
                "caller": None,
            },
        },
        {
            "type": "weapon_assign",
            "data": {
                "player_index": 0,
                "weapon_id": 14,
                "weapon_before": 1,
                "weapon_after": 14,
                "caller": None,
            },
        },
        {"type": "projectile_spawn", "data": {"owner_id": -100, "requested_type_id": 1, "actual_type_id": 1}},
    ]

    obj = _capture_obj(ticks=[tick0, tick1])
    path = tmp_path / "capture.json"
    _write_capture(path, obj)

    capture = load_capture(path)
    replay = convert_capture_to_replay(capture, seed=0)

    flags1 = _replay_input_flags(replay, 1, 0)
    fire_down1, fire_pressed1, reload_pressed1 = unpack_input_flags(flags1)
    assert fire_down1 is True
    assert fire_pressed1 is False
    assert reload_pressed1 is False
