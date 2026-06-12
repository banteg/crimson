from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from crimson.dbg.frida_finalize import FridaFinalizeError, finalize_frida_jsonl_to_traces
from crimson.dbg.trace import load_trace
from crimson.replay.codec import load_replay_file
from crimson.replay.types import WEAPON_USAGE_COUNT

CAPTURE_FORMAT_VERSION = 13


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
        "capture_profile": "exhaustive_default",
        "config_env_overrides": [],
        "log_mode": "truncate",
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
        "flush_capture_writes": False,
        "max_head_per_kind": -1,
        "max_events_per_tick": -1,
        "max_rng_head_per_tick": -1,
        "max_rng_caller_kinds": -1,
        "enable_rng_roll_log": True,
        "max_rng_roll_log_events": -1,
        "max_rng_outside_tick_head": 256,
        "enable_rng_state_mirror": True,
        "max_creature_delta_ids": 256,
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


def _session_start_row(*, capture_format_version: int = CAPTURE_FORMAT_VERSION) -> dict[str, object]:
    return {
        "event": "session_start",
        "capture_format_version": int(capture_format_version),
        "session_id": "session-test",
        "out_path": "C:\\share\\frida\\gameplay_diff_capture.jsonl",
        "platform": "windows",
        "arch": "x86",
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
    frame_dt = float(dt_ms_i32) / 1000.0 if dt is None else float(dt)
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
        # The real capture emits a null mode_fn: the gpur_enter sample is built
        # before any mode hook fires.
        "mode_fn": None,
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
    }


def _sim_state_stub(
    *,
    mode_id: int,
    player_count: int = 1,
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
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
            "status": {
                "quest_unlock_index": 0,
                "quest_unlock_index_full": 0,
                "weapon_usage_counts": [0] * int(WEAPON_USAGE_COUNT),
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
    caller_static: str | None = "0x00430b88",
) -> dict[str, object]:
    return {
        "tick_call_index": int(tick_call_index),
        "value_15": int(value_15),
        "state_before_u32": int(state_before_u32),
        "state_after_u32": int(state_after_u32),
        "caller_static": caller_static,
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
        "heading": 0.0,
        "target_heading": 0.0,
        "orbit_angle": 0.0,
        "orbit_radius": 0.0,
        "lifecycle_stage": 0.0,
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
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    creatures: list[dict[str, object]] | None = None,
    projectiles: list[dict[str, object]] | None = None,
    secondary_projectiles: list[dict[str, object]] | None = None,
    checkpoint_overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    checkpoint = _checkpoint_stub(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        player_count=int(player_count),
    )
    if checkpoint_overrides:
        checkpoint.update(dict(checkpoint_overrides))
    return {
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


def _replay_inputs_stub(*, player_count: int = 1) -> list[list[float | int]]:
    return [[0.0, 0.0, 0.0, 0.0, 0] for _ in range(max(0, int(player_count)))]


def _run_start_row(
    *,
    run_id: int,
    mode_id: int,
    seed: int = 123,
    player_count: int = 1,
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    seed_source: str = "crt_srand",
    rng_state_at_run_setup: int | None = None,
    include_rng_state_at_run_setup: bool = True,
) -> dict[str, object]:
    row: dict[str, object] = {
        "event": "run_start",
        "run_id": int(run_id),
        "mode_id": int(mode_id),
        "seed": int(seed),
        "seed_source": str(seed_source),
        "player_count": int(player_count),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
    }
    if include_rng_state_at_run_setup:
        row["rng_state_at_run_setup"] = int(seed if rng_state_at_run_setup is None else rng_state_at_run_setup)
        row["rng_setup_caller_static"] = "0x004181cc"
    return row


def _rng_accounting_stub(*, rng_calls: int = 0) -> dict[str, object]:
    return {
        "rng_calls": int(rng_calls),
        "rng_outside_before": _rng_outside_bag_stub(),
        "rng_state_enter_u32": 0,
        "rng_state_leave_u32": 0,
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
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    channels: dict[str, object] | None = None,
    rng_calls: int | None = None,
    rng_outside_before: dict[str, object] | None = None,
    rng_state_enter_u32: int | None = 0,
    rng_state_leave_u32: int | None = 0,
    include_rng_accounting: bool = True,
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
        "tick_index_global": int(tick_index),
        "elapsed_ms": int(elapsed_ms),
        "dt_ms_i32": int(dt_ms_i32),
        "dt": float(dt),
        "mode_id": int(mode_id),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
        "replay_inputs": _replay_inputs_stub(player_count=player_count),
        "channels": resolved_channels,
    }
    if include_rng_accounting:
        stream = cast(list[object], resolved_channels.get("rng_stream") or [])
        row["rng_calls"] = len(stream) if rng_calls is None else int(rng_calls)
        row["rng_outside_before"] = (
            _rng_outside_bag_stub() if rng_outside_before is None else rng_outside_before
        )
        row["rng_state_enter_u32"] = rng_state_enter_u32
        row["rng_state_leave_u32"] = rng_state_leave_u32
    return row


def _run_end_row(
    *,
    run_id: int,
    mode_id: int = -1,
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    ticks_written: int = 0,
    reason: str = "run_end",
    rng_outside_tail: dict[str, object] | None = None,
    include_rng_outside_tail: bool = True,
) -> dict[str, object]:
    row: dict[str, object] = {
        "event": "run_end",
        "run_id": int(run_id),
        "reason": str(reason),
        "mode_id": int(mode_id),
        "quest_stage_major": int(quest_stage_major),
        "quest_stage_minor": int(quest_stage_minor),
        "ticks_written": int(ticks_written),
    }
    if include_rng_outside_tail:
        row["rng_outside_tail"] = _rng_outside_bag_stub() if rng_outside_tail is None else rng_outside_tail
    return row


def _session_end_row(*, session_id: str = "session-test", ticks_written: int = 0) -> dict[str, object]:
    return {
        "event": "session_end",
        "session_id": str(session_id),
        "ticks_written": int(ticks_written),
    }


def test_finalize_frida_jsonl_to_traces_writes_trace_and_replay_and_deletes_raw(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {
                **_session_start_row(),
            },
            _run_start_row(run_id=1, mode_id=1, seed=777, player_count=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 1,
                "tick_index_global": 100,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=100,
                    elapsed_ms=0,
                    mode_id=1,
                    creatures=[_creature_sample(uid=562949953421317, generation=1, index=5, active=True)],
                    projectiles=[_projectile_sample(uid=1001, generation=1, index=2, owner_id=-100)],
                    checkpoint_overrides={
                        "deaths": [
                            {
                                "creature_index": 7,
                                "type_id": 18,
                                "reward_value": 75.0,
                                "xp_awarded": 10,
                                "owner_id": -1,
                            },
                        ],
                    },
                ),
            },
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 1,
                "tick_index_global": 101,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=101,
                    elapsed_ms=16,
                    mode_id=1,
                    creatures=[_creature_sample(uid=562949953421317, generation=1, index=5, active=False)],
                ),
            },
            _run_end_row(run_id=1, mode_id=1, ticks_written=2),
            _session_end_row(ticks_written=2),
        ],
    )

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
    assert len(replay.ticks) == 2

    meta, ticks, footer = load_trace(out_trace.out_path)
    assert footer.tick_count == 2
    assert meta.producer.impl == "frida_original"
    assert ticks[0].channels.checkpoint.tick_index == 0
    assert ticks[1].channels.checkpoint.tick_index == 1

    creatures0 = ticks[0].channels.entity_samples.creatures
    creatures1 = ticks[1].channels.entity_samples.creatures
    assert isinstance(creatures0[0].uid, int)
    assert creatures0[0].generation == 1
    assert creatures1[0].generation == 1
    assert ticks[0].channels.entity_samples.projectiles[0].owner_id == -100
    assert ticks[0].channels.checkpoint.deaths[0].owner_id == -1

    # Capture timing rows are rebased to the run-local domain with the gpur
    # label so the timing channel is comparable against rewrite traces.
    timing0 = ticks[0].channels.timing_samples[0]
    timing1 = ticks[1].channels.timing_samples[0]
    assert timing0.tick_index == 0
    assert timing1.tick_index == 1
    assert timing0.mode_fn == "gameplay_update_and_render"
    assert timing1.mode_fn == "gameplay_update_and_render"


def test_finalize_frida_jsonl_to_traces_canonicalizes_rng_caller(tmp_path: Path) -> None:
    channels = _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1)
    channels["rng_stream"] = [_rng_stream_row_stub()]
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, seed=777, player_count=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=0,
                dt_ms_i32=16,
                dt=0.016,
                mode_id=1,
                player_count=1,
                channels=channels,
            ),
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
            _session_end_row(ticks_written=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    _meta, ticks, _footer = load_trace(result.traces[0].out_path)
    assert ticks[0].channels.rng_stream[0].caller == 0x00430B88


def test_finalize_frida_jsonl_to_traces_allows_missing_session_end_when_run_closed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=1, seed=11, player_count=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1),
            },
            _run_end_row(run_id=1, mode_id=1, ticks_written=1),
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].tick_count == 1
    assert result.traces[0].replay_path.is_file()


def test_finalize_frida_jsonl_to_traces_finalizes_active_run_when_capture_abruptly_ends(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=4, mode_id=2, seed=22, player_count=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 4,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "dt": 0.033,
                "mode_id": 2,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=33, mode_id=2, dt_ms_i32=33, dt=0.033),
            },
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].run_id == 4
    assert result.traces[0].tick_count == 1
    assert result.traces[0].replay_path.is_file()


def test_finalize_frida_jsonl_to_traces_rejects_missing_session_end_when_no_runs(tmp_path: Path) -> None:
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [_session_start_row()])

    with pytest.raises(FridaFinalizeError, match="missing session_end"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_names_runs_by_mode_not_stale_quest_stage(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=31, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 5,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=0,
                    mode_id=3,
                    quest_stage_major=1,
                    quest_stage_minor=5,
                ),
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=5, ticks_written=1),
            _run_start_row(run_id=2, mode_id=2, seed=32, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 2,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 2,
                "quest_stage_major": 1,
                "quest_stage_minor": 5,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=1,
                    elapsed_ms=16,
                    mode_id=2,
                    quest_stage_major=1,
                    quest_stage_minor=5,
                ),
            },
            _run_end_row(run_id=2, mode_id=2, quest_stage_major=1, quest_stage_minor=5, ticks_written=1),
            _run_start_row(run_id=3, mode_id=1, seed=33, player_count=1, quest_stage_major=1, quest_stage_minor=5),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 3,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "dt": 0.033,
                "mode_id": 1,
                "quest_stage_major": 1,
                "quest_stage_minor": 5,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=2,
                    elapsed_ms=33,
                    mode_id=1,
                    dt_ms_i32=33,
                    dt=0.033,
                    quest_stage_major=1,
                    quest_stage_minor=5,
                ),
            },
            _run_end_row(run_id=3, mode_id=1, quest_stage_major=1, quest_stage_minor=5, ticks_written=1),
            _session_end_row(ticks_written=3),
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
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
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
            _session_end_row(ticks_written=1),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="invalid capture row"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_null_run_start_seed_with_actionable_error(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "seed": None,
                "player_count": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="Expected `int`, got `null` - at `\\$\\.seed`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_legacy_bootstrap_kind_field(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "seed": 7,
                "player_count": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
                "bootstrap_kind": "terrain_v1",
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `bootstrap_kind`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_legacy_bootstrap_seed_field(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "seed": 7,
                "bootstrap_seed": 7,
                "seed_source": "crt_srand",
                "player_count": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="unknown field `bootstrap_seed`"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_legacy_capture_format_version(
    tmp_path: Path,
) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(capture_format_version=6),
            _run_start_row(run_id=1, mode_id=3, seed=91, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(tick_index=0, elapsed_ms=16, mode_id=3),
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
            _session_end_row(ticks_written=1),
        ],
    )

    with pytest.raises(FridaFinalizeError, match=r"unsupported capture_format_version=6; expected one of \[13, 14\]"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_keeps_large_first_tick_elapsed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=92, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            {
                "event": "tick",
                **_rng_accounting_stub(),
                "run_id": 1,
                "elapsed_ms": 25_000,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": _channels_stub(
                    tick_index=0,
                    elapsed_ms=25_000,
                    mode_id=3,
                    quest_stage_major=1,
                    quest_stage_minor=1,
                ),
            },
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    assert result.deleted_raw is False
    assert len(result.traces) == 1
    assert result.traces[0].tick_count == 1


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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": channels,
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
            _session_end_row(ticks_written=1),
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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "replay_inputs": _replay_inputs_stub(player_count=1),
                "channels": channels,
            },
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
            _session_end_row(ticks_written=1),
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


def test_finalize_frida_jsonl_to_traces_rejects_invalid_run_start_seed_source(tmp_path: Path) -> None:
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

    with pytest.raises(FridaFinalizeError, match="seed_source must be one of"):
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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
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
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=108, player_count=1, quest_stage_major=1, quest_stage_minor=1),
            _tick_row(
                run_id=1,
                tick_index=0,
                elapsed_ms=16,
                dt_ms_i32=16,
                dt=0.017,
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
        match=r"channels\.timing_samples\.gpur_enter\.frame_dt_f32=0\.016 does not match tick\.dt 0\.017",
    ):
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
                "run_id": 1,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "dt": 0.016,
                "mode_id": 3,
                "quest_stage_major": 1,
                "quest_stage_minor": 1,
                "replay_inputs": _replay_inputs_stub(player_count=1),
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
            _run_start_row(run_id=1, mode_id=3, seed=108, player_count=1, quest_stage_major=1, quest_stage_minor=1),
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
                "tick_index_global": 77,
            },
        ],
    )

    with pytest.raises(FridaFinalizeError, match="capture error='missing_run_start_seed' tick_index_global=77"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_session_end_session_id_mismatch(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _session_end_row(session_id="session-other"),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="session_id must match session_start.session_id"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_session_end_tick_count_mismatch(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            _session_start_row(),
            _run_start_row(run_id=1, mode_id=3, seed=104, player_count=1, quest_stage_major=1, quest_stage_minor=1),
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
            _run_end_row(run_id=1, mode_id=3, quest_stage_major=1, quest_stage_minor=1, ticks_written=1),
            _session_end_row(ticks_written=0),
        ],
    )

    with pytest.raises(FridaFinalizeError, match="ticks_written=0 does not match parsed tick_count 1"):
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
        "run_id": 1,
        "elapsed_ms": 0,
        "dt_ms_i32": 16,
        "dt": 0.016,
        "mode_id": 1,
        "replay_inputs": _replay_inputs_stub(player_count=1),
        "channels": _channels_stub(tick_index=0, elapsed_ms=0, mode_id=1),
    }
    tick.update(tick_overrides or {})
    return [
        _session_start_row(),
        run_start,
        tick,
        _run_end_row(run_id=1, mode_id=1, ticks_written=1) if run_end is None else run_end,
        _session_end_row(ticks_written=1),
    ]


def test_finalize_frida_jsonl_to_traces_seeds_replay_from_run_setup_rng_state(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1, seed=123, player_count=1, rng_state_at_run_setup=999),
        ),
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    replay = load_replay_file(result.traces[0].replay_path)
    assert replay.header.seed == 999
    meta, _ticks, _footer = load_trace(result.traces[0].out_path)
    assert meta.source.seed == 999
    assert meta.source.run_start_seed_source == "run_setup_rng_state"


def test_finalize_frida_jsonl_to_traces_rejects_missing_run_setup_rng_state(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1, include_rng_state_at_run_setup=False),
        ),
    )

    with pytest.raises(FridaFinalizeError, match="rng_state_at_run_setup is required"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_rejects_tick_without_rng_accounting(tmp_path: Path) -> None:
    rows = _single_tick_rows(run_start=_run_start_row(run_id=1, mode_id=1))
    tick = rows[2]
    del tick["rng_outside_before"]
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", rows)

    with pytest.raises(FridaFinalizeError, match="must carry rng accounting"):
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

    with pytest.raises(FridaFinalizeError, match="rng_outside_tail is required"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_reports_unhooked_rng_draws(tmp_path: Path) -> None:
    # enter == seed (setup distance 0); leave is one LCG step past the last
    # observed draw, so the report must attribute one unhooked in-tick draw.
    seed = 100
    leave = (seed * 214013 + 2531011) & 0xFFFFFFFF
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        _single_tick_rows(
            run_start=_run_start_row(run_id=1, mode_id=1, rng_state_at_run_setup=seed),
            tick_overrides={
                "rng_state_enter_u32": seed,
                "rng_state_leave_u32": leave,
                "rng_outside_before": _rng_outside_bag_stub(calls=2, caller_counts={"0x00417f00": 2}),
            },
        ),
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)

    evidence_path = result.traces[0].out_path.with_suffix(".rng_evidence.json")
    report = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert report["setup_draw_distance"] == 0
    assert report["unhooked_in_tick"] == 1
    assert report["unhooked_gap_neighbors"] == {"tick_tail": 1}
    assert report["outside_calls"] == 2
    assert report["outside_caller_counts"] == {"0x00417f00": 2}
