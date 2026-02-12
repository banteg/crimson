from __future__ import annotations

import json
import os
from pathlib import Path

from crimson.original.diagnostics_cache import (
    CaptureSession,
    SessionRegistry,
    build_focus_key,
    cache_enabled,
)
from crimson.original.focus_trace import (
    FocusTraceReport,
    RngAlignmentSummary,
)
from crimson.original import divergence_report, focus_trace
from crimson.original.schema import CAPTURE_FORMAT_VERSION


def _checkpoint_tick(tick: int, *, level: int, weapon_id: int, experience: int, perk_pairs: list[list[int]]) -> dict[str, object]:
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
            }
        ],
        "status": {
            "quest_unlock_index": -1,
            "quest_unlock_index_full": -1,
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
        "events": {"hit_count": -1, "pickup_count": -1, "sfx_count": -1, "sfx_head": []},
        "debug": {
            "sampling_phase": "",
            "timing": {},
            "spawn": {},
            "rng": {},
            "perk_apply_outside_before": {"calls": 0, "dropped": 0, "head": []},
            "creature_lifecycle": None,
            "before_players": [],
            "before_status": {"quest_unlock_index": -1, "quest_unlock_index_full": -1},
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
        "game_mode_id": 1,
        "checkpoint": _checkpoint_tick(
            tick,
            level=int(level),
            weapon_id=int(weapon_id),
            experience=int(experience),
            perk_pairs=perk_pairs,
        ),
        "event_heads": list(event_heads),
        "samples": {
            "creatures": [
                {
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
                }
            ],
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
        "input_player_keys": [{"player_index": 0}],
        "input_approx": [{"player_index": 0, "aim_x": 0.0, "aim_y": 0.0}],
    }


def _capture_obj(*, ticks: list[dict[str, object]]) -> dict[str, object]:
    return {
        "capture_format_version": int(CAPTURE_FORMAT_VERSION),
        "script": "gameplay_diff_capture",
        "session_id": "s",
        "out_path": "capture.json",
        "config": {},
        "session_fingerprint": {"session_id": "s", "module_hash": "a", "ptrs_hash": "b"},
        "process": {"pid": 1, "platform": "windows", "arch": "x86", "frida_version": "16", "runtime": "v8"},
        "exe": {"base": "0x400000", "size": 1, "path": "crimsonland.exe"},
        "grim": None,
        "pointers_resolved": {},
        "ticks": ticks,
    }


def _write_capture_stream(path: Path, capture: dict[str, object]) -> None:
    meta = {key: value for key, value in capture.items() if key != "ticks"}
    ticks_obj = capture.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(
        json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks
    )
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
                    {"kind": "bonus_apply", "data": {"player_index": 0, "bonus_id": 3, "amount_i32": 12}},
                    {"kind": "weapon_assign", "data": {"player_index": 0, "weapon_before": 1, "weapon_after": 12}},
                    {"kind": "state_transition", "data": {"before": {"id": 9}, "after": {"id": 6}}},
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
        ]
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
        ]
    )

    assert no_cache is True
    assert args == ["capture.json", "--window", "24", "--json-out", "out.json"]


def test_capture_session_builds_sidecars_and_indexes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRIMSON_ORIGINAL_CACHE_DIR", str(tmp_path / "cache"))

    capture_path = tmp_path / "capture.json"
    _write_fixture_capture(capture_path)

    session = CaptureSession(capture_path)

    cache_capture_blobs = list((tmp_path / "cache").glob("*/capture.msgpack.gz"))
    cache_tick_blobs = list((tmp_path / "cache").glob("*/tick_index.msgpack.gz"))
    cache_meta_files = list((tmp_path / "cache").glob("*/meta.json"))
    assert cache_capture_blobs
    assert cache_tick_blobs
    assert cache_meta_files

    sample_counts = session.get_sample_creature_counts()
    assert sample_counts[0] == 1
    assert sample_counts[1] == 1

    raw_debug = session.get_raw_debug_by_tick()
    assert raw_debug[0]["sample_streams_present"] is True
    assert int((raw_debug[0]["sample_counts"] or {}).get("creatures", -1)) == 1

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
