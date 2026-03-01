from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from crimson.dbg.frida_finalize import FridaFinalizeError, finalize_frida_jsonl_to_traces
from crimson.dbg.trace import load_trace


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row))
            handle.write("\n")
    return path


def test_finalize_frida_jsonl_to_traces_writes_trace_and_deletes_raw(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {
                "event": "session_start",
                "platform": "windows",
                "arch": "x86",
                "script_version": "5",
                "config": {"a": 1},
            },
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
            {
                "event": "tick",
                "run_id": 1,
                "tick_index_global": 100,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "phase_markers": ["a"],
                "channels": {
                    "checkpoint": {"elapsed_ms": 0},
                    "entity_samples": {
                        "creatures": [{"index": 5, "active": True}],
                        "projectiles": [],
                        "secondary_projectiles": [],
                        "bonuses": [],
                    },
                },
            },
            {
                "event": "tick",
                "run_id": 1,
                "tick_index_global": 101,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "phase_markers": [],
                "channels": {
                    "checkpoint": {"elapsed_ms": 16},
                    "entity_samples": {
                        "creatures": [{"index": 5, "active": False}],
                        "projectiles": [],
                        "secondary_projectiles": [],
                        "bonuses": [],
                    },
                },
            },
            {
                "event": "run_end",
                "run_id": 1,
                "mode_id": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
            {"event": "session_end"},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=True)

    assert result.deleted_raw is True
    assert not raw_path.exists()
    assert len(result.traces) == 1

    out_trace = result.traces[0]
    assert out_trace.tick_count == 2

    meta, ticks, footer = load_trace(out_trace.out_path)
    assert footer.tick_count == 2
    assert meta.producer["impl"] == "frida_original"
    assert "checkpoint" in meta.channels
    assert "entity_samples" in meta.channels

    creatures0 = cast("dict[str, list[dict[str, object]]]", ticks[0].channels["entity_samples"])["creatures"]
    creatures1 = cast("dict[str, list[dict[str, object]]]", ticks[1].channels["entity_samples"])["creatures"]
    assert isinstance(creatures0[0]["uid"], int)
    assert creatures0[0]["generation"] == 1
    assert creatures1[0]["generation"] == 1


def test_finalize_frida_jsonl_to_traces_allows_missing_session_end_when_run_closed(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
            {
                "event": "run_start",
                "run_id": 1,
                "mode_id": 1,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 1,
                "phase_markers": [],
                "channels": {"checkpoint": {"elapsed_ms": 0}},
            },
            {"event": "run_end", "run_id": 1},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].tick_count == 1


def test_finalize_frida_jsonl_to_traces_finalizes_active_run_when_capture_abruptly_ends(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
            {
                "event": "run_start",
                "run_id": 4,
                "mode_id": 2,
                "quest_stage_major": -1,
                "quest_stage_minor": -1,
            },
            {
                "event": "tick",
                "run_id": 4,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "mode_id": 2,
                "phase_markers": [],
                "channels": {"checkpoint": {"elapsed_ms": 33}},
            },
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 1
    assert result.traces[0].run_id == 4
    assert result.traces[0].tick_count == 1


def test_finalize_frida_jsonl_to_traces_rejects_missing_session_end_when_no_runs(tmp_path: Path) -> None:
    raw_path = _write_jsonl(tmp_path / "capture.jsonl", [{"event": "session_start"}])

    with pytest.raises(FridaFinalizeError, match="missing session_end"):
        finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)


def test_finalize_frida_jsonl_to_traces_names_runs_by_mode_not_stale_quest_stage(tmp_path: Path) -> None:
    raw_path = _write_jsonl(
        tmp_path / "capture.jsonl",
        [
            {"event": "session_start"},
            {"event": "run_start", "run_id": 1, "mode_id": 3, "quest_stage_major": 1, "quest_stage_minor": 5},
            {
                "event": "tick",
                "run_id": 1,
                "elapsed_ms": 0,
                "dt_ms_i32": 16,
                "mode_id": 3,
                "phase_markers": [],
                "channels": {"checkpoint": {"elapsed_ms": 0}},
            },
            {"event": "run_end", "run_id": 1},
            {"event": "run_start", "run_id": 2, "mode_id": 2, "quest_stage_major": 1, "quest_stage_minor": 5},
            {
                "event": "tick",
                "run_id": 2,
                "elapsed_ms": 16,
                "dt_ms_i32": 16,
                "mode_id": 2,
                "phase_markers": [],
                "channels": {"checkpoint": {"elapsed_ms": 16}},
            },
            {"event": "run_end", "run_id": 2},
            {"event": "run_start", "run_id": 3, "mode_id": 1, "quest_stage_major": 1, "quest_stage_minor": 5},
            {
                "event": "tick",
                "run_id": 3,
                "elapsed_ms": 33,
                "dt_ms_i32": 33,
                "mode_id": 1,
                "phase_markers": [],
                "channels": {"checkpoint": {"elapsed_ms": 33}},
            },
            {"event": "run_end", "run_id": 3},
            {"event": "session_end"},
        ],
    )

    result = finalize_frida_jsonl_to_traces(raw_path, output_dir=tmp_path / "out", delete_raw=False)
    assert len(result.traces) == 3
    names = sorted(trace.out_path.name for trace in result.traces)
    assert names == [
        "capture.mode_1.run1.cdt",
        "capture.mode_2.run1.cdt",
        "capture.quest_1_5.run1.cdt",
    ]
