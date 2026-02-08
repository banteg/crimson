from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def _load_focus_trace_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "original_capture_focus_trace.py"
    spec = importlib.util.spec_from_file_location("original_capture_focus_trace", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_rng_alignment_reports_prefix_and_tail_callers() -> None:
    focus = _load_focus_trace_module()
    summary = focus._summarize_rng_alignment(
        capture_rng_head=[
            {"value": 11, "caller_static": "0xAAA", "caller": "native+0xaaa"},
            {"value": 12, "caller_static": "0xAAA", "caller": "native+0xaaa"},
            {"value": 13, "caller_static": "0xBBB", "caller": "native+0xbbb"},
            {"value": 14, "caller_static": "0xCCC", "caller": "native+0xccc"},
            {"value": 15, "caller_static": "0xCCC", "caller": "native+0xccc"},
        ],
        capture_rng_calls=5,
        rewrite_rng_values=[11, 12, 13],
        rewrite_rng_callsites=["rewrite:one", "rewrite:one", "rewrite:two"],
        tail_preview_limit=8,
    )

    assert int(summary.capture_calls) == 5
    assert int(summary.capture_head_len) == 5
    assert int(summary.rewrite_calls) == 3
    assert int(summary.value_prefix_match) == 3
    assert summary.first_value_mismatch_index is None
    assert int(summary.missing_native_tail_count) == 2
    assert summary.missing_native_tail_callers_top[0] == ("0xCCC", 2)
    assert len(summary.missing_native_tail_preview) == 2
    assert summary.missing_native_tail_preview[0].capture_caller_static == "0xCCC"
    assert summary.missing_native_tail_preview[0].inferred_rewrite_callsite == ""


def test_rng_alignment_reports_first_value_mismatch() -> None:
    focus = _load_focus_trace_module()
    summary = focus._summarize_rng_alignment(
        capture_rng_head=[
            {"value": 100, "caller_static": "0x111", "caller": "native+0x111"},
            {"value": 101, "caller_static": "0x111", "caller": "native+0x111"},
            {"value": 999, "caller_static": "0x222", "caller": "native+0x222"},
        ],
        capture_rng_calls=3,
        rewrite_rng_values=[100, 101, 555],
        rewrite_rng_callsites=["a", "b", "c"],
        tail_preview_limit=8,
    )

    assert int(summary.value_prefix_match) == 2
    assert int(summary.first_value_mismatch_index or -1) == 2
    assert int(summary.first_value_mismatch_capture or -1) == 999
    assert int(summary.first_value_mismatch_rewrite or -1) == 555
    assert int(summary.missing_native_tail_count) == 0

