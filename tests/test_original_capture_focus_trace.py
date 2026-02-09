from __future__ import annotations


def _load_focus_trace_module():
    from crimson.original import focus_trace

    return focus_trace


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


def test_rng_alignment_reports_native_caller_gap_and_fire_bullets_loop_parity() -> None:
    focus = _load_focus_trace_module()
    summary = focus._summarize_rng_alignment(
        capture_rng_head=[
            {"value": 10, "caller_static": "0x0042176f", "caller": "native+176f"},
            {"value": 11, "caller_static": "0x0042184c", "caller": "native+184c"},
            {"value": 12, "caller_static": "0x00421799", "caller": "native+1799"},
            {"value": 13, "caller_static": "0x0042176f", "caller": "native+176f"},
            {"value": 14, "caller_static": "0x0042184c", "caller": "native+184c"},
            {"value": 15, "caller_static": "0x0042176f", "caller": "native+176f"},
            {"value": 16, "caller_static": "0x0042184c", "caller": "native+184c"},
            {"value": 17, "caller_static": "0x0042176f", "caller": "native+176f"},
        ],
        capture_rng_calls=8,
        rewrite_rng_values=[10, 11, 12, 13, 14, 15],
        rewrite_rng_callsites=[
            "rewrite:seed",
            "rewrite:pre_freeze",
            "rewrite:midrange",
            "rewrite:seed",
            "rewrite:pre_freeze",
            "rewrite:seed",
        ],
        tail_preview_limit=8,
    )

    gaps = focus._build_native_caller_gaps(summary, limit=8)
    seed_gap = next(row for row in gaps if row.native_caller_static == "0x0042176f")
    assert int(seed_gap.capture_count) == 4
    assert str(seed_gap.inferred_rewrite_callsite) == "rewrite:seed"
    assert int(seed_gap.rewrite_count) == 3
    assert int(seed_gap.gap) == 1

    parity = focus._build_fire_bullets_loop_parity(summary)
    assert parity is not None
    assert int(parity.capture_iterations) == 4
    assert int(parity.rewrite_iterations) == 3
    assert int(parity.missing_iterations) == 1
    assert int(parity.loop_iterations_per_hit) == 6
    assert int(parity.capture_midrange_rolls) == 1
    assert int(parity.rewrite_midrange_rolls) == 1
    assert int(parity.capture_pre_freeze_rolls) == 3
    assert int(parity.rewrite_pre_freeze_rolls) == 2
