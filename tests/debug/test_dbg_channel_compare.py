from __future__ import annotations

from crimson.dbg.canonical_channels import TimingSampleRow
from crimson.dbg.channel_compare import compare_timing_samples


def test_compare_timing_samples_equal_rows_match() -> None:
    rows = [
        TimingSampleRow(
            tick_index=0,
            gameplay_frame=123,
            phase="gpur_enter",
            write_kind="snapshot",
            frame_dt_f32=0.016666667,
            frame_dt_ms_i32=16,
            time_scale_active_entry=False,
            time_scale_factor=1.0,
        ),
    ]

    ok, detail = compare_timing_samples(rows, rows)

    assert ok
    assert detail is None


def test_compare_timing_samples_reports_first_mismatch_payload() -> None:
    expected_rows = [
        TimingSampleRow(
            tick_index=0,
            gameplay_frame=123,
            phase="gpur_enter",
            write_kind="snapshot",
            frame_dt_f32=0.016666667,
            frame_dt_ms_i32=16,
            time_scale_active_entry=False,
            time_scale_factor=1.0,
        ),
    ]
    actual_rows = [
        TimingSampleRow(
            tick_index=0,
            gameplay_frame=123,
            phase="gpur_enter",
            write_kind="snapshot",
            frame_dt_f32=0.015,
            frame_dt_ms_i32=15,
            time_scale_active_entry=False,
            time_scale_factor=1.0,
        ),
    ]

    ok, detail = compare_timing_samples(expected_rows, actual_rows)

    assert not ok
    assert detail is not None
    diff_count = detail["diff_count"]
    assert isinstance(diff_count, int)
    assert diff_count > 0
    assert detail["mismatches"]
