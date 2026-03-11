from __future__ import annotations

from crimson.dbg.canonical_channels import RngStreamRow, TimingSampleRow
from crimson.dbg.channel_compare import compare_rng_stream, compare_timing_samples


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


def test_compare_rng_stream_reports_caller_static_hex_on_first_mismatch() -> None:
    expected_rows = [
        RngStreamRow(
            tick_call_index=1,
            value_15=28052,
            state_before_u32=2427270273,
            state_after_u32=3985917248,
            caller_static_u32=0x004281A2,
        ),
    ]
    actual_rows = [
        RngStreamRow(
            tick_call_index=1,
            value_15=28052,
            state_before_u32=2427270273,
            state_after_u32=3985917248,
            caller_static_u32=0x00430B88,
        ),
    ]

    ok, detail = compare_rng_stream(expected_rows, actual_rows)

    assert not ok
    assert detail is not None
    expected_first = detail["expected_first_mismatch"]
    actual_first = detail["actual_first_mismatch"]
    assert isinstance(expected_first, dict)
    assert isinstance(actual_first, dict)
    assert expected_first["caller_static_u32"] == 0x004281A2
    assert expected_first["caller_static_hex"] == "0x004281a2"
    assert actual_first["caller_static_u32"] == 0x00430B88
    assert actual_first["caller_static_hex"] == "0x00430b88"
