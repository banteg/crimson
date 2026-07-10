from __future__ import annotations

from typing import cast

from crimson.dbg.canonical_channels import RngStreamRow, TimingSampleRow
from crimson.dbg.channel_compare import compare_rng_stream, compare_timing_samples


def _timing_sample(**overrides: object) -> TimingSampleRow:
    values: dict[str, object] = {
        "tick_index": 0,
        "gameplay_frame": 123,
        "phase": "gpur_enter",
        "write_kind": "snapshot",
        "frame_dt_f32": 0.016666667,
        "frame_dt_ms_i32": 16,
        "frame_dt_ms_f32": 16.0,
        "time_scale_active_entry": False,
        "time_scale_active_current": False,
        "time_scale_factor": 1.0,
        "bonus_reflex_boost_timer": 0.0,
        "mode_fn": "gameplay_update_and_render",
        "player_index": None,
    }
    values.update(overrides)
    return TimingSampleRow(**values)  # type: ignore[arg-type]


def test_compare_timing_samples_equal_rows_match() -> None:
    rows = [_timing_sample()]

    ok, detail = compare_timing_samples(rows, rows)

    assert ok
    assert detail is None


def test_compare_timing_samples_reports_first_mismatch_payload() -> None:
    expected_rows = [_timing_sample()]
    actual_rows = [_timing_sample(frame_dt_f32=0.015, frame_dt_ms_i32=15)]

    ok, detail = compare_timing_samples(expected_rows, actual_rows)

    assert not ok
    assert detail is not None
    diff_count = detail["diff_count"]
    assert isinstance(diff_count, int)
    assert diff_count > 0
    assert detail["mismatches"]


def test_compare_rng_stream_reports_caller_only_difference_as_diagnostic() -> None:
    expected_rows = [
        RngStreamRow(
            tick_call_index=1,
            value_15=28052,
            state_before_u32=2427270273,
            state_after_u32=3985917248,
            caller=0x004281A2,
        ),
    ]
    actual_rows = [
        RngStreamRow(
            tick_call_index=1,
            value_15=28052,
            state_before_u32=2427270273,
            state_after_u32=3985917248,
            caller=0x00430B88,
        ),
    ]

    ok, detail = compare_rng_stream(expected_rows, actual_rows)

    assert ok
    assert detail is not None
    assert detail["classification"] == "caller_attribution_only"
    assert detail["behavior_ok"] is True
    assert detail["caller_attribution_ok"] is False
    expected_first = detail["expected_first_mismatch"]
    actual_first = detail["actual_first_mismatch"]
    assert isinstance(expected_first, dict)
    assert isinstance(actual_first, dict)
    assert expected_first["caller"] == 0x004281A2
    assert expected_first["caller_hex"] == "0x004281a2"
    assert actual_first["caller"] == 0x00430B88
    assert actual_first["caller_hex"] == "0x00430b88"


def test_compare_rng_stream_keeps_state_difference_behavioral() -> None:
    expected = [RngStreamRow(1, 28052, 2427270273, 3985917248, 0x004281A2)]
    actual = [RngStreamRow(1, 28053, 2427270273, 3985917249, 0x004281A2)]

    ok, detail = compare_rng_stream(expected, actual)

    assert not ok
    assert detail is not None
    assert detail["classification"] == "rng_behavior"
    assert detail["behavior_prefix_match_len"] == 0


def test_float_mismatch_reports_f32_bits_and_ulp_distance() -> None:
    expected_rows = [_timing_sample(frame_dt_f32=1.0)]
    actual_rows = [_timing_sample(frame_dt_f32=1.0000001192092896)]

    ok, detail = compare_timing_samples(expected_rows, actual_rows)

    assert not ok
    assert detail is not None
    mismatches = detail["mismatches"]
    assert isinstance(mismatches, list)
    mismatch = cast("dict[str, object]", mismatches[0])
    assert mismatch["expected_f32_hex"] == "0x3f800000"
    assert mismatch["actual_f32_hex"] == "0x3f800001"
    assert mismatch["f32_ulp_distance"] == 1


def test_float_mismatch_preserves_signed_zero() -> None:
    expected_rows = [_timing_sample(frame_dt_ms_f32=-0.0)]
    actual_rows = [_timing_sample(frame_dt_ms_f32=0.0)]

    ok, detail = compare_timing_samples(expected_rows, actual_rows)

    assert not ok
    assert detail is not None
    mismatches = detail["mismatches"]
    assert isinstance(mismatches, list)
    mismatch = cast("dict[str, object]", mismatches[0])
    assert mismatch["expected_f32_hex"] == "0x80000000"
    assert mismatch["actual_f32_hex"] == "0x00000000"
