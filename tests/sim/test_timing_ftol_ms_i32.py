from __future__ import annotations

from crimson.sim.timing import FrameTiming, ftol_ms_i32, nearest_ms_i32


def test_ftol_ms_i32_tie_cases_are_truncation() -> None:
    assert ftol_ms_i32(0.0005) == 0
    assert ftol_ms_i32(0.0025) == 2
    assert ftol_ms_i32(-0.0015) == -1


def test_ftol_ms_i32_uses_float32_scale_path() -> None:
    assert ftol_ms_i32(1.0 / 60.0) == 16


def test_nearest_ms_i32_matches_frida_number_rounding() -> None:
    assert nearest_ms_i32(8.811999320983887) == 8812
    assert nearest_ms_i32(0.0005) == 1


def test_frame_timing_defaults_to_live_dt_when_zero_gate_disabled() -> None:
    timing = FrameTiming.compute(
        1.0 / 60.0,
        time_scale_active_entry=False,
        time_scale_factor=1.0,
        zero_gate_active=False,
    )
    assert timing.zero_gate_active is False
    assert timing.dt_sim > 0.0
