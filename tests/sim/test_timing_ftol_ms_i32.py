from __future__ import annotations

from crimson.sim.timing import ftol_ms_i32, zero_gate_active_from_state


def test_ftol_ms_i32_tie_cases_are_truncation() -> None:
    assert ftol_ms_i32(0.0005) == 0
    assert ftol_ms_i32(0.0025) == 2
    assert ftol_ms_i32(-0.0015) == -1


def test_ftol_ms_i32_uses_float32_scale_path() -> None:
    assert ftol_ms_i32(1.0 / 60.0) == 16


def test_zero_gate_is_driven_by_demo_mode_only() -> None:
    assert zero_gate_active_from_state(demo_mode_active=False) is False
    assert zero_gate_active_from_state(demo_mode_active=True) is True
