from __future__ import annotations

from crimson.sim.timing import nearest_ms_i32


def test_nearest_ms_i32_matches_frida_number_rounding() -> None:
    assert nearest_ms_i32(8.811999320983887) == 8812
    assert nearest_ms_i32(0.0005) == 1
