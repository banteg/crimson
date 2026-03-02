from __future__ import annotations

import math

from ..math_parity import f32


def ftol_ms_i32(dt_seconds: float) -> int:
    """Convert seconds -> integer milliseconds via float32 scale + truncation."""

    dt_f32 = f32(float(dt_seconds))
    scaled_ms_f32 = f32(float(dt_f32) * 1000.0)
    return int(math.trunc(float(scaled_ms_f32)))
