from __future__ import annotations

import math

from ..math_parity import f32


def _field_label(field: str | None) -> str:
    if field and str(field).strip():
        return str(field)
    return "value"


def wire_f32(value: float, *, field: str | None = None) -> float:
    label = _field_label(field)
    narrowed = float(f32(float(value)))
    if not math.isfinite(narrowed):
        raise ValueError(f"{label} must be finite")
    return narrowed


def wire_f32_opt(value: float | None, *, field: str | None = None) -> float | None:
    if value is None:
        return None
    return wire_f32(float(value), field=field)


def assert_wire_f32(value: float, *, field: str | None = None) -> float:
    label = _field_label(field)
    candidate = float(value)
    if not math.isfinite(candidate):
        raise ValueError(f"{label} must be finite")
    narrowed = float(f32(candidate))
    if candidate != narrowed:
        raise ValueError(f"{label} must be f32-canonical")
    return candidate
