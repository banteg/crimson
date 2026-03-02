from __future__ import annotations

import math

from ..timing import ftol_ms_i32


def resolve_dt_frame(
    *,
    tick_index: int,
    default_dt_frame: float,
    dt_frame_overrides: dict[int, float] | None,
) -> float:
    if not dt_frame_overrides:
        return float(default_dt_frame)
    override = dt_frame_overrides.get(int(tick_index))
    if override is None:
        return float(default_dt_frame)
    dt_frame = float(override)
    if not math.isfinite(dt_frame) or dt_frame <= 0.0:
        return float(default_dt_frame)
    return float(dt_frame)


def resolve_dt_frame_ms_i32(
    *,
    tick_index: int,
    dt_frame: float,
    dt_frame_ms_i32_overrides: dict[int, int] | None,
) -> int | None:
    if dt_frame_ms_i32_overrides is None:
        return None
    if dt_frame_ms_i32_overrides:
        override = dt_frame_ms_i32_overrides.get(int(tick_index))
        if override is not None and int(override) > 0:
            return int(override)
    dt_ms_i32 = ftol_ms_i32(float(dt_frame))
    if dt_ms_i32 <= 0:
        return 1
    return int(dt_ms_i32)


def should_apply_world_dt_steps_for_replay(
    *,
    original_capture_replay: bool,
    dt_frame_overrides: dict[int, float] | None,
    dt_frame_ms_i32_overrides: dict[int, int] | None,
) -> bool:
    if not bool(original_capture_replay):
        return True
    has_capture_dt_overrides = bool(dt_frame_overrides) or bool(dt_frame_ms_i32_overrides)
    if bool(has_capture_dt_overrides):
        return False
    return True
