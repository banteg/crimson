from __future__ import annotations

import math


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


def should_apply_world_dt_steps_for_replay(
    *,
    original_capture_replay: bool,
    dt_frame_overrides: dict[int, float] | None,
) -> bool:
    if not bool(original_capture_replay):
        return True
    has_capture_dt_overrides = bool(dt_frame_overrides)
    if bool(has_capture_dt_overrides):
        return False
    return True
