from __future__ import annotations


def should_apply_world_dt_steps_for_replay(
    *,
    original_capture_replay: bool,
) -> bool:
    _ = original_capture_replay
    return True
