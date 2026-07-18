from __future__ import annotations


def should_apply_world_dt_steps_for_replay(
    *,
    original_capture_replay: bool,
) -> bool:
    # Native captures store the already transformed gameplay-entry delta.
    # Port-recorded fixed-step replays store the outer-loop delta and must
    # apply the perk transform during playback.
    return not bool(original_capture_replay)
