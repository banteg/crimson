from __future__ import annotations

from dataclasses import dataclass

DEMO_TOTAL_PLAY_TIME_MS = 2_400_000
DEMO_QUEST_GRACE_TIME_MS = 300_000


def format_demo_trial_time(ms: int) -> str:
    value = int(ms)
    if value < 0:
        value = 0
    minutes = value // 60_000
    seconds = (value // 1_000) % 60
    centiseconds = (value % 1_000) // 10
    return f"{minutes}:{seconds:02d}.{centiseconds:02d}"


@dataclass(frozen=True, slots=True)
class DemoTrialOverlayInfo:
    visible: bool
    kind: str  # "none" | "quest_tier_limit" | "quest_grace_left" | "time_up"
    remaining_ms: int
    remaining_label: str


def tick_demo_trial_timers(
    *,
    demo_build: bool,
    game_mode_id: int,
    overlay_visible: bool,
    global_playtime_ms: int,
    quest_grace_elapsed_ms: int,
    dt_ms: int,
) -> tuple[int, int]:
    """Advance demo timers by `dt_ms` (ms), returning updated values.

    This mirrors the classic behavior where:
      - global playtime accumulates until it hits `DEMO_TOTAL_PLAY_TIME_MS`, then clamps
      - once global time is exhausted, a quest-only grace timer becomes active
      - timers do not advance while the demo trial overlay is shown
    """

    if not demo_build:
        return int(global_playtime_ms), int(quest_grace_elapsed_ms)

    if int(game_mode_id) == 8:
        return int(global_playtime_ms), int(quest_grace_elapsed_ms)

    used_ms = max(0, int(global_playtime_ms))
    grace_ms = max(0, int(quest_grace_elapsed_ms))
    if used_ms >= DEMO_TOTAL_PLAY_TIME_MS and grace_ms < 1:
        grace_ms = 1
    used_ms = min(DEMO_TOTAL_PLAY_TIME_MS, used_ms)

    if overlay_visible:
        return int(used_ms), int(grace_ms)

    delta_ms = int(dt_ms)
    if delta_ms <= 0:
        return int(used_ms), int(grace_ms)

    used_ms = min(DEMO_TOTAL_PLAY_TIME_MS, used_ms + delta_ms)
    if used_ms >= DEMO_TOTAL_PLAY_TIME_MS and grace_ms < 1:
        grace_ms = 1

    if grace_ms > 0 and int(game_mode_id) == 3:
        grace_ms += delta_ms

    return int(used_ms), int(grace_ms)


def demo_trial_overlay_info(
    *,
    demo_build: bool,
    game_mode_id: int,
    global_playtime_ms: int,
    quest_grace_elapsed_ms: int,
    quest_stage_major: int,
    quest_stage_minor: int,
) -> DemoTrialOverlayInfo:
    """Compute demo trial overlay status.

    Modeled after `demo_trial_overlay_render` (0x004047c0) call sites and time formatting.

    Notes:
      - `global_playtime_ms` maps to `game_status_blob.game_sequence_id` (ms).
      - `quest_grace_elapsed_ms` maps to `demo_trial_elapsed_ms` (ms) once activated.
    """

    if not demo_build:
        return DemoTrialOverlayInfo(False, "none", 0, format_demo_trial_time(0))

    mode_id = int(game_mode_id)
    if mode_id == 8:  # tutorial
        return DemoTrialOverlayInfo(False, "none", 0, format_demo_trial_time(0))

    used_ms = max(0, int(global_playtime_ms))
    grace_ms = max(0, int(quest_grace_elapsed_ms))

    global_remaining_ms = max(0, DEMO_TOTAL_PLAY_TIME_MS - used_ms)
    grace_remaining_ms = max(0, DEMO_QUEST_GRACE_TIME_MS - grace_ms)

    tier_locked = mode_id == 3 and (int(quest_stage_major) > 1 or int(quest_stage_minor) > 10)

    if grace_ms > 0:
        if grace_remaining_ms <= 0:
            return DemoTrialOverlayInfo(True, "time_up", 0, format_demo_trial_time(0))
        if tier_locked:
            return DemoTrialOverlayInfo(
                True,
                "quest_tier_limit",
                int(grace_remaining_ms),
                format_demo_trial_time(grace_remaining_ms),
            )
        # During the quest-only grace period, the classic demo blocks other modes
        # and points the player back to Quests.
        if mode_id != 3:
            return DemoTrialOverlayInfo(
                True,
                "quest_grace_left",
                int(grace_remaining_ms),
                format_demo_trial_time(grace_remaining_ms),
            )
        return DemoTrialOverlayInfo(False, "none", int(grace_remaining_ms), format_demo_trial_time(grace_remaining_ms))

    if global_remaining_ms <= 0:
        return DemoTrialOverlayInfo(True, "time_up", 0, format_demo_trial_time(0))

    # Demo tier gating: the classic demo lets you play stage 1 quests only; once
    # the player reaches stage > 1, it shows the upsell overlay even if time remains.
    if tier_locked:
        return DemoTrialOverlayInfo(
            True,
            "quest_tier_limit",
            int(global_remaining_ms),
            format_demo_trial_time(global_remaining_ms),
        )

    return DemoTrialOverlayInfo(False, "none", int(global_remaining_ms), format_demo_trial_time(global_remaining_ms))
