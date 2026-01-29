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


def demo_trial_overlay_info(
    *,
    demo_build: bool,
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

    used_ms = max(0, int(global_playtime_ms))
    grace_ms = max(0, int(quest_grace_elapsed_ms))

    global_remaining_ms = DEMO_TOTAL_PLAY_TIME_MS - used_ms

    use_grace = grace_ms > 0
    remaining_ms = (DEMO_QUEST_GRACE_TIME_MS - grace_ms) if use_grace else global_remaining_ms

    # Demo tier gating: classic demo lets you play stage 1 quests only; once the
    # player reaches stage > 1, it shows the upsell overlay even if time remains.
    if used_ms < DEMO_TOTAL_PLAY_TIME_MS and (int(quest_stage_major) > 1 or int(quest_stage_minor) > 10):
        return DemoTrialOverlayInfo(
            True,
            "quest_tier_limit",
            int(remaining_ms),
            format_demo_trial_time(remaining_ms),
        )

    if remaining_ms <= 0:
        return DemoTrialOverlayInfo(True, "time_up", 0, format_demo_trial_time(0))

    if use_grace:
        return DemoTrialOverlayInfo(
            True,
            "quest_grace_left",
            int(remaining_ms),
            format_demo_trial_time(remaining_ms),
        )

    return DemoTrialOverlayInfo(False, "none", int(remaining_ms), format_demo_trial_time(remaining_ms))

