from __future__ import annotations

import pytest

from crimson.demo_trial import (
    DEMO_QUEST_GRACE_TIME_MS,
    DEMO_TOTAL_PLAY_TIME_MS,
    demo_trial_overlay_info,
    format_demo_trial_time,
    tick_demo_trial_timers,
)
from crimson.game_modes import GameMode


def test_format_demo_trial_time() -> None:
    assert format_demo_trial_time(0) == "0:00.00"
    assert format_demo_trial_time(12_340) == "0:12.34"
    assert format_demo_trial_time(60_000) == "1:00.00"
    assert format_demo_trial_time(-1) == "0:00.00"


@pytest.mark.parametrize(
    (
        "demo_build",
        "game_mode_id",
        "global_playtime_ms",
        "quest_grace_elapsed_ms",
        "quest_stage_major",
        "quest_stage_minor",
        "expected_visible",
        "expected_kind",
        "expected_remaining_ms",
    ),
    [
        (False, GameMode.SURVIVAL, DEMO_TOTAL_PLAY_TIME_MS, DEMO_QUEST_GRACE_TIME_MS, 4, 10, False, "none", None),
        (True, GameMode.SURVIVAL, DEMO_TOTAL_PLAY_TIME_MS, 0, 1, 1, True, "time_up", 0),
        (True, GameMode.QUESTS, 0, 0, 2, 1, True, "quest_tier_limit", None),
        (
            True,
            GameMode.SURVIVAL,
            DEMO_TOTAL_PLAY_TIME_MS,
            1_000,
            1,
            1,
            True,
            "quest_grace_left",
            DEMO_QUEST_GRACE_TIME_MS - 1_000,
        ),
        (True, GameMode.QUESTS, DEMO_TOTAL_PLAY_TIME_MS, 1_000, 1, 1, False, "none", None),
        (
            True,
            GameMode.QUESTS,
            DEMO_TOTAL_PLAY_TIME_MS,
            1_000,
            2,
            1,
            True,
            "quest_tier_limit",
            DEMO_QUEST_GRACE_TIME_MS - 1_000,
        ),
    ],
    ids=[
        "hidden-when-not-demo",
        "shows-when-global-time-exhausted",
        "shows-tier-limit-while-time-remains",
        "uses-grace-timer",
        "grace-allows-quest-mode",
        "shows-tier-limit-during-grace",
    ],
)
def test_demo_trial_overlay_info(
    demo_build: bool,
    game_mode_id: GameMode,
    global_playtime_ms: int,
    quest_grace_elapsed_ms: int,
    quest_stage_major: int,
    quest_stage_minor: int,
    expected_visible: bool,
    expected_kind: str,
    expected_remaining_ms: int | None,
) -> None:
    info = demo_trial_overlay_info(
        demo_build=demo_build,
        game_mode_id=game_mode_id,
        global_playtime_ms=global_playtime_ms,
        quest_grace_elapsed_ms=quest_grace_elapsed_ms,
        quest_stage_major=quest_stage_major,
        quest_stage_minor=quest_stage_minor,
    )
    assert info.visible is expected_visible
    assert info.kind == expected_kind
    if expected_remaining_ms is not None:
        assert info.remaining_ms == expected_remaining_ms


@pytest.mark.parametrize(
    ("overlay_visible", "global_playtime_ms", "quest_grace_elapsed_ms", "dt_ms"),
    [
        (False, DEMO_TOTAL_PLAY_TIME_MS - 5, 0, 10),
        (True, DEMO_TOTAL_PLAY_TIME_MS, 0, 0),
    ],
    ids=["accumulates-and-starts-grace", "starts-grace-even-when-overlay-visible"],
)
def test_tick_demo_trial_timers_starts_grace_after_time_limit(
    overlay_visible: bool,
    global_playtime_ms: int,
    quest_grace_elapsed_ms: int,
    dt_ms: int,
) -> None:
    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=GameMode.SURVIVAL,
        overlay_visible=overlay_visible,
        global_playtime_ms=global_playtime_ms,
        quest_grace_elapsed_ms=quest_grace_elapsed_ms,
        dt_ms=dt_ms,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 1


def test_tick_demo_trial_timers_grace_counts_only_in_quests() -> None:
    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=GameMode.QUESTS,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1,
        dt_ms=100,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 101

    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=GameMode.SURVIVAL,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1,
        dt_ms=100,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 1
