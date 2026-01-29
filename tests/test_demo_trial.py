from __future__ import annotations

from crimson.demo_trial import (
    DEMO_QUEST_GRACE_TIME_MS,
    DEMO_TOTAL_PLAY_TIME_MS,
    demo_trial_overlay_info,
    format_demo_trial_time,
    tick_demo_trial_timers,
)


def test_format_demo_trial_time() -> None:
    assert format_demo_trial_time(0) == "0:00.00"
    assert format_demo_trial_time(12_340) == "0:12.34"
    assert format_demo_trial_time(60_000) == "1:00.00"
    assert format_demo_trial_time(-1) == "0:00.00"


def test_demo_trial_overlay_hidden_when_not_demo() -> None:
    info = demo_trial_overlay_info(
        demo_build=False,
        game_mode_id=1,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=DEMO_QUEST_GRACE_TIME_MS,
        quest_stage_major=4,
        quest_stage_minor=10,
    )
    assert info.visible is False
    assert info.kind == "none"


def test_demo_trial_overlay_shows_when_global_time_exhausted() -> None:
    info = demo_trial_overlay_info(
        demo_build=True,
        game_mode_id=1,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=0,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    assert info.visible is True
    assert info.kind == "time_up"
    assert info.remaining_ms == 0


def test_demo_trial_overlay_shows_tier_limit_while_time_remains() -> None:
    info = demo_trial_overlay_info(
        demo_build=True,
        game_mode_id=3,
        global_playtime_ms=0,
        quest_grace_elapsed_ms=0,
        quest_stage_major=2,
        quest_stage_minor=1,
    )
    assert info.visible is True
    assert info.kind == "quest_tier_limit"


def test_demo_trial_overlay_uses_grace_timer() -> None:
    info = demo_trial_overlay_info(
        demo_build=True,
        game_mode_id=1,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1_000,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    assert info.visible is True
    assert info.kind == "quest_grace_left"
    assert info.remaining_ms == DEMO_QUEST_GRACE_TIME_MS - 1_000


def test_demo_trial_overlay_grace_allows_quest_mode() -> None:
    info = demo_trial_overlay_info(
        demo_build=True,
        game_mode_id=3,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1_000,
        quest_stage_major=1,
        quest_stage_minor=1,
    )
    assert info.visible is False
    assert info.kind == "none"


def test_tick_demo_trial_timers_accumulates_and_starts_grace() -> None:
    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=1,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS - 5,
        quest_grace_elapsed_ms=0,
        dt_ms=10,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 1


def test_tick_demo_trial_timers_grace_counts_only_in_quests() -> None:
    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=3,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1,
        dt_ms=100,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 101

    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=1,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1,
        dt_ms=100,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 1
