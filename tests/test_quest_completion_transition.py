from __future__ import annotations

from crimson.modes.quest_mode import _quest_complete_banner_alpha
from crimson.quests.runtime import QUEST_COMPLETION_TRANSITION_MS, tick_quest_completion_transition


def test_tick_quest_completion_transition_resets_when_not_idle_complete() -> None:
    timer, completed, play_hit_sfx, play_completion_music = tick_quest_completion_transition(
        500.0,
        frame_dt_ms=16.0,
        creatures_none_active=False,
        spawn_table_empty=True,
    )
    assert timer == -1.0
    assert completed is False
    assert play_hit_sfx is False
    assert play_completion_music is False


def test_tick_quest_completion_transition_completes_after_delay() -> None:
    timer = -1.0
    completed = False
    for _ in range(30):
        timer, completed, _play_hit_sfx, _play_completion_music = tick_quest_completion_transition(
            timer,
            frame_dt_ms=100.0,
            creatures_none_active=True,
            spawn_table_empty=True,
        )
        if completed:
            break
    assert timer > QUEST_COMPLETION_TRANSITION_MS
    assert completed is True


def test_tick_quest_completion_transition_triggers_hit_sfx_in_native_window() -> None:
    timer, completed, play_hit_sfx, play_completion_music = tick_quest_completion_transition(
        801.0,
        frame_dt_ms=16.0,
        creatures_none_active=True,
        spawn_table_empty=True,
    )
    assert timer == 851.0 + 16.0
    assert completed is False
    assert play_hit_sfx is True
    assert play_completion_music is False


def test_tick_quest_completion_transition_triggers_completion_music_in_native_window() -> None:
    timer, completed, play_hit_sfx, play_completion_music = tick_quest_completion_transition(
        2001.0,
        frame_dt_ms=16.0,
        creatures_none_active=True,
        spawn_table_empty=True,
    )
    assert timer == 2051.0 + 16.0
    assert completed is False
    assert play_hit_sfx is False
    assert play_completion_music is True


def test_quest_complete_banner_alpha_matches_native_envelope() -> None:
    assert _quest_complete_banner_alpha(0.0) == 0.0
    assert _quest_complete_banner_alpha(250.0) == 0.5
    assert _quest_complete_banner_alpha(500.0) == 1.0
    assert _quest_complete_banner_alpha(1500.0) == 1.0
    assert _quest_complete_banner_alpha(1750.0) == 0.5
    assert _quest_complete_banner_alpha(2000.0) == 0.0
