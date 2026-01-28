from __future__ import annotations

from crimson.quests.runtime import tick_quest_completion_transition


def test_tick_quest_completion_transition_resets_when_not_idle_complete() -> None:
    timer, completed = tick_quest_completion_transition(
        500.0,
        frame_dt_ms=16.0,
        creatures_none_active=False,
        spawn_table_empty=True,
    )
    assert timer == -1.0
    assert completed is False


def test_tick_quest_completion_transition_completes_after_delay() -> None:
    timer = -1.0
    completed = False
    for _ in range(10):
        timer, completed = tick_quest_completion_transition(
            timer,
            frame_dt_ms=100.0,
            creatures_none_active=True,
            spawn_table_empty=True,
        )
    assert timer >= 1000.0
    assert completed is True

