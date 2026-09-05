from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.screens.panels.stats import _format_playtime_text
from crimson.screens.stack import ScreenEntry
from tests.support.gameplay_screen import GameplayScreenStub
from tests.support.screens import ScreenStub


def test_format_playtime_text_uses_hour_and_minute_buckets() -> None:
    assert _format_playtime_text(0) == "played for 0 hours 0 minutes"
    assert _format_playtime_text((2 * 60 * 60 + 35 * 60 + 59) * 1000) == "played for 2 hours 35 minutes"


def test_format_playtime_text_pluralizes_in_default_mode() -> None:
    assert _format_playtime_text((1 * 60 * 60 + 1 * 60) * 1000) == "played for 1 hours 1 minutes"
    assert _format_playtime_text((1 * 60 * 60 + 2 * 60) * 1000) == "played for 1 hours 2 minutes"


def test_format_playtime_text_preserve_bugs_keeps_native_plural_form() -> None:
    assert (
        _format_playtime_text(
            (1 * 60 * 60 + 1 * 60) * 1000,
            preserve_bugs=True,
        )
        == "played for 1 hours 1 minutes"
    )


@pytest.mark.parametrize(
    ("demo_enabled", "is_gameplay", "dt", "start_value", "expected_value"),
    [
        (False, True, 0.0169, 10, 26),
        (False, True, 0.016, 0xFFFFFFFF, 15),
        (False, True, 0.0289999999, 0, 29),
        (False, False, 0.5, 123, 123),
        (True, True, 0.5, 123, 123),
    ],
    ids=[
        "accumulates-for-non-demo-gameplay",
        "wraps-native-u32-counter",
        "rounds-frame-time-to-f32-before-truncation",
        "skips-non-gameplay-views",
        "skips-demo-builds",
    ],
)
def test_tick_statistics_playtime_behavior(
    make_game_state,
    demo_enabled: bool,
    is_gameplay: bool,
    dt: float,
    start_value: int,
    expected_value: int,
) -> None:
    state = make_game_state(demo_enabled=demo_enabled)
    loop = GameLoopView(state)
    active = GameplayScreenStub() if is_gameplay else ScreenStub()
    state.screens.push(ScreenEntry(active, gameplay=active if isinstance(active, GameplayScreenStub) else None))
    state.status.play_time_ms = start_value

    loop._tick_statistics_playtime(dt)

    assert state.status.play_time_ms == expected_value
