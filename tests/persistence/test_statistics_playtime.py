from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.screens.actions import Route, StartRun
from crimson.screens.panels.stats import _format_playtime_text


def test_format_playtime_text_uses_hour_and_minute_buckets() -> None:
    assert _format_playtime_text(0) == "played for 0 hours 0 minutes"
    assert _format_playtime_text((2 * 60 * 60 + 35 * 60 + 59) * 1000) == "played for 2 hours 35 minutes"


@pytest.mark.parametrize(
    ("is_gameplay", "dt", "start_value", "expected_value"),
    [
        (True, 0.0169, 10, 26),
        (True, 0.016, 0xFFFFFFFF, 15),
        (True, 0.0289999999, 0, 29),
        (False, 0.5, 123, 123),
    ],
    ids=[
        "accumulates-for-gameplay",
        "wraps-native-u32-counter",
        "rounds-frame-time-to-f32-before-truncation",
        "skips-non-gameplay-views",
    ],
)
@pytest.mark.usefixtures("headless_window")
def test_tick_statistics_playtime_behavior(
    make_game_state,
    headless_resources,
    is_gameplay: bool,
    dt: float,
    start_value: int,
    expected_value: int,
) -> None:
    state = make_game_state(resources=headless_resources)
    loop = GameLoopView(state)
    loop.navigation.navigate(StartRun(GameMode.SURVIVAL) if is_gameplay else Route.MENU)
    state.status.play_time_ms = start_value

    loop._tick_statistics_playtime(dt)

    assert state.status.play_time_ms == expected_value
