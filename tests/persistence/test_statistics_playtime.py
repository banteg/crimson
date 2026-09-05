from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.screens.panels.stats import _format_playtime_text


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
    ("demo_enabled", "front_view_key", "dt", "start_value", "expected_value"),
    [
        (False, "start_survival", 0.0169, 10, 26),
        (False, "open_statistics", 0.5, 123, 123),
        (True, "start_survival", 0.5, 123, 123),
    ],
    ids=[
        "accumulates-for-non-demo-gameplay",
        "skips-non-gameplay-views",
        "skips-demo-builds",
    ],
)
def test_tick_statistics_playtime_behavior(
    make_game_state,
    demo_enabled: bool,
    front_view_key: str,
    dt: float,
    start_value: int,
    expected_value: int,
) -> None:
    state = make_game_state(demo_enabled=demo_enabled)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views[front_view_key]
    state.status.play_time_ms = start_value

    loop._tick_statistics_playtime(dt)

    assert state.status.play_time_ms == expected_value
