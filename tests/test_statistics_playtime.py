from __future__ import annotations

from crimson.frontend.panels.stats import _format_playtime_text
from crimson.game.loop_view import GameLoopView


def test_format_playtime_text_uses_hour_and_minute_buckets() -> None:
    assert _format_playtime_text(0) == "played for 0 hours 0 minutes"
    assert _format_playtime_text((2 * 60 * 60 + 35 * 60 + 59) * 1000) == "played for 2 hours 35 minutes"


def test_format_playtime_text_pluralizes_in_default_mode() -> None:
    assert _format_playtime_text((1 * 60 * 60 + 1 * 60) * 1000) == "played for 1 hour 1 minute"
    assert _format_playtime_text((1 * 60 * 60 + 2 * 60) * 1000) == "played for 1 hour 2 minutes"


def test_format_playtime_text_preserve_bugs_keeps_native_plural_form() -> None:
    assert (
        _format_playtime_text(
            (1 * 60 * 60 + 1 * 60) * 1000,
            preserve_bugs=True,
        )
        == "played for 1 hours 1 minutes"
    )


def test_tick_statistics_playtime_accumulates_for_non_demo_gameplay(make_game_state) -> None:
    state = make_game_state(demo_enabled=False)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views["start_survival"]
    state.status.game_sequence_id = 10

    loop._tick_statistics_playtime(0.0169)

    assert state.status.game_sequence_id == 26


def test_tick_statistics_playtime_skips_non_gameplay_views(make_game_state) -> None:
    state = make_game_state(demo_enabled=False)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views["open_statistics"]
    state.status.game_sequence_id = 123

    loop._tick_statistics_playtime(0.5)

    assert state.status.game_sequence_id == 123


def test_tick_statistics_playtime_skips_demo_builds(make_game_state) -> None:
    state = make_game_state(demo_enabled=True)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views["start_survival"]
    state.status.game_sequence_id = 123

    loop._tick_statistics_playtime(0.5)

    assert state.status.game_sequence_id == 123
