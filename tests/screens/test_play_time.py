from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.screens.actions import StartRun
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run

pytestmark = pytest.mark.usefixtures("headless_window")

FRAME_DT = 1.0 / 60.0  # (int)(0.016666668f * 1000.0f) = 16 ms


@pytest.fixture
def make_loop(make_game_state, headless_resources, mocker):
    def _make(mode: GameMode) -> GameLoopView:
        state = make_game_state(resources=headless_resources, audio=HeadlessAudio(mocker).state)
        start_run(state, StartRun(mode))
        return GameLoopView(state)

    return _make


def test_play_time_counts_gameplay_frames_with_the_console_closed(make_loop) -> None:
    loop = make_loop(GameMode.SURVIVAL)
    status = loop.state.status

    loop._tick_statistics_playtime(FRAME_DT)
    assert status.play_time_ms == 16

    loop.state.console.open_flag = True
    loop._tick_statistics_playtime(FRAME_DT)
    assert status.play_time_ms == 16


def test_play_time_stops_at_game_over(make_loop) -> None:
    loop = make_loop(GameMode.SURVIVAL)
    run = loop.state.screens.gameplay
    assert run is not None
    run._enter_game_over()

    loop._tick_statistics_playtime(FRAME_DT)

    assert loop.state.status.play_time_ms == 0


def test_typo_runs_add_no_play_time(make_loop) -> None:
    loop = make_loop(GameMode.TYPO)

    loop._tick_statistics_playtime(FRAME_DT)

    assert loop.state.status.play_time_ms == 0
