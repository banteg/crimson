from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.screens.actions import Route, StartRun
from crimson.screens.pause_menu import PauseMenuView
from crimson.ui.animation import ui_element_timeline_window
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")


@pytest.fixture
def paused(make_game_state, headless_resources, mocker):
    """A survival run paused the way the game pauses it, with the pause menu slid in."""
    audio = HeadlessAudio(mocker)
    state = make_game_state(resources=headless_resources, audio=audio.state)
    navigator, run = start_run(state, StartRun.from_config(state.config, GameMode.SURVIVAL))
    navigator.navigate(Route.PAUSE)
    view = state.screens.active
    assert isinstance(view, PauseMenuView)
    while not state.ui.opened:
        view.update(0.1)
    return view, run, audio


def _press(view: PauseMenuView, mocker, key: int) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda pressed: pressed == key)
    view.update(0.016)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)


def test_pause_menu_quit_fades_the_paused_run_toward_the_main_menu(paused, mocker) -> None:
    view, run, audio = paused
    # Tab moves focus from Options to Quit; Enter picks it.
    _press(view, mocker, rl.KeyboardKey.KEY_TAB)
    _press(view, mocker, rl.KeyboardKey.KEY_ENTER)
    assert view.state.ui.closing
    assert view.state.ui.pending == Route.MENU
    assert audio.played() == [SfxId.UI_PANELCLICK, SfxId.UI_BUTTONCLICK]

    mocker.patch.object(run, "_draw_world")
    background = mocker.spy(run, "draw_pause_background")
    view.state.ui.timeline_ms = ui_element_timeline_window(28)[1] // 2
    view.draw()

    background.assert_called_once_with(entity_alpha=0.5)


def test_pause_menu_back_keeps_the_paused_run_opaque(paused, mocker) -> None:
    view, run, audio = paused
    _press(view, mocker, rl.KeyboardKey.KEY_ESCAPE)
    assert view.state.ui.closing
    assert view.state.ui.pending == Route.BACK
    assert audio.played() == [SfxId.UI_PANELCLICK, SfxId.UI_BUTTONCLICK]

    mocker.patch.object(run, "_draw_world")
    background = mocker.spy(run, "draw_pause_background")
    view.state.ui.timeline_ms = 0
    view.draw()

    background.assert_called_once_with(entity_alpha=1.0)
