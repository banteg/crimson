from __future__ import annotations

from collections.abc import Callable

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.screens import menu
from crimson.screens.actions import Route, StartRun
from crimson.screens.menu import MenuView
from crimson.screens.panels.options import OptionsMenuView
from crimson.screens.panels.play_game import PlayGameMenuView
from crimson.ui.menu_layout import MENU_LABEL_ROW_OPTIONS
from grim.raylib_api import rl
from tests.support.screens import finish_transition

DPAD_UP = rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_UP
DPAD_DOWN = rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN
DPAD_RIGHT = rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_RIGHT
PAD_A = rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN
PAD_B = rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT


@pytest.fixture
def pad(headless_window, mocker) -> None:
    """One pad in the second slot, sticks at rest; `press` supplies its button edges."""
    mocker.patch.object(rl, "is_gamepad_available", side_effect=lambda gamepad: int(gamepad) == 1)
    mocker.patch.object(rl, "get_gamepad_axis_movement", return_value=0.0)
    mocker.patch.object(rl, "is_gamepad_button_pressed", return_value=False)


def press(loop: GameLoopView, mocker, *buttons: int) -> None:
    """One loop frame with `buttons` pressed on the pad, and nothing else."""
    pressed = {int(button) for button in buttons}
    mocker.patch.object(
        rl, "is_gamepad_button_pressed", side_effect=lambda gamepad, button: int(gamepad) == 1 and int(button) in pressed,
    )
    loop.update(0.016)
    mocker.patch.object(rl, "is_gamepad_button_pressed", return_value=False)


def dpad_to(loop: GameLoopView, mocker, focused: Callable[[], bool]) -> None:
    """D-pad down until the widget reports the focus."""
    for _ in range(40):
        if focused():
            return
        press(loop, mocker, DPAD_DOWN)
    raise AssertionError("the D-pad never reached the widget")


pytestmark = pytest.mark.usefixtures("pad")


def test_main_menu_to_a_survival_run_with_only_the_pad(loop, mocker) -> None:
    state = loop.state
    state.config.gameplay.player_count = 1
    finish_transition(loop)
    main = state.screens.active
    assert isinstance(main, MenuView)
    # The first item, Play Game, holds the focus of a fresh menu.
    press(loop, mocker, PAD_A)
    finish_transition(loop)

    panel = state.screens.active
    assert isinstance(panel, PlayGameMenuView)
    entries, *_ = panel._mode_entries()
    survival = next(entry for entry in entries if entry.game_mode == GameMode.SURVIVAL)
    finish_transition(loop)
    dpad_to(loop, mocker, lambda: panel._mode_buttons[survival.key].focused)
    press(loop, mocker, PAD_A)
    assert state.ui.pending == StartRun(GameMode.SURVIVAL)
    assert state.config.gameplay.mode == GameMode.SURVIVAL


def test_player_count_list_with_the_pad(loop, mocker) -> None:
    state = loop.state
    state.config.gameplay.player_count = 1
    loop.navigation.navigate(Route.PLAY_GAME)
    finish_transition(loop)
    panel = state.screens.active
    assert isinstance(panel, PlayGameMenuView)
    widget = panel.player_count_list

    dpad_to(loop, mocker, lambda: widget.focused)
    # A opens the focused list; the D-pad then walks its rows instead of the focus, and A takes one.
    press(loop, mocker, PAD_A)
    assert widget.open
    assert widget.active_index == 0
    press(loop, mocker, DPAD_DOWN)
    press(loop, mocker, DPAD_DOWN)
    assert widget.focused
    assert widget.active_index == 2
    press(loop, mocker, DPAD_UP)
    press(loop, mocker, PAD_A)
    assert not widget.open
    assert state.config.gameplay.player_count == 2
    # Closed again, the D-pad moves the focus on.
    press(loop, mocker, DPAD_DOWN)
    assert not widget.focused


def test_options_slider_with_the_pad(loop, mocker) -> None:
    finish_transition(loop)
    main = loop.state.screens.active
    assert isinstance(main, MenuView)
    options_entry = next(entry for entry in main._menu_entries if entry.row == MENU_LABEL_ROW_OPTIONS)
    dpad_to(loop, mocker, lambda: options_entry.focused)
    press(loop, mocker, PAD_A)
    finish_transition(loop)

    options = loop.state.screens.active
    assert isinstance(options, OptionsMenuView)
    slider = options._slider_detail
    slider.value = 3
    dpad_to(loop, mocker, lambda: slider.focused)
    press(loop, mocker, DPAD_RIGHT)
    assert slider.value == 4
    assert loop.state.config.display.detail_preset == 4


def test_pad_b_backs_out_of_a_panel(loop, mocker) -> None:
    loop.navigation.navigate(Route.PLAY_GAME)
    finish_transition(loop)
    press(loop, mocker, PAD_B)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, menu.MenuView)
