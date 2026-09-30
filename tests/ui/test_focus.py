from __future__ import annotations

import pytest

from crimson.ui.button import UiButtonState
from crimson.ui.checkbox import UiCheckbox, ui_checkbox_update
from crimson.ui.focus import UiFocus
from grim.geom import Vec2
from grim.raylib_api import rl


class Keys:
    """The keyboard as `rl.is_key_pressed` / `rl.is_key_down` report it for one frame."""

    def __init__(self, mocker) -> None:
        self.pressed: set[int] = set()
        self.down: set[int] = set()
        mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: int(key) in self.pressed)
        mocker.patch.object(rl, "is_key_down", side_effect=lambda key: int(key) in self.down)

    def frame(self, focus: UiFocus, *pressed: int, dt_ms: int = 16) -> None:
        self.pressed = {int(key) for key in pressed}
        focus.begin_frame(dt_ms)


@pytest.fixture
def keys(mocker) -> Keys:
    return Keys(mocker)


def register(focus: UiFocus, *widgets: object) -> list[bool]:
    return [focus.update(widget) for widget in widgets]


def test_tab_walks_the_candidates_and_wraps(keys: Keys) -> None:
    focus = UiFocus()
    a, b, c = UiButtonState("a"), UiButtonState("b"), UiButtonState("c")
    # Focus is judged against the previous frame's list, so the first frame only fills it.
    keys.frame(focus)
    assert register(focus, a, b, c) == [False, False, False]
    keys.frame(focus)
    assert register(focus, a, b, c) == [True, False, False]

    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    assert register(focus, a, b, c) == [False, True, False]
    assert focus.timer_ms == 1000
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    assert register(focus, a, b, c) == [True, False, False]

    # Shift+Tab walks back, wrapping to the last candidate.
    keys.down = {int(rl.KeyboardKey.KEY_LEFT_SHIFT)}
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    assert register(focus, a, b, c) == [False, False, True]


def test_tab_wraps_against_the_last_frame_that_registered(keys: Keys) -> None:
    focus = UiFocus()
    a, b = UiButtonState("a"), UiButtonState("b")
    keys.frame(focus)
    register(focus, a, b)
    # A frame without widgets (gameplay, say) keeps the list, as native's frame marker does.
    keys.frame(focus)
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    assert register(focus, a, b) == [True, False]


def test_hover_focuses_silently_and_the_marker_fades(keys: Keys, mocker) -> None:
    draw = mocker.patch.object(rl, "draw_rectangle_rec")
    focus = UiFocus()
    a, b = UiButtonState("a"), UiButtonState("b")
    keys.frame(focus)
    register(focus, a, b)

    # Hovering moves the focus without resetting the timer, so no marker shows.
    focus.set(b)
    keys.frame(focus)
    assert register(focus, a, b) == [False, True]
    focus.draw(Vec2(100.0, 50.0))
    draw.assert_not_called()

    # Tab restarts the one-second timer; the marker's alpha follows it down to nothing.
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    keys.frame(focus, dt_ms=500)
    assert focus.timer_ms == 500
    focus.draw(Vec2(100.0, 50.0))
    rect, color = draw.call_args.args
    assert (rect.x, rect.y, rect.width, rect.height) == (100.0, 54.0, 6.0, 6.0)
    assert color.a == int(0.4 * 255)
    keys.frame(focus, dt_ms=600)
    assert focus.timer_ms == 0
    draw.reset_mock()
    focus.draw(Vec2(100.0, 50.0))
    draw.assert_not_called()


def test_input_lock_holds_tab_and_the_checkbox(keys: Keys, headless_resources) -> None:
    focus = UiFocus()
    checkbox, button = UiCheckbox("Hardcore"), UiButtonState("Back")
    keys.frame(focus)
    register(focus, checkbox, button)

    focus.input_locked = True
    keys.frame(focus, rl.KeyboardKey.KEY_TAB)
    assert register(focus, checkbox, button) == [True, False]
    keys.frame(focus, rl.KeyboardKey.KEY_ENTER)
    assert not ui_checkbox_update(headless_resources, checkbox, Vec2(), focus=focus, mouse=Vec2(-1000.0, -1000.0), click=False)
    assert not checkbox.checked

    focus.input_locked = False
    keys.frame(focus, rl.KeyboardKey.KEY_ENTER)
    assert ui_checkbox_update(headless_resources, checkbox, Vec2(), focus=focus, mouse=Vec2(-1000.0, -1000.0), click=False)
    assert checkbox.checked


class Pad:
    """One connected pad's button edges and left stick, as raylib reports them."""

    def __init__(self, mocker) -> None:
        self.pressed: set[int] = set()
        self.stick = (0.0, 0.0)
        axes = {int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_X): 0, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_Y): 1}
        mocker.patch.object(rl, "is_gamepad_available", side_effect=lambda gamepad: int(gamepad) == 0)
        mocker.patch.object(rl, "is_gamepad_button_pressed", side_effect=lambda _pad, button: int(button) in self.pressed)
        mocker.patch.object(
            rl, "get_gamepad_axis_movement", side_effect=lambda _pad, axis: self.stick[axes[int(axis)]] if int(axis) in axes else 0.0,
        )

    def frame(self, focus: UiFocus, *buttons: int, stick: tuple[float, float] = (0.0, 0.0), dt_ms: int = 16) -> None:
        self.pressed = {int(button) for button in buttons}
        self.stick = stick
        focus.begin_frame(dt_ms)


def test_pad_buttons_stand_in_for_the_keys(keys: Keys, mocker) -> None:
    pad = Pad(mocker)
    focus = UiFocus()
    a, b, c = UiButtonState("a"), UiButtonState("b"), UiButtonState("c")
    pad.frame(focus)
    register(focus, a, b, c)

    # D-pad down/up are Tab/Shift+Tab.
    pad.frame(focus, rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN)
    assert register(focus, a, b, c) == [False, True, False]
    assert not focus.down
    pad.frame(focus, rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_UP)
    assert register(focus, a, b, c) == [True, False, False]

    # A held widget takes them as Up/Down for one frame instead.
    focus.hold(up=False, down=True)
    pad.frame(focus, rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN)
    assert register(focus, a, b, c) == [True, False, False]
    assert focus.down

    pad.frame(focus, rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_RIGHT, rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN)
    assert (focus.right, focus.enter, focus.escape) == (True, True, False)
    pad.frame(focus, rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT, rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_TRIGGER_1)
    assert (focus.escape, focus.page_down, focus.page_up) == (True, True, False)


def test_left_stick_steps_then_repeats(keys: Keys, mocker) -> None:
    pad = Pad(mocker)
    focus = UiFocus()
    widgets = [UiButtonState(str(index)) for index in range(8)]
    pad.frame(focus)
    register(focus, *widgets)

    def index_after(stick: tuple[float, float], dt_ms: int) -> int:
        pad.frame(focus, stick=stick, dt_ms=dt_ms)
        register(focus, *widgets)
        return focus.index

    # Past half travel it steps once, then again after 400 ms and every 120 ms while held.
    assert index_after((0.0, 0.3), 16) == 0
    assert index_after((0.1, 0.9), 16) == 1
    assert index_after((0.1, 0.9), 390) == 1
    assert index_after((0.1, 0.9), 10) == 2
    assert index_after((0.1, 0.9), 120) == 3
    assert index_after((0.0, 0.0), 16) == 3
    pad.frame(focus, stick=(-0.8, 0.2))
    assert focus.left

    # Gameplay turns the stick off; a push held over from it steps no sooner than a repeat.
    pad.stick = (0.0, 0.9)
    focus.begin_frame(16, stick=False)
    register(focus, *widgets)
    assert index_after((0.0, 0.9), 16) == 3
    assert index_after((0.0, 0.9), 400) == 4
