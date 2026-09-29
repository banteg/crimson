from __future__ import annotations

import pytest

from crimson.ui.checkbox import UiCheckbox, ui_checkbox_update
from crimson.ui.focus import UiFocus
from crimson.ui.perk_menu import UiButtonState
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
