from __future__ import annotations

import pytest

from crimson.screens.actions import Route
from crimson.screens.panels import controls
from crimson.screens.panels.controls import ControlsMenuView, RebindCapture
from crimson.screens.panels.controls_labels import RebindRowSpec, RebindTarget
from grim.raylib_api import rl

LISTS = (
    ("move_method_list", controls.CONTROLS_MOVE_METHOD_LIST_OFFSET),
    ("aim_method_list", controls.CONTROLS_AIM_METHOD_LIST_OFFSET),
    ("player_list", controls.CONTROLS_PLAYER_LIST_OFFSET),
)


@pytest.mark.parametrize(("name", "_offset"), LISTS)
def test_open_list_consumes_escape_before_back(controls_view, name, _offset, mocker) -> None:
    view = controls_view
    view._capture = None
    getattr(view, name).open = True
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    view.update(0.016)
    assert not getattr(view, name).open
    assert not view.state.ui.closing
    view.update(0.016)
    assert view.state.ui.pending is Route.BACK


@pytest.mark.parametrize(("name", "offset"), LISTS)
def test_enter_on_a_list_header_opens_it_instead_of_leaving(controls_view, name, offset, mocker) -> None:
    view = controls_view
    view._capture = None
    header = view._left_panel_top_left() + offset
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(header.x + 5.0, header.y + 5.0))
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)
    view.update(0.016)
    assert getattr(view, name).open
    assert not view.state.ui.closing


@pytest.fixture
def controls_view(make_game_state, screen_resources, screen_io) -> ControlsMenuView:
    view = ControlsMenuView(make_game_state(resources=screen_resources))
    view.open()
    view.state.ui.timeline_ms = view.state.ui.max_timeline_ms
    view._capture = RebindCapture(RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE), 0, skip_frames=0)
    return view


def test_escape_cancels_capture_before_navigation(controls_view, mocker) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    controls_view.update(0.016)
    assert controls_view._capture is None
    assert not controls_view.state.ui.closing
    assert controls_view.take_action() is None

    # A subsequent Escape can leave the screen after capture releases input.
    controls_view.update(0.016)
    assert controls_view.state.ui.pending is Route.BACK


def test_enter_is_captured_instead_of_leaving(controls_view, mocker) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)
    mocker.patch.object(rl, "get_key_pressed", side_effect=[rl.KeyboardKey.KEY_ENTER, 0])
    controls_view.update(0.016)
    assert controls_view.state.config.controls.player(0).fire_code == 0x1C
    assert controls_view._capture is None
    assert controls_view._dirty
    assert not controls_view.state.ui.closing
    assert controls_view.take_action() is None


@pytest.mark.parametrize("player_index", range(4))
def test_capture_prompt_draws_for_every_player(controls_view, player_index, mocker) -> None:
    controls_view._config_player = player_index + 1
    controls_view._capture.player_index = player_index
    draw_text = mocker.patch.object(controls, "draw_small_text")
    controls_view._draw_contents()
    texts = [call.args[1] for call in draw_text.call_args_list]
    assert "<press input>" in texts
    assert any("Esc/Right: cancel" in text for text in texts)
