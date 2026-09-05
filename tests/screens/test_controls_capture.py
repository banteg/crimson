from __future__ import annotations

import pytest

from crimson.screens.actions import Route
from crimson.screens.panels import controls
from crimson.screens.panels.controls import ControlsMenuView, RebindCapture
from crimson.screens.panels.controls_labels import RebindRowSpec, RebindTarget
from grim.raylib_api import rl


@pytest.fixture
def controls_view(make_game_state, screen_resources, screen_io) -> ControlsMenuView:
    view = ControlsMenuView(make_game_state(resources=screen_resources))
    view.open()
    view._timeline_ms = view._timeline_max_ms
    view._capture = RebindCapture(RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE), 0, skip_frames=0)
    return view


def test_escape_cancels_capture_before_navigation(controls_view, mocker) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    controls_view.update(0.016)
    assert controls_view._capture is None
    assert not controls_view._closing
    assert controls_view.take_action() is None

    # A subsequent Escape can leave the screen after capture releases input.
    controls_view.update(0.016)
    assert controls_view._close_action is Route.BACK


def test_enter_is_captured_instead_of_leaving(controls_view, mocker) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)
    mocker.patch.object(rl, "get_key_pressed", side_effect=[rl.KeyboardKey.KEY_ENTER, 0])
    controls_view.update(0.016)
    assert controls_view.state.config.controls.player(0).fire_code == 0x1C
    assert controls_view._capture is None
    assert controls_view._dirty
    assert not controls_view._closing
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
