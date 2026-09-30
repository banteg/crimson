from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.screens.actions import Route
from crimson.screens.panels.options import OptionsMenuView
from grim.raylib_api import rl
from tests.support.screens import finish_transition


def open_options(loop: GameLoopView) -> OptionsMenuView:
    loop.navigation.navigate(Route.OPTIONS)
    finish_transition(loop)
    options = loop.state.screens.active
    assert isinstance(options, OptionsMenuView)
    return options


def test_holding_the_button_on_a_volume_segment_sets_that_volume(loop, mocker) -> None:
    options = open_options(loop)
    sfx = options._content_layout().slider_pos.offset(dy=47.0)
    mocker.patch.object(rl, "is_mouse_button_down", return_value=True)
    for segment, volume in ((7, 0.7), (0, 0.0)):
        mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(sfx.x + segment * 8 + 3.0, sfx.y + 6.0))
        loop.update(0.016)
        assert options._slider_sfx.value == segment
        assert loop.state.config.audio.sfx_volume == pytest.approx(volume)

    # Past the slider's end the drag no longer reaches it.
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(sfx.x + 100.0, sfx.y + 6.0))
    loop.update(0.016)
    assert options._slider_sfx.value == 0


def test_the_detail_slider_keeps_the_preset_at_one(loop, mocker) -> None:
    options = open_options(loop)
    detail = options._content_layout().slider_pos.offset(dy=87.0)
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(detail.x + 3.0, detail.y + 6.0))
    mocker.patch.object(rl, "is_mouse_button_down", return_value=True)
    loop.update(0.016)
    assert loop.state.config.display.detail_preset == 1

    # Hovering focused it; Left takes the slider to 0 and the preset stays 1.
    mocker.patch.object(rl, "is_mouse_button_down", return_value=False)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_LEFT)
    loop.update(0.016)
    assert options._slider_detail.value == 1
    assert loop.state.config.display.detail_preset == 1
