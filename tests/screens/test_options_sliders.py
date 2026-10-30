from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.render.rtx.mode import RtxRenderMode, load_rtx_choice
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


def test_the_rtx_box_switches_the_mode_and_keeps_the_choice(loop, mocker) -> None:
    options = open_options(loop)
    box = options._content_layout().label_pos.offset(dy=110.0)
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(box.x + 8.0, box.y + 8.0))
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    loop.update(0.016)
    assert loop.state.rtx_mode is RtxRenderMode.RTX
    assert load_rtx_choice(loop.state.base_dir) is RtxRenderMode.RTX

    loop.update(0.016)
    assert loop.state.rtx_mode is RtxRenderMode.CLASSIC
    assert load_rtx_choice(loop.state.base_dir) is RtxRenderMode.CLASSIC


def test_rtx_choice_is_locked_through_a_run_pause_and_options(loop, mocker) -> None:
    from crimson.game.runtime import _boot_command_handlers
    from crimson.game_modes import GameMode
    from crimson.screens.actions import StartRun

    assert loop.state.choose_rtx_mode(RtxRenderMode.RTX)
    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))
    for route in (None, Route.PAUSE, Route.OPTIONS):
        if route is not None:
            loop.navigation.navigate(route)
        assert not loop.state.can_change_rtx_mode
        handlers = _boot_command_handlers(loop.state)
        handlers["rendermode"](["classic"])
        handlers["togglertx"]([])
        loop._set_rtx_mode(RtxRenderMode.CLASSIC, source="debug hotkey F4")
        assert loop.state.rtx_mode is RtxRenderMode.RTX
        assert load_rtx_choice(loop.state.base_dir) is RtxRenderMode.RTX
        assert loop.state.console.log.lines[-1] == "Change render mode from the main menu."
    options = loop.state.screens.active
    assert isinstance(options, OptionsMenuView)
    finish_transition(loop)
    loop.update(0.016)
    assert options._rtx_checkbox.disabled
    loop.navigation.navigate(Route.MENU)
    assert loop.state.choose_rtx_mode(RtxRenderMode.CLASSIC)
    assert load_rtx_choice(loop.state.base_dir) is RtxRenderMode.CLASSIC
