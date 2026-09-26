from __future__ import annotations

from pytest_mock import MockerFixture

from crimson.aim_schemes import AimScheme
from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from crimson.input_codes import PadCode
from grim.config import load_crimson_cfg
from grim.raylib_api import rl


def test_game_loop_switches_and_saves_when_the_pad_is_used(make_game_state, mocker: MockerFixture) -> None:
    state = make_game_state()
    view = GameLoopView(state)
    button_down = {"value": False}
    mocker.patch.object(rl, "is_gamepad_available", side_effect=lambda pad: int(pad) == 0)
    mocker.patch.object(rl, "get_gamepad_axis_movement", return_value=0.0)
    mocker.patch.object(rl, "is_gamepad_button_down", side_effect=lambda _pad, _button: button_down["value"])
    mocker.patch.object(rl, "get_gamepad_name", return_value="DualSense Wireless Controller")

    # A connected but untouched pad leaves the mouse player alone.
    view._apply_gamepad_profiles()
    assert state.config.controls.player(0).aim_scheme is AimScheme.MOUSE

    button_down["value"] = True
    view._apply_gamepad_profiles()

    assert state.config.controls.player(0).aim_scheme is AimScheme.DUAL_ACTION_PAD
    assert state.console.log.lines[-1] == (
        "input: player 1 switched to gamepad controls (pad 0: DualSense Wireless Controller): "
        "aim/move methods, move axes, aim axes, fire, reload, level up"
    )
    saved = load_crimson_cfg(state.config.path)
    assert saved.controls == state.config.controls
    assert saved.controls.player(0).fire_code == PadCode.R2


def test_gamepads_command_reports_pads_and_bindings(make_game_state, mocker: MockerFixture) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)
    mocker.patch.object(rl, "is_gamepad_available", return_value=False)

    handlers["gamepads"]([])

    assert state.console.log.lines[-2] == "gamepads: none connected"
    assert state.console.log.lines[-1].startswith("player 1 (pad 0): move=STATIC")
    assert "fire=Mouse1" in state.console.log.lines[-1]
