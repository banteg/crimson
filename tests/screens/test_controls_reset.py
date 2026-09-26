from __future__ import annotations

import pytest
from pytest_mock import MockerFixture

from crimson.aim_schemes import AimScheme
from crimson.gamepad_profile import (
    PAD_PROFILE_FIRE_CODE,
    PAD_PROFILE_PICK_PERK_CODE,
    PAD_PROFILE_RELOAD_CODE,
    reset_player_controls,
)
from crimson.input_codes import PadCode
from crimson.movement_controls import MovementControlType
from crimson.screens.panels.controls import ControlsMenuView
from grim.config import (
    DEFAULT_PICK_PERK_CODE,
    DEFAULT_RELOAD_CODE,
    default_crimson_cfg,
    default_player_controls,
    load_crimson_cfg,
)
from grim.raylib_api import rl


def _customize(config) -> None:
    for idx in range(4):
        player = config.controls.player(idx)
        player.movement = MovementControlType.RELATIVE
        player.aim_scheme = AimScheme.KEYBOARD
        player.fire_code = 0x39
        player.move_axis_codes = (0x140, 0x13F)
        player.show_direction_arrow = False
    config.controls.reload_code = 0x13
    config.controls.pick_perk_code = 0x2A


def test_reset_without_pad_restores_stock_bindings() -> None:
    config = default_crimson_cfg()
    _customize(config)
    reset_player_controls(config.controls, 0, pad_connected=False)
    player = config.controls.player(0)
    stock = default_player_controls(0)
    assert player.movement is stock.movement
    assert player.aim_scheme is stock.aim_scheme
    assert player.fire_code == stock.fire_code
    assert player.move_axis_codes == stock.move_axis_codes
    assert player.show_direction_arrow is False  # HUD preference, not a binding
    assert config.controls.reload_code == DEFAULT_RELOAD_CODE
    assert config.controls.pick_perk_code == DEFAULT_PICK_PERK_CODE


def test_reset_with_pad_applies_the_full_pad_profile() -> None:
    config = default_crimson_cfg()
    _customize(config)
    reset_player_controls(config.controls, 0, pad_connected=True)
    player = config.controls.player(0)
    assert player.movement is MovementControlType.DUAL_ACTION_PAD
    assert player.aim_scheme is AimScheme.DUAL_ACTION_PAD
    assert player.move_axis_codes == (PadCode.LEFT_STICK_Y, PadCode.LEFT_STICK_X)
    assert player.aim_axis_codes == (PadCode.RIGHT_STICK_Y, PadCode.RIGHT_STICK_X)
    assert player.fire_code == PAD_PROFILE_FIRE_CODE
    assert player.move_codes == default_player_controls(0).move_codes
    assert config.controls.reload_code == PAD_PROFILE_RELOAD_CODE
    assert config.controls.pick_perk_code == PAD_PROFILE_PICK_PERK_CODE


@pytest.mark.parametrize("pad_connected", [False, True])
def test_reset_of_other_players_keeps_player_one_globals(pad_connected: bool) -> None:
    config = default_crimson_cfg()
    _customize(config)
    reset_player_controls(config.controls, 1, pad_connected=pad_connected)
    assert config.controls.reload_code == 0x13
    assert config.controls.pick_perk_code == 0x2A
    assert config.controls.player(0).fire_code == 0x39
    expected_fire = PAD_PROFILE_FIRE_CODE if pad_connected else default_player_controls(1).fire_code
    assert config.controls.player(1).fire_code == expected_fire


@pytest.fixture
def controls_view(make_game_state, screen_resources, screen_io) -> ControlsMenuView:
    view = ControlsMenuView(make_game_state(resources=screen_resources))
    view.open()
    view._transition.timeline_ms = view._transition.duration_ms
    return view


def _click_reset(view: ControlsMenuView, mocker: MockerFixture) -> None:
    panel_scale, _ = view._menu_item_scale(0)
    pos, width = view._reset_button_layout(
        left_top_left=view._left_panel_top_left(panel_scale),
        panel_scale=panel_scale,
    )
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(pos.x + width * 0.5, pos.y + 16.0))
    mocker.patch.object(
        rl,
        "is_mouse_button_pressed",
        side_effect=lambda button: button == rl.MouseButton.MOUSE_BUTTON_LEFT,
    )
    view.update(0.016)


@pytest.mark.parametrize(
    ("pad_connected", "expected_aim", "log"),
    [
        (False, AimScheme.MOUSE, "controls: player 1 reset to defaults"),
        (True, AimScheme.DUAL_ACTION_PAD, "controls: player 1 reset to gamepad defaults (pad 0: DualSense)"),
    ],
)
def test_reset_button_resets_saves_and_logs(
    controls_view: ControlsMenuView,
    mocker: MockerFixture,
    pad_connected: bool,
    expected_aim: AimScheme,
    log: str,
) -> None:
    state = controls_view.state
    _customize(state.config)
    mocker.patch.object(rl, "is_gamepad_available", side_effect=lambda pad: pad_connected and int(pad) == 0)
    mocker.patch.object(rl, "get_gamepad_name", return_value="DualSense")

    _click_reset(controls_view, mocker)

    assert state.config.controls.player(0).aim_scheme is expected_aim
    assert state.console.log.lines[-1] == log
    saved = load_crimson_cfg(state.config.path)
    assert saved.controls == state.config.controls
    assert not controls_view._transition.closing
