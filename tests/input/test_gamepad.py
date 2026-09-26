from __future__ import annotations

import math
from pathlib import Path

import msgspec
import pytest
from pytest_mock import MockerFixture

from crimson import input_codes
from crimson.aim_schemes import AimScheme
from crimson.gamepad_profile import (
    PAD_PROFILE_FIRE_CODE,
    PAD_PROFILE_PICK_PERK_CODE,
    PAD_PROFILE_RELOAD_CODE,
    apply_pad_profile,
    auto_apply_pad_profiles,
    player_bindings_are_stock,
)
from crimson.gameplay import _direction_from_heading_native, _native_move_target_heading
from crimson.input_codes import (
    INPUT_CODE_UNBOUND,
    PadCode,
    capture_first_pressed_input_code,
    gamepad_has_activity,
    gamepad_snapshot,
    input_axis_value,
    input_code_is_down,
    input_code_name,
)
from crimson.local_input import LocalInputInterpreter
from crimson.modes.components.perk_prompt_ui import PerkPromptUi
from crimson.movement_controls import MovementControlType
from crimson.sim.state_types import PlayerState
from crimson.ui.menu_nav import menu_confirm_pressed, menu_focus_step
from grim.config import (
    DEFAULT_PICK_PERK_CODE,
    DEFAULT_RELOAD_CODE,
    CrimsonConfig,
    decode_crimson_cfg,
    default_crimson_cfg,
    encode_crimson_cfg,
)
from grim.geom import Vec2
from grim.raylib_api import rl

LEFT_X = int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_X)
LEFT_Y = int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_Y)
RIGHT_X = int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_X)
RIGHT_Y = int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_Y)
LEFT_TRIGGER = int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_TRIGGER)
RIGHT_TRIGGER = int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_TRIGGER)
RT_BUTTON = int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_TRIGGER_2)
DPAD_DOWN_BUTTON = int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN)
FACE_DOWN_BUTTON = int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN)


class FakePads(msgspec.Struct):
    """raylib gamepad state as GLFW reports it: triggers rest at -1."""

    connected: set[int] = msgspec.field(default_factory=lambda: {0})
    axes: dict[tuple[int, int], float] = msgspec.field(default_factory=dict)
    down: set[tuple[int, int]] = msgspec.field(default_factory=set)
    pressed: set[tuple[int, int]] = msgspec.field(default_factory=set)

    def axis(self, pad: int, axis: int) -> float:
        rest = -1.0 if axis in {LEFT_TRIGGER, RIGHT_TRIGGER} else 0.0
        return self.axes.get((pad, axis), rest)


@pytest.fixture
def pads(mocker: MockerFixture) -> FakePads:
    state = FakePads()
    mocker.patch.object(rl, "is_gamepad_available", side_effect=lambda pad: int(pad) in state.connected)
    mocker.patch.object(rl, "get_gamepad_axis_movement", side_effect=lambda pad, axis: state.axis(int(pad), int(axis)))
    mocker.patch.object(rl, "is_gamepad_button_down", side_effect=lambda pad, b: (int(pad), int(b)) in state.down)
    mocker.patch.object(rl, "is_gamepad_button_pressed", side_effect=lambda pad, b: (int(pad), int(b)) in state.pressed)
    mocker.patch.object(rl, "get_gamepad_name", side_effect=lambda pad: f"Test Pad {int(pad)}")
    mocker.patch.object(rl, "get_key_pressed", return_value=0)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    mocker.patch.object(rl, "is_key_down", return_value=False)
    mocker.patch.object(rl, "is_mouse_button_down", return_value=False)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)
    mocker.patch.object(rl, "get_mouse_wheel_move", return_value=0.0)
    return state


def _pad_config(*, player_count: int = 1) -> CrimsonConfig:
    config = default_crimson_cfg(Path("<memory>"))
    config.gameplay.player_count = player_count
    for player_index in range(player_count):
        apply_pad_profile(config.controls, player_index)
    return config


def _build_input(config: CrimsonConfig, *, player_index: int = 0, interpreter: LocalInputInterpreter | None = None):
    interpreter = interpreter or LocalInputInterpreter()
    player = PlayerState(index=player_index, pos=Vec2(100.0, 100.0), aim=Vec2(100.0, 40.0))
    return interpreter.build_player_input(
        player_index=player_index,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.016,
    )


def _travel_direction(move: Vec2) -> Vec2:
    """Where the sim steers the player for a pad move vector (native heading math)."""

    return _direction_from_heading_native(_native_move_target_heading(move, normalize=True, wrap=True))


# --- code space -----------------------------------------------------------------------


def test_pad_codes_stay_clear_of_native_code_families() -> None:
    codes = [int(code) for code in PadCode]
    assert len(set(codes)) == len(codes)
    # Native ids end at the RIM/unbound block; everything above is ignored by grim.
    assert min(codes) > INPUT_CODE_UNBOUND
    assert max(codes) < 2**31
    assert not set(codes) & set(input_codes._JOYS_BUTTON_CODES)
    assert not set(codes) & set(input_codes._AXIS_CODE_TO_AXIS)
    assert set(input_codes._PAD_AXIS_CODES) | set(input_codes._PAD_BUTTON_CODES) == set(codes)


@pytest.mark.parametrize(
    ("code", "name"),
    [
        (PadCode.LEFT_STICK_X, "Left Stick X"),
        (PadCode.RIGHT_STICK_Y, "Right Stick Y"),
        (PadCode.R2, "R2 / RT"),
        (PadCode.FACE_DOWN, "Cross / A"),
        (PadCode.FACE_LEFT, "Square / X"),
        (PadCode.FACE_UP, "Triangle / Y"),
        (PadCode.DPAD_LEFT, "D-Pad Left"),
    ],
)
def test_pad_code_display_names(code: PadCode, name: str) -> None:
    assert input_code_name(code) == name


def test_legacy_code_names_unchanged() -> None:
    assert input_code_name(0x13F) == "JoyAxisX"
    assert input_code_name(0x11F) == "Joys1"


def test_pad_codes_round_trip_through_crimson_cfg() -> None:
    config = _pad_config(player_count=2)
    config.gameplay.player_count = 2
    decoded = decode_crimson_cfg(Path("<memory>"), encode_crimson_cfg(config))
    assert decoded.controls == config.controls
    player = decoded.controls.player(1)
    assert player.aim_axis_codes == (PadCode.RIGHT_STICK_Y, PadCode.RIGHT_STICK_X)
    assert player.fire_code == PadCode.R2


# --- raw reads ------------------------------------------------------------------------


def test_stick_axes_read_raw_values_for_the_players_pad(pads: FakePads) -> None:
    pads.connected = {0, 1}
    pads.axes[(1, LEFT_X)] = 0.1
    pads.axes[(0, LEFT_X)] = 0.9
    # No per-axis deadzone: consumers apply radial deadzones on the 2D stick.
    assert input_axis_value(PadCode.LEFT_STICK_X, player_index=1) == pytest.approx(0.1)
    assert input_axis_value(PadCode.LEFT_STICK_X, player_index=0) == pytest.approx(0.9)
    assert input_axis_value(PadCode.LEFT_STICK_X, player_index=2) == 0.0


def test_trigger_codes_are_buttons_not_resting_axes(pads: FakePads) -> None:
    assert not input_code_is_down(PadCode.R2)
    pads.down.add((0, RT_BUTTON))
    assert input_code_is_down(PadCode.R2)


def test_capture_yields_standard_codes_and_ignores_resting_triggers(pads: FakePads) -> None:
    # Both triggers sit at -1: an axis capture must not grab them.
    assert capture_first_pressed_input_code(player_index=0, include_axes=True) is None
    pads.axes[(0, RIGHT_Y)] = -0.8
    assert capture_first_pressed_input_code(player_index=0, include_axes=True) == PadCode.RIGHT_STICK_Y
    pads.pressed.add((0, RT_BUTTON))
    assert capture_first_pressed_input_code(player_index=0, include_axes=False) == PadCode.R2


def test_gamepad_activity_and_snapshot(pads: FakePads) -> None:
    assert not gamepad_has_activity(0)
    assert not gamepad_has_activity(1)
    pads.axes[(0, LEFT_Y)] = 0.3
    assert not gamepad_has_activity(0)
    pads.axes[(0, LEFT_Y)] = 0.7
    assert gamepad_has_activity(0)
    pads.axes.clear()
    pads.down.add((0, FACE_DOWN_BUTTON))
    assert gamepad_has_activity(0)

    snapshot = gamepad_snapshot(0)
    assert snapshot is not None
    assert snapshot.name == "Test Pad 0"
    assert snapshot.held == ("Cross / A",)
    assert dict(snapshot.axes)["R2 Axis"] == -1.0
    assert "Test Pad 0" in snapshot.summary()
    assert gamepad_snapshot(3) is None


# --- directions -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stick", "expected"),
    [
        (Vec2(1.0, 0.0), Vec2(1.0, 0.0)),
        (Vec2(-1.0, 0.0), Vec2(-1.0, 0.0)),
        (Vec2(0.0, -1.0), Vec2(0.0, -1.0)),  # stick up is screen up
        (Vec2(0.0, 1.0), Vec2(0.0, 1.0)),
        (Vec2(0.6, -0.6), Vec2(math.sqrt(0.5), -math.sqrt(0.5))),
    ],
)
def test_left_stick_moves_the_way_it_is_pushed(pads: FakePads, stick: Vec2, expected: Vec2) -> None:
    pads.axes[(0, LEFT_X)] = stick.x
    pads.axes[(0, LEFT_Y)] = stick.y
    out = _build_input(_pad_config())
    assert out.move_mode is MovementControlType.DUAL_ACTION_PAD
    travel = _travel_direction(out.move)
    assert travel.x == pytest.approx(expected.x, abs=1e-5)
    assert travel.y == pytest.approx(expected.y, abs=1e-5)


def test_legacy_axis_codes_follow_native_direction(pads: FakePads) -> None:
    # Native `player_update` negates the axes into `movement_input` and heads away
    # from it, so a DirectInput axis moves the player the way it is pushed too.
    config = default_crimson_cfg(Path("<memory>"))
    player = config.controls.player(0)
    player.movement = MovementControlType.DUAL_ACTION_PAD
    player.move_axis_codes = (0x140, 0x13F)
    pads.axes[(0, LEFT_X)] = 1.0
    travel = _travel_direction(_build_input(config).move)
    assert travel.x == pytest.approx(1.0, abs=1e-5)
    assert travel.y == pytest.approx(0.0, abs=1e-5)


def test_resting_stick_inside_sim_deadzone_does_not_steer(pads: FakePads) -> None:
    pads.axes[(0, LEFT_X)] = 0.12
    pads.axes[(0, LEFT_Y)] = -0.1
    out = _build_input(_pad_config())
    # Raw drift is passed through; the sim's native 0.2 radius ignores it.
    assert math.hypot(out.move.x, out.move.y) < 0.2


def test_right_stick_aims_the_way_it_is_pushed(pads: FakePads) -> None:
    pads.axes[(0, RIGHT_X)] = 1.0
    out = _build_input(_pad_config())
    assert out.aim_scheme is AimScheme.DUAL_ACTION_PAD
    assert out.aim.x == pytest.approx(100.0 + 42.0 + 96.0)
    assert out.aim.y == pytest.approx(100.0)

    pads.axes[(0, RIGHT_X)] = 0.0
    pads.axes[(0, RIGHT_Y)] = -0.5
    out = _build_input(_pad_config())
    assert out.aim.x == pytest.approx(100.0)
    assert out.aim.y == pytest.approx(100.0 - (42.0 + 0.5 * 96.0))


def test_aim_reach_clamps_stick_length_like_native(pads: FakePads) -> None:
    pads.axes[(0, RIGHT_X)] = 1.0
    pads.axes[(0, RIGHT_Y)] = 1.0
    out = _build_input(_pad_config())
    reach = math.hypot(out.aim.x - 100.0, out.aim.y - 100.0)
    assert reach == pytest.approx(42.0 + 96.0)


def test_released_aim_stick_keeps_last_direction(pads: FakePads) -> None:
    config = _pad_config()
    interpreter = LocalInputInterpreter()
    pads.axes[(0, RIGHT_X)] = -1.0
    _build_input(config, interpreter=interpreter)
    pads.axes[(0, RIGHT_X)] = -0.1  # drift inside the aim deadzone
    out = _build_input(config, interpreter=interpreter)
    assert out.aim.x < 100.0
    assert out.aim.y == pytest.approx(100.0, abs=1e-4)


def test_pad_profile_fire_and_reload_read_the_pad(pads: FakePads) -> None:
    pads.down.add((0, RT_BUTTON))
    pads.pressed.add((0, RT_BUTTON))
    input_codes.input_begin_frame()
    out = _build_input(_pad_config())
    assert out.fire_down
    assert not out.reload_down


# --- auto profile ---------------------------------------------------------------------


def test_auto_profile_switches_a_stock_player_once_their_pad_is_used() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    assert auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: False) == ()
    assert config.controls == default_crimson_cfg(Path("<memory>")).controls

    assert auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: True) == (0,)
    player = config.controls.player(0)
    assert player.movement is MovementControlType.DUAL_ACTION_PAD
    assert player.aim_scheme is AimScheme.DUAL_ACTION_PAD
    assert player.move_axis_codes == (PadCode.LEFT_STICK_Y, PadCode.LEFT_STICK_X)
    assert player.aim_axis_codes == (PadCode.RIGHT_STICK_Y, PadCode.RIGHT_STICK_X)
    assert player.fire_code == PAD_PROFILE_FIRE_CODE
    assert config.controls.reload_code == PAD_PROFILE_RELOAD_CODE
    assert config.controls.pick_perk_code == PAD_PROFILE_PICK_PERK_CODE
    # Keyboard keys survive so a keyboard movement method brings WASD back.
    assert player.move_codes == (0x11, 0x1F, 0x1E, 0x20)

    # Applied players are no longer stock: the switch never repeats.
    assert not player_bindings_are_stock(config.controls, 0)
    assert auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: True) == ()


def test_auto_profile_leaves_customized_players_alone() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    config.controls.player(0).fire_code = 0x39
    assert auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: True) == ()
    assert config.controls.player(0).aim_scheme is AimScheme.MOUSE


def test_auto_profile_reverted_methods_do_not_retrigger() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: True)
    player = config.controls.player(0)
    player.aim_scheme = AimScheme.MOUSE
    player.movement = MovementControlType.STATIC
    assert auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: True) == ()
    assert player.aim_scheme is AimScheme.MOUSE


def test_auto_profile_ignores_the_direction_arrow_toggle() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    config.controls.player(0).show_direction_arrow = False
    assert player_bindings_are_stock(config.controls, 0)


def test_auto_profile_keeps_customized_global_codes() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    config.controls.reload_code = 0x13
    auto_apply_pad_profiles(config.controls, player_count=1, pad_active=lambda _pad: True)
    assert config.controls.reload_code == 0x13
    assert config.controls.pick_perk_code == PAD_PROFILE_PICK_PERK_CODE


def test_auto_profile_uses_each_players_pad_and_only_active_players() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    active_pads = {1, 2}
    switched = auto_apply_pad_profiles(config.controls, player_count=2, pad_active=lambda pad: pad in active_pads)
    assert switched == (1,)
    assert config.controls.player(0).aim_scheme is AimScheme.MOUSE
    assert config.controls.player(2).aim_scheme is AimScheme.MOUSE
    # Reload/Level Up belong to player 1; another player's pad does not take them.
    assert config.controls.reload_code == DEFAULT_RELOAD_CODE
    assert config.controls.pick_perk_code == DEFAULT_PICK_PERK_CODE


# --- menus ----------------------------------------------------------------------------


def test_menu_navigation_accepts_any_pad(pads: FakePads) -> None:
    pads.connected = {0, 1}
    assert menu_focus_step() == 0
    assert not menu_confirm_pressed()
    pads.pressed.add((1, DPAD_DOWN_BUTTON))
    assert menu_focus_step() == 1
    pads.pressed.add((1, FACE_DOWN_BUTTON))
    assert menu_confirm_pressed()


def test_perk_prompt_names_the_bound_level_up_input() -> None:
    config = default_crimson_cfg(Path("<memory>"))
    assert PerkPromptUi.label(config, pending_count=1) == "Press Mouse2 to pick a perk"
    apply_pad_profile(config.controls, 0)
    assert PerkPromptUi.label(config, pending_count=2) == "Press Triangle / Y to pick a perk (2)"
