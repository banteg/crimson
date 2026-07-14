from __future__ import annotations

from typing import cast

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.screens.panels.controls_labels import (
    RebindRowSpec,
    RebindTarget,
    controls_aim_method_dropdown_ids,
    controls_method_labels,
    controls_rebind_plan,
    input_configure_for_label,
    input_scheme_label,
)
from grim.config import default_crimson_cfg


def _controls():
    return default_crimson_cfg().controls


def test_input_configure_for_label_mapping() -> None:
    assert input_configure_for_label(AimScheme.MOUSE) == "Mouse"
    assert input_configure_for_label(AimScheme.KEYBOARD) == "Keyboard"
    assert input_configure_for_label(AimScheme.JOYSTICK) == "Joystick"
    assert input_configure_for_label(AimScheme.MOUSE_RELATIVE) == "Mouse relative"
    assert input_configure_for_label(AimScheme.DUAL_ACTION_PAD) == "Dual Action Pad"
    assert input_configure_for_label(AimScheme.COMPUTER) == "Computer"
    assert input_configure_for_label(cast(AimScheme, 99)) == "Unknown"


def test_input_scheme_label_mapping() -> None:
    assert input_scheme_label(MovementControlType.RELATIVE) == "Relative"
    assert input_scheme_label(MovementControlType.STATIC) == "Static"
    assert input_scheme_label(MovementControlType.DUAL_ACTION_PAD) == "Dual Action Pad"
    assert input_scheme_label(MovementControlType.MOUSE_POINT_CLICK) == "Mouse point&click"
    assert input_scheme_label(MovementControlType.COMPUTER) == "Computer"
    assert input_scheme_label(MovementControlType.UNKNOWN) == "Unknown"


def test_controls_method_labels_reads_player_arrays() -> None:
    controls = _controls()
    controls.player(0).movement = MovementControlType.STATIC
    controls.player(1).movement = MovementControlType.MOUSE_POINT_CLICK
    controls.player(2).movement = MovementControlType.COMPUTER
    controls.player(3).movement = MovementControlType.RELATIVE
    controls.player(0).aim_scheme = AimScheme.MOUSE_RELATIVE
    controls.player(1).aim_scheme = AimScheme.JOYSTICK
    controls.player(2).aim_scheme = AimScheme.DUAL_ACTION_PAD
    controls.player(3).aim_scheme = AimScheme.COMPUTER

    assert controls_method_labels(controls, player_index=0) == ("Mouse relative", "Static")
    assert controls_method_labels(controls, player_index=1) == ("Joystick", "Mouse point&click")
    assert controls_method_labels(controls, player_index=2) == ("Dual Action Pad", "Computer")
    assert controls_method_labels(controls, player_index=3) == ("Computer", "Relative")


def test_controls_method_labels_defaults_missing_blob() -> None:
    assert controls_method_labels(_controls(), player_index=0) == ("Mouse", "Static")


def test_controls_method_labels_unknown_move_mode_maps_to_unknown_enum() -> None:
    controls = _controls()
    controls.player(0).movement = MovementControlType.UNKNOWN
    assert controls_method_labels(controls, player_index=0) == ("Mouse", "Unknown")


def test_controls_aim_method_dropdown_ids_hides_computer_unless_loaded() -> None:
    assert controls_aim_method_dropdown_ids(AimScheme.MOUSE) == (
        AimScheme.MOUSE,
        AimScheme.KEYBOARD,
        AimScheme.JOYSTICK,
        AimScheme.MOUSE_RELATIVE,
        AimScheme.DUAL_ACTION_PAD,
    )
    assert controls_aim_method_dropdown_ids(AimScheme.COMPUTER) == (
        AimScheme.MOUSE,
        AimScheme.KEYBOARD,
        AimScheme.JOYSTICK,
        AimScheme.MOUSE_RELATIVE,
        AimScheme.DUAL_ACTION_PAD,
        AimScheme.COMPUTER,
    )


def test_controls_rebind_plan_keyboard_static_player1() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_plan(
        aim_scheme=AimScheme.KEYBOARD,
        move_mode=MovementControlType.STATIC,
        player_index=0,
    )
    assert aim_rows == (
        RebindRowSpec("Torso left:", RebindTarget.PLAYER_KEYBOARD_AIM_CODES, 0),
        RebindRowSpec("Torso right:", RebindTarget.PLAYER_KEYBOARD_AIM_CODES, 1),
        RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE),
    )
    assert move_rows == (
        RebindRowSpec("Move Up:", RebindTarget.PLAYER_MOVE_CODES, 0),
        RebindRowSpec("Move Down:", RebindTarget.PLAYER_MOVE_CODES, 1),
        RebindRowSpec("Move Left:", RebindTarget.PLAYER_MOVE_CODES, 2),
        RebindRowSpec("Move Right:", RebindTarget.PLAYER_MOVE_CODES, 3),
    )
    assert misc_rows == (
        RebindRowSpec("Level Up:", RebindTarget.GLOBAL_PICK_PERK_CODE),
        RebindRowSpec("Reload:", RebindTarget.GLOBAL_RELOAD_CODE),
    )


def test_controls_rebind_plan_dualpad_mouse_cursor_player2() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_plan(
        aim_scheme=AimScheme.DUAL_ACTION_PAD,
        move_mode=MovementControlType.MOUSE_POINT_CLICK,
        player_index=1,
    )
    assert aim_rows == (
        RebindRowSpec("Aim Up/Down Axis:", RebindTarget.PLAYER_AIM_AXIS_CODES, 0, axis=True),
        RebindRowSpec("Aim Left/Right Axis:", RebindTarget.PLAYER_AIM_AXIS_CODES, 1, axis=True),
        RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE),
    )
    assert move_rows == (RebindRowSpec("Move to cursor:", RebindTarget.GLOBAL_RELOAD_CODE),)
    assert misc_rows == ()
