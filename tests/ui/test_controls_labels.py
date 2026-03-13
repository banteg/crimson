from __future__ import annotations

from typing import cast

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.screens.panels.controls_labels import (
    RebindRowSpec,
    controls_aim_method_dropdown_ids,
    controls_method_labels,
    controls_method_values,
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
    assert input_scheme_label(MovementControlType.MOUSE_POINT_CLICK) == "Mouse point click"
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
    assert controls_method_labels(controls, player_index=1) == ("Joystick", "Mouse point click")
    assert controls_method_labels(controls, player_index=2) == ("Dual Action Pad", "Computer")
    assert controls_method_labels(controls, player_index=3) == ("Computer", "Relative")
    assert controls_method_values(controls, player_index=1) == (AimScheme.JOYSTICK, MovementControlType.MOUSE_POINT_CLICK)


def test_controls_method_labels_defaults_missing_blob() -> None:
    assert controls_method_labels(_controls(), player_index=0) == ("Mouse", "Static")


def test_controls_method_values_unknown_move_mode_maps_to_unknown_enum() -> None:
    controls = _controls()
    controls.player(0).movement = MovementControlType.UNKNOWN
    assert controls_method_values(controls, player_index=0) == (AimScheme.MOUSE, MovementControlType.UNKNOWN)


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
        RebindRowSpec("Torso left:", "aim_left_code"),
        RebindRowSpec("Torso right:", "aim_right_code"),
        RebindRowSpec("Fire:", "fire_code"),
    )
    assert move_rows == (
        RebindRowSpec("Move Up:", "move_forward_code"),
        RebindRowSpec("Move Down:", "move_backward_code"),
        RebindRowSpec("Move Left:", "turn_left_code"),
        RebindRowSpec("Move Right:", "turn_right_code"),
    )
    assert misc_rows == (
        RebindRowSpec("Level Up:", "pick_perk_code", controls_field=True),
        RebindRowSpec("Reload:", "reload_code", controls_field=True),
    )


def test_controls_rebind_plan_dualpad_mouse_cursor_player2() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_plan(
        aim_scheme=AimScheme.DUAL_ACTION_PAD,
        move_mode=MovementControlType.MOUSE_POINT_CLICK,
        player_index=1,
    )
    assert aim_rows == (
        RebindRowSpec("Aim Up/Down Axis:", "aim_vertical_axis_code", axis=True),
        RebindRowSpec("Aim Left/Right Axis:", "aim_horizontal_axis_code", axis=True),
        RebindRowSpec("Fire:", "fire_code"),
    )
    assert move_rows == (RebindRowSpec("Move to cursor:", "reload_code", controls_field=True),)
    assert misc_rows == ()
