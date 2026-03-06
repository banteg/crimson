from __future__ import annotations

from typing import cast

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.screens.panels.controls_labels import (
    PICK_PERK_BIND_SLOT,
    RELOAD_BIND_SLOT,
    controls_aim_method_dropdown_ids,
    controls_method_labels,
    controls_method_values,
    controls_rebind_slot_plan,
    input_configure_for_label,
    input_scheme_label,
)


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
    config_data = {
        "player_mode_flag_p1": 2,
        "player_mode_flag_p2": 4,
        "player_mode_flag_p3": 5,
        "player_mode_flag_p4": 1,
        "aim_scheme_p1": 3,
        "aim_scheme_p2": 2,
        "aim_scheme_p3": 4,
        "aim_scheme_p4": 5,
    }

    assert controls_method_labels(config_data, player_index=0) == ("Mouse relative", "Static")
    assert controls_method_labels(config_data, player_index=1) == ("Joystick", "Mouse point click")
    assert controls_method_labels(config_data, player_index=2) == ("Dual Action Pad", "Computer")
    assert controls_method_labels(config_data, player_index=3) == ("Computer", "Relative")
    assert controls_method_values(config_data, player_index=1) == (AimScheme.JOYSTICK, MovementControlType.MOUSE_POINT_CLICK)


def test_controls_method_labels_defaults_missing_blob() -> None:
    assert controls_method_labels({}, player_index=0) == ("Mouse", "Static")


def test_controls_method_values_unknown_move_mode_maps_to_unknown_enum() -> None:
    config_data = {
        "player_mode_flag_p1": 99,
        "player_mode_flag_p2": 2,
        "player_mode_flag_p3": 2,
        "player_mode_flag_p4": 2,
    }

    assert controls_method_values(config_data, player_index=0) == (AimScheme.MOUSE, MovementControlType.UNKNOWN)


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


def test_controls_rebind_slot_plan_keyboard_static_player1() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_slot_plan(
        aim_scheme=AimScheme.KEYBOARD,
        move_mode=MovementControlType.STATIC,
        player_index=0,
    )
    assert aim_rows == (("Torso left:", 7), ("Torso right:", 8), ("Fire:", 4))
    assert move_rows == (("Move Up:", 0), ("Move Down:", 1), ("Move Left:", 2), ("Move Right:", 3))
    assert misc_rows == (("Level Up:", PICK_PERK_BIND_SLOT), ("Reload:", RELOAD_BIND_SLOT))


def test_controls_rebind_slot_plan_dualpad_mouse_cursor_player2() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_slot_plan(
        aim_scheme=AimScheme.DUAL_ACTION_PAD,
        move_mode=MovementControlType.MOUSE_POINT_CLICK,
        player_index=1,
    )
    assert aim_rows == (("Aim Up/Down Axis:", 9), ("Aim Left/Right Axis:", 10), ("Fire:", 4))
    assert move_rows == (("Move to cursor:", RELOAD_BIND_SLOT),)
    assert misc_rows == ()
