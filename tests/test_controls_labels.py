from __future__ import annotations

import struct

from crimson.frontend.panels.controls_labels import (
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
    assert input_configure_for_label(0) == "Mouse"
    assert input_configure_for_label(1) == "Keyboard"
    assert input_configure_for_label(2) == "Joystick"
    assert input_configure_for_label(3) == "Mouse relative"
    assert input_configure_for_label(4) == "Dual Action Pad"
    assert input_configure_for_label(5) == "Computer"
    assert input_configure_for_label(99) == "Unknown"


def test_input_scheme_label_mapping() -> None:
    assert input_scheme_label(1) == "Relative"
    assert input_scheme_label(2) == "Static"
    assert input_scheme_label(3) == "Dual Action Pad"
    assert input_scheme_label(4) == "Mouse point click"
    assert input_scheme_label(5) == "Computer"
    assert input_scheme_label(0) == "Unknown"


def test_controls_method_labels_reads_player_arrays() -> None:
    mode_flags = struct.pack("<IIII", 2, 4, 5, 1) + b"\x00" * (40 - 16)
    aim_tail = struct.pack("<II", 4, 5) + b"\x00" * (32 - 8)
    config_data = {
        "unknown_1c": mode_flags,
        "unknown_44": 3,
        "unknown_48": 2,
        "unknown_4c": aim_tail,
    }

    assert controls_method_labels(config_data, player_index=0) == ("Mouse relative", "Static")
    assert controls_method_labels(config_data, player_index=1) == ("Joystick", "Mouse point click")
    assert controls_method_labels(config_data, player_index=2) == ("Dual Action Pad", "Computer")
    assert controls_method_labels(config_data, player_index=3) == ("Computer", "Relative")
    assert controls_method_values(config_data, player_index=1) == (2, 4)


def test_controls_method_labels_defaults_missing_blob() -> None:
    assert controls_method_labels({}, player_index=0) == ("Mouse", "Static")


def test_controls_aim_method_dropdown_ids_hides_computer_unless_loaded() -> None:
    assert controls_aim_method_dropdown_ids(0) == (0, 1, 2, 3, 4)
    assert controls_aim_method_dropdown_ids(5) == (0, 1, 2, 3, 4, 5)


def test_controls_rebind_slot_plan_keyboard_static_player1() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_slot_plan(aim_scheme=1, move_mode=2, player_index=0)
    assert aim_rows == (("Torso left:", 7), ("Torso right:", 8), ("Fire:", 4))
    assert move_rows == (("Move Up:", 0), ("Move Down:", 1), ("Move Left:", 2), ("Move Right:", 3))
    assert misc_rows == (("Level Up:", PICK_PERK_BIND_SLOT), ("Reload:", RELOAD_BIND_SLOT))


def test_controls_rebind_slot_plan_dualpad_mouse_cursor_player2() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_slot_plan(aim_scheme=4, move_mode=4, player_index=1)
    assert aim_rows == (("Aim Up/Down Axis:", 9), ("Aim Left/Right Axis:", 10), ("Fire:", 4))
    assert move_rows == (("Move to cursor:", RELOAD_BIND_SLOT),)
    assert misc_rows == ()
