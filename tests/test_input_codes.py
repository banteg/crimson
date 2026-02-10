from __future__ import annotations

import crimson.input_codes as input_codes
from crimson.input_codes import INPUT_CODE_UNBOUND, input_code_name


def test_input_code_name_extended_axes_match_original_labels() -> None:
    assert input_code_name(0x13F) == "JoyAxisX"
    assert input_code_name(0x140) == "JoyAxisY"
    assert input_code_name(0x141) == "JoyAxisZ"
    assert input_code_name(0x153) == "JoyRotX"
    assert input_code_name(0x154) == "JoyRotY"
    assert input_code_name(0x155) == "JoyRotZ"


def test_input_code_name_extended_rim_codes_match_original_labels() -> None:
    assert input_code_name(0x163) == "RIM0XAxis"
    assert input_code_name(0x165) == "RIM2XAxis"
    assert input_code_name(0x168) == "RIM0YAxis"
    assert input_code_name(0x16A) == "RIM2YAxis"
    assert input_code_name(0x16D) == "RIM0Btn1"
    assert input_code_name(0x176) == "RIM1Btn5"
    assert input_code_name(0x17B) == "RIM2Btn5"


def test_input_code_name_unbound_and_rawinput_fallback() -> None:
    assert input_code_name(INPUT_CODE_UNBOUND) == "unbound"
    assert input_code_name(0x17F) == "RawInput ?"


def test_axis_z_and_rot_x_bindings_use_distinct_raylib_axes() -> None:
    assert input_codes._AXIS_CODE_TO_AXIS[0x141] != input_codes._AXIS_CODE_TO_AXIS[0x153]


def test_pressed_edge_does_not_retrigger_after_unpolled_held_frame(monkeypatch) -> None:
    key_down = {"value": False}

    monkeypatch.setattr(input_codes.rl, "is_key_down", lambda _key: bool(key_down["value"]))
    monkeypatch.setattr(input_codes.rl, "get_mouse_wheel_move", lambda: 0.0)

    input_codes._PRESSED_STATE.prev_down.clear()
    input_codes._PRESSED_STATE.down.clear()
    input_codes._PRESSED_STATE.pressed_cache.clear()
    input_codes._PRESSED_STATE.wheel_up = False
    input_codes._PRESSED_STATE.wheel_down = False

    input_codes.input_begin_frame()
    key_down["value"] = True
    assert input_codes.input_code_is_pressed_for_player(0x11, player_index=0)

    input_codes.input_begin_frame()
    # Simulate a frame where this binding is not queried at all.
    input_codes.input_begin_frame()

    assert not input_codes.input_code_is_pressed_for_player(0x11, player_index=0)
