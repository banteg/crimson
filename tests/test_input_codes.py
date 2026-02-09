from __future__ import annotations

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
