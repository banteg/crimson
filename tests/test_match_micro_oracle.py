import pytest

from crimson.match_micro_oracle import Value, evaluate_window


def test_scan_output_rotation_preserves_call_inputs():
    native = evaluate_window(
        [
            "lea ecx, dword [esp+0x2c]",
            "mov dword [@notice], eax",
            "lea edx, dword [esp+0x28]",
            "push ecx",
            "lea eax, dword [esp+0x28]",
            "push edx",
            "push eax",
        ],
    )
    candidate = evaluate_window(
        [
            "mov dword [@notice], eax",
            "lea edx, dword [esp+0x2c]",
            "lea eax, dword [esp+0x28]",
            "push edx",
            "lea ecx, dword [esp+0x28]",
            "push eax",
            "push ecx",
        ],
    )
    assert native.call_inputs() == candidate.call_inputs()
    assert native.registers != candidate.registers
    assert [v for _, v in native.writes] == [
        Value("entry:eax"),
        Value("entry:esp", 44),
        Value("entry:esp", 40),
        Value("entry:esp", 36),
    ]


def test_wrong_output_order_is_detected():
    correct = evaluate_window(["lea eax, dword [esp+0x10]", "lea ecx, dword [esp+0x14]", "push eax", "push ecx"])
    wrong = evaluate_window(["lea eax, dword [esp+0x10]", "lea ecx, dword [esp+0x14]", "push ecx", "push eax"])
    assert correct.call_inputs() != wrong.call_inputs()


def test_write_order_and_saved_registers_are_observable():
    first = evaluate_window(["mov dword [@a], eax", "mov dword [@b], ecx"])
    second = evaluate_window(["mov dword [@b], ecx", "mov dword [@a], eax"])
    assert first.call_inputs() != second.call_inputs()
    assert evaluate_window(["mov ebx, eax"]).call_inputs() != evaluate_window([]).call_inputs()


def test_push_esp_uses_value_before_decrement_and_wraps_32_bits():
    result = evaluate_window(["push esp", "push -1"])
    assert result.writes == (
        (Value("entry:esp", 0xFFFFFFFC), Value("entry:esp")),
        (Value("entry:esp", 0xFFFFFFF8), Value(None, 0xFFFFFFFF)),
    )


@pytest.mark.parametrize(
    "instruction",
    [
        "call eax",
        "add esp, 0x4",
        "je L4",
        "fld1",
        "push ADDR",
        "mov eax, dword [esp+0x4]",
        "mov byte [esp], 0x1",
        "mov esp, eax",
        "lea eax, dword [ecx+0x4]",
        "lea dword [esp], eax",
    ],
)
def test_unsupported_instructions_fail_closed(instruction):
    with pytest.raises(ValueError):
        evaluate_window([instruction])
