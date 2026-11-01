"""GOG 1.9.93 input regressions for original bugs 72 and 73."""

from __future__ import annotations

import pytest

from ._support import install_fake_grim

_JOY_Z = 0x141
_MOUSE_3 = 0x102


@pytest.mark.parametrize(
    ("input_code", "expected_reload"),
    [pytest.param(_JOY_Z, _JOY_Z, id="joystick-z"), pytest.param(0x12, _MOUSE_3, id="keyboard-e")],
)
def test_rebinding_level_up_can_also_replace_reload(oracle, input_code: int, expected_reload: int) -> None:
    # Grim reports a tilted axis both as a held key and as an analog value.
    # Flushing the keyboard queue after the first match leaves the stick tilted.
    install_fake_grim(
        oracle,
        {
            "grim_is_key_active": lambda call: int(call.arg_u32(0) == input_code),
            "grim_was_key_pressed": lambda _: 0,
        },
    )
    vtable = oracle.read_u32(oracle.read_u32("grim_interface_ptr"))
    oracle.stub(
        oracle.read_u32(vtable + 0x84),  # grim_get_config_float
        lambda call: 0.75 if input_code == _JOY_Z and call.arg_u32(0) == _JOY_Z else 0.0,
        pop=4,
        returns="st0",
    )
    oracle.write_u32("controls_rebind_player_index", 0)
    oracle.write_u32("controls_rebind_slot_index", 13)  # Level Up
    oracle.write_u8("controls_rebind_capture_armed", 1)
    oracle.write_u32("config_key_pick_perk", 0x101)
    oracle.write_u32("config_key_reload", _MOUSE_3)

    # Run the complete key-row capture in controls_menu_update. EDI is the
    # Level Up row (13), EBX the idle row (−1). The next block updates the lists.
    oracle.run(0x0044DCBF, 0x0044DDFA, regs={"edi": 13, "ebx": 0xFFFF_FFFF})
    assert oracle.read_i32("controls_rebind_slot_index") == -1
    assert oracle.read_u32("config_key_pick_perk") == input_code
    assert oracle.read_u32("config_key_reload") == expected_reload


def test_menu_cursor_needs_both_mouse_axes_to_take_over_from_a_stick(oracle) -> None:
    install_fake_grim(oracle)
    vtable = oracle.read_u32(oracle.read_u32("grim_interface_ptr"))
    oracle.stub(oracle.read_u32(vtable + 0x70), lambda _: mouse_x, returns="st0")  # grim_get_mouse_dx
    oracle.stub(oracle.read_u32(vtable + 0x74), lambda _: mouse_y, returns="st0")  # grim_get_mouse_dy
    oracle.stub(
        oracle.read_u32(vtable + 0x84),  # grim_get_config_float
        lambda call: stick_x if call.arg_u32(0) == 0x13F else 0.0,
        pop=4,
        returns="st0",
    )
    for name, code in (
        ("player_axis_aim_x", 0x13F),
        ("player_axis_aim_y", 0x140),
        ("player_axis_move_x", 0x155),
        ("player_axis_move_y", 0x153),
    ):
        oracle.write_u32(name, code)
    oracle.write_u32("game_state_id", 0)  # Menu
    oracle.write_u32("ui_analog_cursor_active", 0)
    oracle.write_f32("frame_dt", 1 / 60)
    oracle.write_f32("config_mouse_sensitivity", 1.0)
    oracle.write_f32("ui_mouse_x", 100.0)
    oracle.write_f32("ui_mouse_y", 100.0)

    # Each row is one frame. With the stick centered again, mouse X and then
    # mouse Y on separate frames both fail. One diagonal move restores the mouse.
    for motion, expected_analog, expected_pos in (
        ((0, 0, 1.0), 1, (109, 100)),
        ((5, 0, 0.0), 1, (109, 100)),
        ((0, 5, 0.0), 1, (109, 100)),
        ((5, 5, 0.0), 0, (119, 110)),
        ((5, 0, 0.0), 0, (129, 110)),
    ):
        mouse_x, mouse_y, stick_x = motion
        # game_frame_update's cursor arbitration and motion, up to the shared
        # screen bounds clamp. EBX carries zero across this block.
        oracle.run(0x0040C5C0, 0x0040C77F, regs={"ebx": 0})
        assert oracle.read_u32("ui_analog_cursor_active") == expected_analog
        assert (oracle.read_f32("ui_mouse_x"), oracle.read_f32("ui_mouse_y")) == expected_pos
