from __future__ import annotations

from collections.abc import Sequence

import pyray as rl

from grim.config import CrimsonConfig


INPUT_CODE_UNBOUND = 0x17E


def _dik_to_rl_key(dik_code: int) -> int | None:
    dik_code = int(dik_code)
    return {
        0x01: int(rl.KeyboardKey.KEY_ESCAPE),
        0x0F: int(rl.KeyboardKey.KEY_TAB),
        0x10: int(rl.KeyboardKey.KEY_Q),
        0x11: int(rl.KeyboardKey.KEY_W),
        0x12: int(rl.KeyboardKey.KEY_E),
        0x13: int(rl.KeyboardKey.KEY_R),
        0x1C: int(rl.KeyboardKey.KEY_ENTER),
        0x1D: int(rl.KeyboardKey.KEY_LEFT_CONTROL),
        0x1E: int(rl.KeyboardKey.KEY_A),
        0x1F: int(rl.KeyboardKey.KEY_S),
        0x20: int(rl.KeyboardKey.KEY_D),
        0x2A: int(rl.KeyboardKey.KEY_LEFT_SHIFT),
        0x36: int(rl.KeyboardKey.KEY_RIGHT_SHIFT),
        0x38: int(rl.KeyboardKey.KEY_LEFT_ALT),
        0x39: int(rl.KeyboardKey.KEY_SPACE),
        0x9D: int(rl.KeyboardKey.KEY_RIGHT_CONTROL),
        0xC8: int(rl.KeyboardKey.KEY_UP),
        0xC9: int(rl.KeyboardKey.KEY_PAGE_UP),
        0xCB: int(rl.KeyboardKey.KEY_LEFT),
        0xCD: int(rl.KeyboardKey.KEY_RIGHT),
        0xD0: int(rl.KeyboardKey.KEY_DOWN),
        0xD1: int(rl.KeyboardKey.KEY_PAGE_DOWN),
        0xD3: int(rl.KeyboardKey.KEY_DELETE),
    }.get(dik_code)


def _mouse_button_for_code(key_code: int) -> int | None:
    key_code = int(key_code)
    return {
        0x100: int(rl.MouseButton.MOUSE_BUTTON_LEFT),
        0x101: int(rl.MouseButton.MOUSE_BUTTON_RIGHT),
        0x102: int(rl.MouseButton.MOUSE_BUTTON_MIDDLE),
        0x103: int(rl.MouseButton.MOUSE_BUTTON_SIDE),
        0x104: int(rl.MouseButton.MOUSE_BUTTON_EXTRA),
    }.get(key_code)


def input_code_name(key_code: int) -> str:
    key_code = int(key_code)
    if key_code == INPUT_CODE_UNBOUND:
        return "unbound"
    if key_code == 0x100:
        return "Mouse1"
    if key_code == 0x101:
        return "Mouse2"
    if key_code == 0x102:
        return "Mouse3"
    if key_code == 0x103:
        return "Mouse4"
    if key_code == 0x104:
        return "Mouse5"
    if key_code == 0x109:
        return "MWheelUp"
    if key_code == 0x10A:
        return "MWheelDown"

    extended_name = {
        0x11F: "Joys1",
        0x120: "Joys2",
        0x121: "Joys3",
        0x122: "Joys4",
        0x123: "Joys5",
        0x124: "Joys6",
        0x125: "Joys7",
        0x126: "Joys8",
        0x127: "Joys9",
        0x128: "Joys10",
        0x129: "Joys11",
        0x12A: "Joys12",
        0x131: "JoysUp",
        0x132: "JoysDown",
        0x133: "JoysLeft",
        0x134: "JoysRight",
        0x13F: "JoyAxisX",
        0x140: "JoyAxisY",
        0x141: "JoyAxisZ",
        0x153: "JoyRotX",
        0x154: "JoyRotY",
        0x155: "JoyRotZ",
        0x163: "RIM0XAxis",
        0x164: "RIM1XAxis",
        0x165: "RIM2XAxis",
        0x168: "RIM0YAxis",
        0x169: "RIM1YAxis",
        0x16A: "RIM2YAxis",
        0x16D: "RIM0Btn1",
        0x16E: "RIM0Btn2",
        0x16F: "RIM0Btn3",
        0x170: "RIM0Btn4",
        0x171: "RIM0Btn5",
        0x172: "RIM1Btn1",
        0x173: "RIM1Btn2",
        0x174: "RIM1Btn3",
        0x175: "RIM1Btn4",
        0x176: "RIM1Btn5",
        0x177: "RIM2Btn1",
        0x178: "RIM2Btn2",
        0x179: "RIM2Btn3",
        0x17A: "RIM2Btn4",
        0x17B: "RIM2Btn5",
    }.get(key_code)
    if extended_name is not None:
        return extended_name
    if key_code > 0x163:
        return "RawInput ?"

    if key_code < 0x100:
        name = {
            0x01: "Escape",
            0x0F: "Tab",
            0x10: "Q",
            0x11: "W",
            0x12: "E",
            0x13: "R",
            0x1C: "Enter",
            0x1D: "LControl",
            0x1E: "A",
            0x1F: "S",
            0x20: "D",
            0x2A: "LShift",
            0x36: "RShift",
            0x38: "LAlt",
            0x39: "Space",
            0x9D: "RControl",
            0xC8: "Up",
            0xC9: "PageUp",
            0xCB: "Left",
            0xCD: "Right",
            0xD0: "Down",
            0xD1: "PageDown",
            0xD3: "Delete",
        }.get(key_code)
        if name is not None:
            return name
        return f"DIK_{key_code:02X}"

    return f"KEY_{key_code:04X}"


def input_code_is_down(key_code: int) -> bool:
    key_code = int(key_code)
    if key_code == INPUT_CODE_UNBOUND:
        return False
    mouse_button = _mouse_button_for_code(key_code)
    if mouse_button is not None:
        return bool(rl.is_mouse_button_down(mouse_button))
    if key_code < 0x100:
        rl_key = _dik_to_rl_key(key_code)
        if rl_key is None:
            return False
        return bool(rl.is_key_down(rl_key))
    return False


def input_code_is_pressed(key_code: int) -> bool:
    key_code = int(key_code)
    if key_code == INPUT_CODE_UNBOUND:
        return False
    mouse_button = _mouse_button_for_code(key_code)
    if mouse_button is not None:
        return bool(rl.is_mouse_button_pressed(mouse_button))
    if key_code < 0x100:
        rl_key = _dik_to_rl_key(key_code)
        if rl_key is None:
            return False
        return bool(rl.is_key_pressed(rl_key))
    return False


def _parse_keybinds_blob(blob: bytes | bytearray | None) -> tuple[int, ...]:
    if blob is None:
        return ()
    if not isinstance(blob, (bytes, bytearray)):
        return ()
    if len(blob) != 0x80:
        return ()
    out: list[int] = []
    for offset in range(0, 0x80, 4):
        out.append(int.from_bytes(blob[offset : offset + 4], "little"))
    return tuple(out)


def config_keybinds(config: CrimsonConfig | None) -> tuple[int, ...]:
    if config is None:
        return ()
    return _parse_keybinds_blob(config.data.get("keybinds"))


def player_move_fire_binds(keybinds: Sequence[int], player_index: int) -> tuple[int, int, int, int, int]:
    """Return (up, down, left, right, fire) key codes for a player.

    The classic config packs keybind blocks in 0x10-int strides; the first five entries
    are used by `ui_render_keybind_help` (Up/Down/Left/Right/Fire).
    """

    base = int(player_index) * 0x10
    values = [INPUT_CODE_UNBOUND, INPUT_CODE_UNBOUND, INPUT_CODE_UNBOUND, INPUT_CODE_UNBOUND, INPUT_CODE_UNBOUND]
    for idx in range(5):
        src = base + idx
        if 0 <= src < len(keybinds):
            values[idx] = int(keybinds[src])
    return values[0], values[1], values[2], values[3], values[4]
