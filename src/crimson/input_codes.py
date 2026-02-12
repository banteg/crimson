from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import pyray as rl

from grim.config import CrimsonConfig, default_player_keybind_block, player_keybind_block


INPUT_CODE_UNBOUND = 0x17E
_AXIS_DEADZONE = 0.2
_AXIS_DOWN_THRESHOLD = 0.5

_DIK_TO_RL_KEY: dict[int, int] = {
    0x01: int(rl.KeyboardKey.KEY_ESCAPE),
    0x02: int(rl.KeyboardKey.KEY_ONE),
    0x03: int(rl.KeyboardKey.KEY_TWO),
    0x04: int(rl.KeyboardKey.KEY_THREE),
    0x05: int(rl.KeyboardKey.KEY_FOUR),
    0x06: int(rl.KeyboardKey.KEY_FIVE),
    0x07: int(rl.KeyboardKey.KEY_SIX),
    0x08: int(rl.KeyboardKey.KEY_SEVEN),
    0x09: int(rl.KeyboardKey.KEY_EIGHT),
    0x0A: int(rl.KeyboardKey.KEY_NINE),
    0x0B: int(rl.KeyboardKey.KEY_ZERO),
    0x0C: int(rl.KeyboardKey.KEY_MINUS),
    0x0D: int(rl.KeyboardKey.KEY_EQUAL),
    0x0E: int(rl.KeyboardKey.KEY_BACKSPACE),
    0x0F: int(rl.KeyboardKey.KEY_TAB),
    0x10: int(rl.KeyboardKey.KEY_Q),
    0x11: int(rl.KeyboardKey.KEY_W),
    0x12: int(rl.KeyboardKey.KEY_E),
    0x13: int(rl.KeyboardKey.KEY_R),
    0x14: int(rl.KeyboardKey.KEY_T),
    0x15: int(rl.KeyboardKey.KEY_Y),
    0x16: int(rl.KeyboardKey.KEY_U),
    0x17: int(rl.KeyboardKey.KEY_I),
    0x18: int(rl.KeyboardKey.KEY_O),
    0x19: int(rl.KeyboardKey.KEY_P),
    0x1A: int(rl.KeyboardKey.KEY_LEFT_BRACKET),
    0x1B: int(rl.KeyboardKey.KEY_RIGHT_BRACKET),
    0x1C: int(rl.KeyboardKey.KEY_ENTER),
    0x1D: int(rl.KeyboardKey.KEY_LEFT_CONTROL),
    0x1E: int(rl.KeyboardKey.KEY_A),
    0x1F: int(rl.KeyboardKey.KEY_S),
    0x20: int(rl.KeyboardKey.KEY_D),
    0x21: int(rl.KeyboardKey.KEY_F),
    0x22: int(rl.KeyboardKey.KEY_G),
    0x23: int(rl.KeyboardKey.KEY_H),
    0x24: int(rl.KeyboardKey.KEY_J),
    0x25: int(rl.KeyboardKey.KEY_K),
    0x26: int(rl.KeyboardKey.KEY_L),
    0x27: int(rl.KeyboardKey.KEY_SEMICOLON),
    0x28: int(rl.KeyboardKey.KEY_APOSTROPHE),
    0x29: int(rl.KeyboardKey.KEY_GRAVE),
    0x2A: int(rl.KeyboardKey.KEY_LEFT_SHIFT),
    0x2B: int(rl.KeyboardKey.KEY_BACKSLASH),
    0x2C: int(rl.KeyboardKey.KEY_Z),
    0x2D: int(rl.KeyboardKey.KEY_X),
    0x2E: int(rl.KeyboardKey.KEY_C),
    0x2F: int(rl.KeyboardKey.KEY_V),
    0x30: int(rl.KeyboardKey.KEY_B),
    0x31: int(rl.KeyboardKey.KEY_N),
    0x32: int(rl.KeyboardKey.KEY_M),
    0x33: int(rl.KeyboardKey.KEY_COMMA),
    0x34: int(rl.KeyboardKey.KEY_PERIOD),
    0x35: int(rl.KeyboardKey.KEY_SLASH),
    0x36: int(rl.KeyboardKey.KEY_RIGHT_SHIFT),
    0x38: int(rl.KeyboardKey.KEY_LEFT_ALT),
    0x39: int(rl.KeyboardKey.KEY_SPACE),
    0x3B: int(rl.KeyboardKey.KEY_F1),
    0x3C: int(rl.KeyboardKey.KEY_F2),
    0x3D: int(rl.KeyboardKey.KEY_F3),
    0x3E: int(rl.KeyboardKey.KEY_F4),
    0x3F: int(rl.KeyboardKey.KEY_F5),
    0x40: int(rl.KeyboardKey.KEY_F6),
    0x41: int(rl.KeyboardKey.KEY_F7),
    0x42: int(rl.KeyboardKey.KEY_F8),
    0x43: int(rl.KeyboardKey.KEY_F9),
    0x44: int(rl.KeyboardKey.KEY_F10),
    0x57: int(rl.KeyboardKey.KEY_F11),
    0x58: int(rl.KeyboardKey.KEY_F12),
    0x9D: int(rl.KeyboardKey.KEY_RIGHT_CONTROL),
    0xC8: int(rl.KeyboardKey.KEY_UP),
    0xC9: int(rl.KeyboardKey.KEY_PAGE_UP),
    0xCB: int(rl.KeyboardKey.KEY_LEFT),
    0xCD: int(rl.KeyboardKey.KEY_RIGHT),
    0xD0: int(rl.KeyboardKey.KEY_DOWN),
    0xD1: int(rl.KeyboardKey.KEY_PAGE_DOWN),
    0xD2: int(rl.KeyboardKey.KEY_INSERT),
    0xD3: int(rl.KeyboardKey.KEY_DELETE),
    0xCF: int(rl.KeyboardKey.KEY_END),
    0xC7: int(rl.KeyboardKey.KEY_HOME),
}

_RL_KEY_TO_DIK: dict[int, int] = {value: key for key, value in _DIK_TO_RL_KEY.items()}

_MOUSE_CODE_TO_BUTTON: dict[int, int] = {
    0x100: int(rl.MouseButton.MOUSE_BUTTON_LEFT),
    0x101: int(rl.MouseButton.MOUSE_BUTTON_RIGHT),
    0x102: int(rl.MouseButton.MOUSE_BUTTON_MIDDLE),
    0x103: int(rl.MouseButton.MOUSE_BUTTON_SIDE),
    0x104: int(rl.MouseButton.MOUSE_BUTTON_EXTRA),
}

_JOYS_BUTTON_CODES: dict[int, int] = {
    0x11F: int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN),
    0x120: int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT),
    0x121: int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_LEFT),
    0x122: int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_UP),
    0x123: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_UP),
    0x124: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_RIGHT),
    0x125: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN),
    0x126: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_LEFT),
    0x127: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_TRIGGER_1),
    0x128: int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_TRIGGER_1),
    0x129: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_TRIGGER_2),
    0x12A: int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_TRIGGER_2),
    0x131: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_UP),
    0x132: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN),
    0x133: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_LEFT),
    0x134: int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_RIGHT),
}

_AXIS_CODE_TO_AXIS: dict[int, int] = {
    0x13F: int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_X),
    0x140: int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_Y),
    # Native Grim maps 0x141 and 0x153 to distinct joystick state fields
    # (lZ vs lRx in grim_get_config_float @ 0x100071b0), so keep them distinct.
    # On raylib backends this is approximated with separate right-stick axes.
    0x141: int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_Y),
    0x153: int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_X),
    0x154: int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_Y),
    0x155: int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_TRIGGER),
}

_RIM_AXIS_CODES: dict[int, tuple[int, int]] = {
    0x163: (0, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_X)),
    0x164: (1, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_X)),
    0x165: (2, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_X)),
    0x168: (0, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_Y)),
    0x169: (1, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_Y)),
    0x16A: (2, int(rl.GamepadAxis.GAMEPAD_AXIS_LEFT_Y)),
}

_RIM_BUTTON_CODES: dict[int, tuple[int, int]] = {
    0x16D: (0, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN)),
    0x16E: (0, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT)),
    0x16F: (0, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_LEFT)),
    0x170: (0, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_UP)),
    0x171: (0, int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_TRIGGER_1)),
    0x172: (1, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN)),
    0x173: (1, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT)),
    0x174: (1, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_LEFT)),
    0x175: (1, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_UP)),
    0x176: (1, int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_TRIGGER_1)),
    0x177: (2, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN)),
    0x178: (2, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT)),
    0x179: (2, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_LEFT)),
    0x17A: (2, int(rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_UP)),
    0x17B: (2, int(rl.GamepadButton.GAMEPAD_BUTTON_LEFT_TRIGGER_1)),
}


@dataclass(slots=True)
class _PressedState:
    prev_down: dict[tuple[int, int], bool] = field(default_factory=dict)
    down: dict[tuple[int, int], bool] = field(default_factory=dict)
    pressed_cache: dict[tuple[int, int], bool] = field(default_factory=dict)
    wheel_up: bool = False
    wheel_down: bool = False

    def begin_frame(self) -> None:
        # Keep last-known key state for keys that are not polled every frame.
        # This preserves edge semantics across temporary input-query gaps and
        # matches the native latch-style behavior used by input_primary_just_pressed.
        self.prev_down = dict(self.down)
        self.pressed_cache = {}
        wheel_move = float(rl.get_mouse_wheel_move())
        self.wheel_up = wheel_move > 0.0
        self.wheel_down = wheel_move < 0.0

    def mark_down(self, *, player_index: int, key_code: int, is_down: bool) -> bool:
        key = (int(player_index), int(key_code))
        self.down[key] = bool(is_down)
        return bool(is_down)

    def is_pressed(self, *, player_index: int, key_code: int, is_down: bool) -> bool:
        key = (int(player_index), int(key_code))
        cached = self.pressed_cache.get(key)
        if cached is not None:
            return bool(cached)
        prev = bool(self.prev_down.get(key, False))
        pressed = bool(is_down) and (not prev)
        self.down[key] = bool(is_down)
        self.pressed_cache[key] = bool(pressed)
        return bool(pressed)


_PRESSED_STATE = _PressedState()
_PRIMARY_EDGE_SENTINEL_PLAYER = -1
_PRIMARY_EDGE_SENTINEL_KEY = -1


def _dik_to_rl_key(dik_code: int) -> int | None:
    return _DIK_TO_RL_KEY.get(int(dik_code))


def _mouse_button_for_code(key_code: int) -> int | None:
    return _MOUSE_CODE_TO_BUTTON.get(int(key_code))


def _player_gamepad_index(player_index: int) -> int:
    return max(0, min(3, int(player_index)))


def _axis_value_for_gamepad(gamepad_index: int, axis: int) -> float:
    if not rl.is_gamepad_available(int(gamepad_index)):
        return 0.0
    value = float(rl.get_gamepad_axis_movement(int(gamepad_index), int(axis)))
    if abs(value) < _AXIS_DEADZONE:
        return 0.0
    return float(max(-1.0, min(1.0, value)))


def _axis_value_from_code(key_code: int, *, player_index: int) -> float:
    code = int(key_code)
    axis = _AXIS_CODE_TO_AXIS.get(code)
    if axis is not None:
        return _axis_value_for_gamepad(_player_gamepad_index(player_index), axis)
    rim_axis = _RIM_AXIS_CODES.get(code)
    if rim_axis is not None:
        rim_player, rim_axis_id = rim_axis
        return _axis_value_for_gamepad(rim_player, rim_axis_id)
    return 0.0


def input_axis_value_for_player(key_code: int, *, player_index: int) -> float:
    return _axis_value_from_code(int(key_code), player_index=int(player_index))


def _digital_down_for_player(key_code: int, *, player_index: int) -> bool:
    code = int(key_code)
    if code == INPUT_CODE_UNBOUND:
        return False

    mouse_button = _mouse_button_for_code(code)
    if mouse_button is not None:
        return bool(rl.is_mouse_button_down(mouse_button))
    if code < 0x100:
        rl_key = _dik_to_rl_key(code)
        if rl_key is None:
            return False
        return bool(rl.is_key_down(rl_key))
    joy_button = _JOYS_BUTTON_CODES.get(code)
    if joy_button is not None:
        gamepad = _player_gamepad_index(player_index)
        return bool(rl.is_gamepad_available(gamepad) and rl.is_gamepad_button_down(gamepad, joy_button))
    rim_button = _RIM_BUTTON_CODES.get(code)
    if rim_button is not None:
        gamepad, button = rim_button
        return bool(rl.is_gamepad_available(gamepad) and rl.is_gamepad_button_down(gamepad, button))
    if code in _AXIS_CODE_TO_AXIS or code in _RIM_AXIS_CODES:
        return abs(_axis_value_from_code(code, player_index=player_index)) >= _AXIS_DOWN_THRESHOLD
    return False


def input_begin_frame() -> None:
    """Latch input edge state once per rendered frame."""

    _PRESSED_STATE.begin_frame()


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
    return input_code_is_down_for_player(int(key_code), player_index=0)


def input_code_is_pressed(key_code: int) -> bool:
    return input_code_is_pressed_for_player(int(key_code), player_index=0)


def input_code_is_down_for_player(key_code: int, *, player_index: int) -> bool:
    down = _digital_down_for_player(int(key_code), player_index=int(player_index))
    return _PRESSED_STATE.mark_down(player_index=int(player_index), key_code=int(key_code), is_down=down)


def input_code_is_pressed_for_player(key_code: int, *, player_index: int) -> bool:
    code = int(key_code)
    player_idx = int(player_index)
    if code == 0x109:
        return bool(_PRESSED_STATE.wheel_up)
    if code == 0x10A:
        return bool(_PRESSED_STATE.wheel_down)
    down = _digital_down_for_player(code, player_index=player_idx)
    return _PRESSED_STATE.is_pressed(player_index=player_idx, key_code=code, is_down=down)


def capture_first_pressed_input_code(
    *,
    player_index: int,
    include_keyboard: bool = True,
    include_mouse: bool = True,
    include_gamepad: bool = True,
    include_axes: bool = True,
    axis_threshold: float = 0.5,
) -> int | None:
    player_idx = int(player_index)

    if include_keyboard:
        while True:
            key = int(rl.get_key_pressed())
            if key <= 0:
                break
            code = _RL_KEY_TO_DIK.get(key)
            if code is not None and code != INPUT_CODE_UNBOUND:
                return int(code)

    if include_mouse:
        for code, button in _MOUSE_CODE_TO_BUTTON.items():
            if rl.is_mouse_button_pressed(button):
                return int(code)
        wheel = float(rl.get_mouse_wheel_move())
        if wheel > 0.0:
            return 0x109
        if wheel < 0.0:
            return 0x10A

    if include_gamepad:
        gamepad = _player_gamepad_index(player_idx)
        if rl.is_gamepad_available(gamepad):
            for code, button in _JOYS_BUTTON_CODES.items():
                if rl.is_gamepad_button_pressed(gamepad, button):
                    return int(code)

    if include_axes:
        gamepad = _player_gamepad_index(player_idx)
        if rl.is_gamepad_available(gamepad):
            for code, axis in _AXIS_CODE_TO_AXIS.items():
                value = float(rl.get_gamepad_axis_movement(gamepad, axis))
                if abs(value) >= float(axis_threshold):
                    return int(code)

    return None


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
    return _parse_keybinds_blob(config.keybinds_blob())


def config_keybinds_for_player(config: CrimsonConfig | None, *, player_index: int) -> tuple[int, ...]:
    if config is None:
        return ()
    return tuple(int(value) for value in player_keybind_block(config.data, player_index=int(player_index)))


def player_fire_keybind(config: CrimsonConfig | None, *, player_index: int) -> int:
    idx = max(0, min(3, int(player_index)))
    keybinds = config_keybinds_for_player(config, player_index=idx)
    if len(keybinds) >= 5:
        return int(keybinds[4])
    return int(default_player_keybind_block(idx)[4])


def _input_primary_any_down(config: CrimsonConfig | None, *, player_count: int) -> bool:
    if input_code_is_down_for_player(0x100, player_index=0):
        return True

    count = max(1, min(4, int(player_count)))
    for player_index in range(count):
        fire_key = player_fire_keybind(config, player_index=player_index)
        if input_code_is_down_for_player(fire_key, player_index=player_index):
            return True
    return False


def input_primary_is_down(config: CrimsonConfig | None, *, player_count: int) -> bool:
    down = _input_primary_any_down(config, player_count=player_count)
    _PRESSED_STATE.mark_down(
        player_index=_PRIMARY_EDGE_SENTINEL_PLAYER,
        key_code=_PRIMARY_EDGE_SENTINEL_KEY,
        is_down=down,
    )
    return bool(down)


def input_primary_just_pressed(config: CrimsonConfig | None, *, player_count: int) -> bool:
    down = _input_primary_any_down(config, player_count=player_count)
    return _PRESSED_STATE.is_pressed(
        player_index=_PRIMARY_EDGE_SENTINEL_PLAYER,
        key_code=_PRIMARY_EDGE_SENTINEL_KEY,
        is_down=down,
    )


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
