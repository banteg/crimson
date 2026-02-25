from __future__ import annotations

from grim.config import CrimsonConfig
from grim.raylib_api import rl

from ..input_codes import INPUT_CODE_UNBOUND, config_keybinds_for_player, input_code_is_down_for_player

_CONTROL_BIND_SLOTS = 5
_SINGLE_PLAYER_ALT_MOVE_CODES: tuple[int, ...] = (0xC8, 0xD0, 0xCB, 0xCD)


def poll_text_input(max_len: int, *, allow_space: bool = True) -> str:
    out = ""
    while True:
        value = rl.get_char_pressed()
        if value == 0:
            break
        if value < 0x20 or value > 0xFF:
            continue
        if not allow_space and value == 0x20:
            continue
        if len(out) >= max_len:
            continue
        out += chr(int(value))
    return out


def flush_text_input_events() -> None:
    # Native flows call `grim_flush_input()` before entering high-score name input.
    while rl.get_char_pressed():
        pass
    while rl.get_key_pressed():
        pass


def gameplay_controls_held(config: CrimsonConfig) -> bool:
    player_count = max(1, min(4, config.player_count))
    for player_index in range(player_count):
        binds = config_keybinds_for_player(config, player_index=player_index)
        for code in binds[:_CONTROL_BIND_SLOTS]:
            key_code = int(code)
            if key_code == INPUT_CODE_UNBOUND:
                continue
            if input_code_is_down_for_player(key_code, player_index=player_index):
                return True

    for code in _SINGLE_PLAYER_ALT_MOVE_CODES:
        if input_code_is_down_for_player(int(code), player_index=0):
            return True
    return False
