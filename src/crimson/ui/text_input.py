from __future__ import annotations

from grim.raylib_api import rl


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
