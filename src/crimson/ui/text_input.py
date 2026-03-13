from __future__ import annotations

from collections.abc import Callable

from grim.config import CrimsonConfig
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ..input_codes import INPUT_CODE_UNBOUND, input_code_is_down
from ..rng_caller_static import RngCallerStatic

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


def update_name_entry_text(
    text: str,
    caret: int,
    *,
    max_len: int,
    rng: CrandLike,
    play_sfx: Callable[[SfxId], None] | None = None,
) -> tuple[str, int]:
    typed = poll_text_input(max_len - len(text), allow_space=True)
    if typed:
        text = (text[:caret] + typed + text[caret:])[:max_len]
        caret = min(len(text), caret + len(typed))
        if play_sfx is not None:
            play_sfx(
                SfxId.UI_TYPECLICK_01
                if (rng.rand(caller=RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK) & 1) == 0
                else SfxId.UI_TYPECLICK_02,
            )
    if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE) and caret > 0:
        text = text[: caret - 1] + text[caret:]
        caret -= 1
        if play_sfx is not None:
            play_sfx(
                SfxId.UI_TYPECLICK_01
                if (rng.rand(caller=RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK) & 1) == 0
                else SfxId.UI_TYPECLICK_02,
            )
    if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
        caret = max(0, caret - 1)
    if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
        caret = min(len(text), caret + 1)
    if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
        caret = 0
    if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
        caret = len(text)
    return text, caret


def gameplay_controls_held(config: CrimsonConfig) -> bool:
    player_count = max(1, min(4, config.gameplay.player_count))
    for player_index in range(player_count):
        move_codes = tuple(int(code) for code in config.controls.player(player_index).move_codes)
        for code in (
            move_codes[0],
            move_codes[1],
            move_codes[2],
            move_codes[3],
            int(config.controls.player(player_index).fire_code),
        )[:_CONTROL_BIND_SLOTS]:
            key_code = int(code)
            if key_code == INPUT_CODE_UNBOUND:
                continue
            if input_code_is_down(key_code, player_index=player_index):
                return True

    for code in _SINGLE_PLAYER_ALT_MOVE_CODES:
        if input_code_is_down(int(code), player_index=0):
            return True
    return False
