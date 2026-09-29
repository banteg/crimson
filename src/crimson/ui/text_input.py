from __future__ import annotations

import math
from collections.abc import Callable

import msgspec

from grim.assets import RuntimeResources
from grim.color import grim_color
from grim.config import CrimsonConfig
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ..input_codes import INPUT_CODE_UNBOUND, input_code_is_down
from ..rng_caller_static import RngCallerStatic
from .focus import UiFocus

_CONTROL_BIND_SLOTS = 5
_SINGLE_PLAYER_ALT_MOVE_CODES: tuple[int, ...] = (0xC8, 0xD0, 0xCB, 0xCD)


class UiTextInput(msgspec.Struct):
    """The focus half of native `ui_text_input_state_t`; the caller keeps the text and caret."""

    focused: bool = False


def ui_text_input_focus(focus: UiFocus, field: UiTextInput, pos: Vec2, *, width: float, mouse: Vec2) -> None:
    """`ui_text_input_update`'s focus: the box registers, and hovering its 18px row focuses it."""
    field.focused = focus.update(field)
    if pos.x < mouse.x < pos.x + width and pos.y < mouse.y < pos.y + 18.0:
        focus.set(field)


def ui_text_input_draw_focus(focus: UiFocus, field: UiTextInput, pos: Vec2) -> None:
    if field.focused:
        focus.draw(pos.offset(dx=-16.0))


def ui_text_input_draw(resources: RuntimeResources, pos: Vec2, *, width: float, text: str, caret: int) -> None:
    """`ui_text_input_update`'s draw half: an 18px box at full alpha, the text scrolled to fit, a blinking caret.

    Native always types at the end; the port's caret can move, so it is drawn at its own position.
    """
    font = resources.small_font
    grim_draw_rect_outline(pos, width, 18.0, rl.WHITE)
    rl.draw_rectangle(int(pos.x + 1.0), int(pos.y + 1.0), int(width - 2.0), 16, rl.BLACK)
    start = 0
    while start < len(text) and measure_small_text_width(font, text[start:]) > width - 10.0:
        start += 1
    draw_small_text(font, text[start:], pos + Vec2(4.0, 2.0), grim_color(1.0, 1.0, 1.0, 0.8))
    caret_alpha = 0.4 if math.sin(rl.get_time() * 4.0) > 0.0 else 1.0
    caret_x = pos.x + 4.0 + measure_small_text_width(font, text[start:max(start, caret)])
    grim_draw_rect_outline(Vec2(caret_x, pos.y + 2.0), 1.0, 14.0, grim_color(1.0, 1.0, 1.0, caret_alpha))


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
                if (rng.rand_tagged(RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK) & 1) == 0
                else SfxId.UI_TYPECLICK_02,
            )
    if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE) and caret > 0:
        text = text[: caret - 1] + text[caret:]
        caret -= 1
        if play_sfx is not None:
            play_sfx(
                SfxId.UI_TYPECLICK_01
                if (rng.rand_tagged(RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK) & 1) == 0
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
        player_controls = config.controls.player(player_index)
        move_forward_key, move_backward_key, turn_left_key, turn_right_key = player_controls.move_codes
        for code in (
            move_forward_key,
            move_backward_key,
            turn_left_key,
            turn_right_key,
            player_controls.fire_code,
        )[:_CONTROL_BIND_SLOTS]:
            if code == INPUT_CODE_UNBOUND:
                continue
            if input_code_is_down(code, player_index=player_index):
                return True

    return any(input_code_is_down(int(code), player_index=0) for code in _SINGLE_PLAYER_ALT_MOVE_CODES)
