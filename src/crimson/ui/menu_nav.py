from __future__ import annotations

from grim.raylib_api import rl

from ..input_codes import PadCode, pad_nav_pressed


def menu_focus_step() -> int:
    """Keyboard focus cycling (Tab / Shift+Tab) or D-pad down/up on any pad."""

    if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
        reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
        return -1 if reverse else 1
    if pad_nav_pressed(PadCode.DPAD_DOWN):
        return 1
    if pad_nav_pressed(PadCode.DPAD_UP):
        return -1
    return 0


def menu_confirm_pressed() -> bool:
    return rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or pad_nav_pressed(PadCode.FACE_DOWN)
