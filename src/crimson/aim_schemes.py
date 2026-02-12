from __future__ import annotations

from enum import IntEnum


class AimScheme(IntEnum):
    """Aiming scheme ids from `config_aim_scheme`."""

    UNKNOWN = -1
    MOUSE = 0
    KEYBOARD = 1
    JOYSTICK = 2
    MOUSE_RELATIVE = 3
    DUAL_ACTION_PAD = 4
    COMPUTER = 5


def aim_scheme_from_value(
    value: int,
) -> AimScheme:
    try:
        return AimScheme(int(value))
    except Exception:
        return AimScheme.UNKNOWN
