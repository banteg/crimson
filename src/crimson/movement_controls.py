from __future__ import annotations

from enum import IntEnum


class MovementControlType(IntEnum):
    """Movement control mode ids from `config_player_mode_flags`."""

    RELATIVE = 1
    STATIC = 2
    DUAL_ACTION_PAD = 3
    MOUSE_POINT_CLICK = 4
    COMPUTER = 5


def movement_control_type_from_value(
    value: object,
) -> MovementControlType | None:
    if isinstance(value, bool):
        raw = int(value)
    elif isinstance(value, (int, float, str, bytes, bytearray)):
        try:
            raw = int(value)
        except Exception:
            return None
    else:
        return None

    try:
        return MovementControlType(raw)
    except Exception:
        return None
