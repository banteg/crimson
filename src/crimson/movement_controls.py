from __future__ import annotations

from enum import IntEnum


class MovementControlType(IntEnum):
    """Movement control mode ids from `config_player_mode_flags`."""

    UNKNOWN = 0
    RELATIVE = 1
    STATIC = 2
    DUAL_ACTION_PAD = 3
    MOUSE_POINT_CLICK = 4
    COMPUTER = 5


def movement_control_type_from_value(
    value: int,
) -> MovementControlType:
    try:
        return MovementControlType(int(value))
    except (TypeError, ValueError):
        return MovementControlType.UNKNOWN
