from __future__ import annotations

import struct
from typing import Mapping

from ...movement_controls import MovementControlType, movement_control_type_from_value


PICK_PERK_BIND_SLOT = -1
RELOAD_BIND_SLOT = -2


def input_configure_for_label(config_id: int) -> str:
    """Port of `input_configure_for_label` (0x00447c90)."""

    labels = (
        "Mouse",
        "Keyboard",
        "Joystick",
        "Mouse relative",
        "Dual Action Pad",
        "Computer",
    )
    idx = int(config_id)
    if 0 <= idx < len(labels):
        return labels[idx]
    return "Unknown"


def input_scheme_label(scheme: MovementControlType) -> str:
    """Port of `input_scheme_label` (0x00447cf0)."""

    labels = {
        MovementControlType.UNKNOWN: "Unknown",
        MovementControlType.RELATIVE: "Relative",
        MovementControlType.STATIC: "Static",
        MovementControlType.DUAL_ACTION_PAD: "Dual Action Pad",
        MovementControlType.MOUSE_POINT_CLICK: "Mouse point click",
        MovementControlType.COMPUTER: "Computer",
    }
    return labels.get(scheme, "Unknown")


def _read_player_mode_flags(
    config_data: Mapping[str, object],
) -> tuple[MovementControlType, MovementControlType, MovementControlType, MovementControlType]:
    # Defaults from `config_init_defaults`: 2 (Static) for player mode flags.
    values = [MovementControlType.STATIC] * 4
    raw = config_data.get("unknown_1c")
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 16:
        for idx in range(4):
            value = int(struct.unpack_from("<I", raw, idx * 4)[0])
            if value > 0:
                values[idx] = movement_control_type_from_value(value)
    return (values[0], values[1], values[2], values[3])


def _read_aim_schemes(config_data: Mapping[str, object]) -> tuple[int, int, int, int]:
    # Defaults from `config_init_defaults`: 0 (Mouse) for aim schemes.
    values = [0, 0, 0, 0]

    def _coerce_int(value: object, default: int = 0) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float, str, bytes, bytearray)):
            try:
                return int(value)
            except Exception:
                return default
        return default

    values[0] = _coerce_int(config_data.get("unknown_44"), 0)
    values[1] = _coerce_int(config_data.get("unknown_48"), 0)

    raw = config_data.get("unknown_4c")
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 8:
        values[2] = int(struct.unpack_from("<I", raw, 0)[0])
        values[3] = int(struct.unpack_from("<I", raw, 4)[0])

    for idx in range(4):
        value = int(values[idx])
        if value < 0:
            values[idx] = 0
        elif value > 5:
            values[idx] = 0

    return (values[0], values[1], values[2], values[3])


def controls_method_values(config_data: Mapping[str, object], *, player_index: int) -> tuple[int, MovementControlType]:
    player_idx = max(0, min(3, int(player_index)))
    aim_scheme = _read_aim_schemes(config_data)[player_idx]
    move_mode = _read_player_mode_flags(config_data)[player_idx]
    return int(aim_scheme), move_mode


def controls_method_labels(config_data: Mapping[str, object], *, player_index: int) -> tuple[str, str]:
    aim_scheme, move_mode = controls_method_values(config_data, player_index=player_index)
    return input_configure_for_label(aim_scheme), input_scheme_label(move_mode)


def controls_aim_method_dropdown_ids(current_aim_scheme: int) -> tuple[int, ...]:
    ids = [0, 1, 2, 3, 4]
    if int(current_aim_scheme) == 5:
        # Original menu keeps "Computer" hidden unless loaded from config.
        ids.append(5)
    return tuple(ids)


def controls_rebind_slot_plan(
    *,
    aim_scheme: int,
    move_mode: MovementControlType,
    player_index: int,
) -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    """Return (aim_rows, move_rows, misc_rows) for `controls_menu_update`."""

    aim_rows: list[tuple[str, int]] = []
    move_rows: list[tuple[str, int]] = []
    misc_rows: list[tuple[str, int]] = []

    if int(aim_scheme) == 1:
        aim_rows.append(("Torso left:", 7))
        aim_rows.append(("Torso right:", 8))
    elif int(aim_scheme) == 4:
        aim_rows.append(("Aim Up/Down Axis:", 9))
        aim_rows.append(("Aim Left/Right Axis:", 10))
    aim_rows.append(("Fire:", 4))

    if move_mode is MovementControlType.STATIC:
        move_rows.extend(
            (
                ("Move Up:", 0),
                ("Move Down:", 1),
                ("Move Left:", 2),
                ("Move Right:", 3),
            )
        )
    elif move_mode is MovementControlType.RELATIVE:
        move_rows.extend(
            (
                ("Forward:", 0),
                ("Backwards:", 1),
                ("Turn left:", 2),
                ("Turn right:", 3),
            )
        )
    elif move_mode is MovementControlType.DUAL_ACTION_PAD:
        move_rows.extend(
            (
                ("Up/Down Axis:", 11),
                ("Left/Right Axis:", 12),
            )
        )
    elif move_mode is MovementControlType.MOUSE_POINT_CLICK:
        move_rows.append(("Move to cursor:", RELOAD_BIND_SLOT))

    if int(player_index) == 0:
        misc_rows.append(("Level Up:", PICK_PERK_BIND_SLOT))
        if move_mode is not MovementControlType.MOUSE_POINT_CLICK:
            misc_rows.append(("Reload:", RELOAD_BIND_SLOT))

    return tuple(aim_rows), tuple(move_rows), tuple(misc_rows)
