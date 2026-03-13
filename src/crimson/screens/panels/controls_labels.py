from __future__ import annotations

from enum import Enum, auto

from grim.config import CrimsonControlsConfig

from ...aim_schemes import AimScheme
from ...movement_controls import MovementControlType


class BindingId(Enum):
    MOVE_FORWARD_CODE = auto()
    MOVE_BACKWARD_CODE = auto()
    TURN_LEFT_CODE = auto()
    TURN_RIGHT_CODE = auto()
    FIRE_CODE = auto()
    AIM_LEFT_CODE = auto()
    AIM_RIGHT_CODE = auto()
    AIM_VERTICAL_AXIS_CODE = auto()
    AIM_HORIZONTAL_AXIS_CODE = auto()
    MOVE_VERTICAL_AXIS_CODE = auto()
    MOVE_HORIZONTAL_AXIS_CODE = auto()
    PICK_PERK_CODE = auto()
    RELOAD_CODE = auto()


def input_configure_for_label(config_id: AimScheme) -> str:
    """Port of `input_configure_for_label` (0x00447c90)."""

    labels = {
        AimScheme.MOUSE: "Mouse",
        AimScheme.KEYBOARD: "Keyboard",
        AimScheme.JOYSTICK: "Joystick",
        AimScheme.MOUSE_RELATIVE: "Mouse relative",
        AimScheme.DUAL_ACTION_PAD: "Dual Action Pad",
        AimScheme.COMPUTER: "Computer",
    }
    return labels.get(config_id, "Unknown")


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


def controls_method_values(
    controls: CrimsonControlsConfig,
    *,
    player_index: int,
) -> tuple[AimScheme, MovementControlType]:
    player = controls.player(player_index)
    return player.aim_scheme, player.movement


def controls_method_labels(controls: CrimsonControlsConfig, *, player_index: int) -> tuple[str, str]:
    aim_scheme, move_mode = controls_method_values(controls, player_index=player_index)
    return input_configure_for_label(aim_scheme), input_scheme_label(move_mode)


def controls_aim_method_dropdown_ids(current_aim_scheme: AimScheme) -> tuple[AimScheme, ...]:
    ids = [
        AimScheme.MOUSE,
        AimScheme.KEYBOARD,
        AimScheme.JOYSTICK,
        AimScheme.MOUSE_RELATIVE,
        AimScheme.DUAL_ACTION_PAD,
    ]
    if current_aim_scheme is AimScheme.COMPUTER:
        # Original menu keeps "Computer" hidden unless loaded from config.
        ids.append(AimScheme.COMPUTER)
    return tuple(ids)


def controls_rebind_plan(
    *,
    aim_scheme: AimScheme,
    move_mode: MovementControlType,
    player_index: int,
) -> tuple[
    tuple[tuple[str, BindingId], ...],
    tuple[tuple[str, BindingId], ...],
    tuple[tuple[str, BindingId], ...],
]:
    """Return (aim_rows, move_rows, misc_rows) for `controls_menu_update`."""

    aim_rows: list[tuple[str, BindingId]] = []
    move_rows: list[tuple[str, BindingId]] = []
    misc_rows: list[tuple[str, BindingId]] = []

    if aim_scheme is AimScheme.KEYBOARD:
        aim_rows.append(("Torso left:", BindingId.AIM_LEFT_CODE))
        aim_rows.append(("Torso right:", BindingId.AIM_RIGHT_CODE))
    elif aim_scheme is AimScheme.DUAL_ACTION_PAD:
        aim_rows.append(("Aim Up/Down Axis:", BindingId.AIM_VERTICAL_AXIS_CODE))
        aim_rows.append(("Aim Left/Right Axis:", BindingId.AIM_HORIZONTAL_AXIS_CODE))
    aim_rows.append(("Fire:", BindingId.FIRE_CODE))

    if move_mode is MovementControlType.STATIC:
        move_rows.extend(
            (
                ("Move Up:", BindingId.MOVE_FORWARD_CODE),
                ("Move Down:", BindingId.MOVE_BACKWARD_CODE),
                ("Move Left:", BindingId.TURN_LEFT_CODE),
                ("Move Right:", BindingId.TURN_RIGHT_CODE),
            ),
        )
    elif move_mode is MovementControlType.RELATIVE:
        move_rows.extend(
            (
                ("Forward:", BindingId.MOVE_FORWARD_CODE),
                ("Backwards:", BindingId.MOVE_BACKWARD_CODE),
                ("Turn left:", BindingId.TURN_LEFT_CODE),
                ("Turn right:", BindingId.TURN_RIGHT_CODE),
            ),
        )
    elif move_mode is MovementControlType.DUAL_ACTION_PAD:
        move_rows.extend(
            (
                ("Up/Down Axis:", BindingId.MOVE_VERTICAL_AXIS_CODE),
                ("Left/Right Axis:", BindingId.MOVE_HORIZONTAL_AXIS_CODE),
            ),
        )
    elif move_mode is MovementControlType.MOUSE_POINT_CLICK:
        move_rows.append(("Move to cursor:", BindingId.RELOAD_CODE))

    if int(player_index) == 0:
        misc_rows.append(("Level Up:", BindingId.PICK_PERK_CODE))
        if move_mode is not MovementControlType.MOUSE_POINT_CLICK:
            misc_rows.append(("Reload:", BindingId.RELOAD_CODE))

    return tuple(aim_rows), tuple(move_rows), tuple(misc_rows)
