from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from grim.config import CrimsonControlsConfig

from ...aim_schemes import AimScheme
from ...movement_controls import MovementControlType


class RebindTarget(Enum):
    PLAYER_MOVE_CODES = auto()
    PLAYER_FIRE_CODE = auto()
    PLAYER_KEYBOARD_AIM_CODES = auto()
    PLAYER_AIM_AXIS_CODES = auto()
    PLAYER_MOVE_AXIS_CODES = auto()
    GLOBAL_PICK_PERK_CODE = auto()
    GLOBAL_RELOAD_CODE = auto()


@dataclass(frozen=True, slots=True)
class RebindRowSpec:
    label: str
    target: RebindTarget
    target_index: int | None = None
    axis: bool = False


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
        MovementControlType.MOUSE_POINT_CLICK: "Mouse point&click",
        MovementControlType.COMPUTER: "Computer",
    }
    return labels.get(scheme, "Unknown")


def controls_method_labels(controls: CrimsonControlsConfig, *, player_index: int) -> tuple[str, str]:
    player = controls.player(player_index)
    aim_scheme = player.aim_scheme
    move_mode = player.movement
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
    tuple[RebindRowSpec, ...],
    tuple[RebindRowSpec, ...],
    tuple[RebindRowSpec, ...],
]:
    """Return (aim_rows, move_rows, misc_rows) for `controls_menu_update`."""

    aim_rows: list[RebindRowSpec] = []
    move_rows: list[RebindRowSpec] = []
    misc_rows: list[RebindRowSpec] = []

    if aim_scheme is AimScheme.KEYBOARD:
        aim_rows.append(RebindRowSpec("Torso left:", RebindTarget.PLAYER_KEYBOARD_AIM_CODES, 0))
        aim_rows.append(RebindRowSpec("Torso right:", RebindTarget.PLAYER_KEYBOARD_AIM_CODES, 1))
    elif aim_scheme is AimScheme.DUAL_ACTION_PAD:
        aim_rows.append(RebindRowSpec("Aim Up/Down Axis:", RebindTarget.PLAYER_AIM_AXIS_CODES, 0, axis=True))
        aim_rows.append(RebindRowSpec("Aim Left/Right Axis:", RebindTarget.PLAYER_AIM_AXIS_CODES, 1, axis=True))
    aim_rows.append(RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE))

    if move_mode is MovementControlType.STATIC:
        move_rows.extend(
            (
                RebindRowSpec("Move Up:", RebindTarget.PLAYER_MOVE_CODES, 0),
                RebindRowSpec("Move Down:", RebindTarget.PLAYER_MOVE_CODES, 1),
                RebindRowSpec("Move Left:", RebindTarget.PLAYER_MOVE_CODES, 2),
                RebindRowSpec("Move Right:", RebindTarget.PLAYER_MOVE_CODES, 3),
            ),
        )
    elif move_mode is MovementControlType.RELATIVE:
        move_rows.extend(
            (
                RebindRowSpec("Forward:", RebindTarget.PLAYER_MOVE_CODES, 0),
                RebindRowSpec("Backwards:", RebindTarget.PLAYER_MOVE_CODES, 1),
                RebindRowSpec("Turn left:", RebindTarget.PLAYER_MOVE_CODES, 2),
                RebindRowSpec("Turn right:", RebindTarget.PLAYER_MOVE_CODES, 3),
            ),
        )
    elif move_mode is MovementControlType.DUAL_ACTION_PAD:
        move_rows.extend(
            (
                RebindRowSpec("Up/Down Axis:", RebindTarget.PLAYER_MOVE_AXIS_CODES, 0, axis=True),
                RebindRowSpec("Left/Right Axis:", RebindTarget.PLAYER_MOVE_AXIS_CODES, 1, axis=True),
            ),
        )
    elif move_mode is MovementControlType.MOUSE_POINT_CLICK:
        move_rows.append(RebindRowSpec("Move to cursor:", RebindTarget.GLOBAL_RELOAD_CODE))

    if int(player_index) == 0:
        misc_rows.append(RebindRowSpec("Level Up:", RebindTarget.GLOBAL_PICK_PERK_CODE))
        if move_mode is not MovementControlType.MOUSE_POINT_CLICK:
            misc_rows.append(RebindRowSpec("Reload:", RebindTarget.GLOBAL_RELOAD_CODE))

    return tuple(aim_rows), tuple(move_rows), tuple(misc_rows)
