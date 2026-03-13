from __future__ import annotations

from dataclasses import dataclass

from grim.config import CrimsonControlsConfig

from ...aim_schemes import AimScheme
from ...movement_controls import MovementControlType


@dataclass(frozen=True, slots=True)
class RebindRowSpec:
    label: str
    field_name: str
    field_index: int | None = None
    axis: bool = False
    controls_field: bool = False


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
        aim_rows.append(RebindRowSpec("Torso left:", "keyboard_aim_codes", 0))
        aim_rows.append(RebindRowSpec("Torso right:", "keyboard_aim_codes", 1))
    elif aim_scheme is AimScheme.DUAL_ACTION_PAD:
        aim_rows.append(RebindRowSpec("Aim Up/Down Axis:", "aim_axis_codes", 0, axis=True))
        aim_rows.append(RebindRowSpec("Aim Left/Right Axis:", "aim_axis_codes", 1, axis=True))
    aim_rows.append(RebindRowSpec("Fire:", "fire_code"))

    if move_mode is MovementControlType.STATIC:
        move_rows.extend(
            (
                RebindRowSpec("Move Up:", "move_codes", 0),
                RebindRowSpec("Move Down:", "move_codes", 1),
                RebindRowSpec("Move Left:", "move_codes", 2),
                RebindRowSpec("Move Right:", "move_codes", 3),
            ),
        )
    elif move_mode is MovementControlType.RELATIVE:
        move_rows.extend(
            (
                RebindRowSpec("Forward:", "move_codes", 0),
                RebindRowSpec("Backwards:", "move_codes", 1),
                RebindRowSpec("Turn left:", "move_codes", 2),
                RebindRowSpec("Turn right:", "move_codes", 3),
            ),
        )
    elif move_mode is MovementControlType.DUAL_ACTION_PAD:
        move_rows.extend(
            (
                RebindRowSpec("Up/Down Axis:", "move_axis_codes", 0, axis=True),
                RebindRowSpec("Left/Right Axis:", "move_axis_codes", 1, axis=True),
            ),
        )
    elif move_mode is MovementControlType.MOUSE_POINT_CLICK:
        move_rows.append(RebindRowSpec("Move to cursor:", "reload_code", controls_field=True))

    if int(player_index) == 0:
        misc_rows.append(RebindRowSpec("Level Up:", "pick_perk_code", controls_field=True))
        if move_mode is not MovementControlType.MOUSE_POINT_CLICK:
            misc_rows.append(RebindRowSpec("Reload:", "reload_code", controls_field=True))

    return tuple(aim_rows), tuple(move_rows), tuple(misc_rows)
