from __future__ import annotations

from grim.config import CrimsonControlsConfig

from ...aim_schemes import AimScheme
from ...movement_controls import MovementControlType

PICK_PERK_BIND_SLOT = -1
RELOAD_BIND_SLOT = -2


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


def controls_rebind_slot_plan(
    *,
    aim_scheme: AimScheme,
    move_mode: MovementControlType,
    player_index: int,
) -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    """Return (aim_rows, move_rows, misc_rows) for `controls_menu_update`."""

    aim_rows: list[tuple[str, int]] = []
    move_rows: list[tuple[str, int]] = []
    misc_rows: list[tuple[str, int]] = []

    if aim_scheme is AimScheme.KEYBOARD:
        aim_rows.append(("Torso left:", 7))
        aim_rows.append(("Torso right:", 8))
    elif aim_scheme is AimScheme.DUAL_ACTION_PAD:
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
            ),
        )
    elif move_mode is MovementControlType.RELATIVE:
        move_rows.extend(
            (
                ("Forward:", 0),
                ("Backwards:", 1),
                ("Turn left:", 2),
                ("Turn right:", 3),
            ),
        )
    elif move_mode is MovementControlType.DUAL_ACTION_PAD:
        move_rows.extend(
            (
                ("Up/Down Axis:", 11),
                ("Left/Right Axis:", 12),
            ),
        )
    elif move_mode is MovementControlType.MOUSE_POINT_CLICK:
        move_rows.append(("Move to cursor:", RELOAD_BIND_SLOT))

    if int(player_index) == 0:
        misc_rows.append(("Level Up:", PICK_PERK_BIND_SLOT))
        if move_mode is not MovementControlType.MOUSE_POINT_CLICK:
            misc_rows.append(("Reload:", RELOAD_BIND_SLOT))

    return tuple(aim_rows), tuple(move_rows), tuple(misc_rows)
