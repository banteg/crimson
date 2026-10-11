from __future__ import annotations

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.screens.panels.controls_labels import (
    RebindRowSpec,
    RebindTarget,
    controls_aim_method_dropdown_ids,
    controls_rebind_plan,
)


def _slots(rows: tuple[RebindRowSpec, ...]) -> list[tuple[RebindTarget, int | None, bool]]:
    return [(row.target, row.target_index, row.axis) for row in rows]


def test_controls_aim_method_dropdown_ids_hides_computer_unless_loaded() -> None:
    assert controls_aim_method_dropdown_ids(AimScheme.MOUSE) == (
        AimScheme.MOUSE,
        AimScheme.KEYBOARD,
        AimScheme.JOYSTICK,
        AimScheme.MOUSE_RELATIVE,
        AimScheme.DUAL_ACTION_PAD,
    )
    assert controls_aim_method_dropdown_ids(AimScheme.COMPUTER) == (
        AimScheme.MOUSE,
        AimScheme.KEYBOARD,
        AimScheme.JOYSTICK,
        AimScheme.MOUSE_RELATIVE,
        AimScheme.DUAL_ACTION_PAD,
        AimScheme.COMPUTER,
    )


def test_controls_rebind_plan_keyboard_static_player1() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_plan(
        aim_scheme=AimScheme.KEYBOARD,
        move_mode=MovementControlType.STATIC,
        player_index=0,
    )
    assert _slots(aim_rows) == [
        (RebindTarget.PLAYER_KEYBOARD_AIM_CODES, 0, False),
        (RebindTarget.PLAYER_KEYBOARD_AIM_CODES, 1, False),
        (RebindTarget.PLAYER_FIRE_CODE, None, False),
    ]
    assert _slots(move_rows) == [(RebindTarget.PLAYER_MOVE_CODES, index, False) for index in range(4)]
    assert _slots(misc_rows) == [
        (RebindTarget.GLOBAL_PICK_PERK_CODE, None, False),
        (RebindTarget.GLOBAL_RELOAD_CODE, None, False),
    ]


def test_controls_rebind_plan_dualpad_mouse_cursor_player2() -> None:
    aim_rows, move_rows, misc_rows = controls_rebind_plan(
        aim_scheme=AimScheme.DUAL_ACTION_PAD,
        move_mode=MovementControlType.MOUSE_POINT_CLICK,
        player_index=1,
    )
    assert _slots(aim_rows) == [
        (RebindTarget.PLAYER_AIM_AXIS_CODES, 0, True),
        (RebindTarget.PLAYER_AIM_AXIS_CODES, 1, True),
        (RebindTarget.PLAYER_FIRE_CODE, None, False),
    ]
    assert _slots(move_rows) == [(RebindTarget.GLOBAL_RELOAD_CODE, None, False)]
    assert misc_rows == ()
