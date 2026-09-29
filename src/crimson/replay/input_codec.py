from __future__ import annotations

from collections.abc import Sequence

from grim.geom import Vec2

from ..aim_schemes import aim_scheme_from_value
from ..math_parity import f32
from ..movement_controls import movement_control_type_from_value
from ..sim.commands import GameCommand
from ..sim.input import PlayerInput
from .types import (
    AIM_SCHEME_MASK,
    AIM_SCHEME_PRESENT_FLAG,
    AIM_SCHEME_SHIFT,
    AIM_TURN_LEFT_FLAG,
    AIM_TURN_RIGHT_FLAG,
    FIRE_BULLETS_KEY_DOWN_FLAG,
    FIRE_DOWN_FLAG,
    FIRE_PRESSED_FLAG,
    MOVE_BACKWARD_FLAG,
    MOVE_FORWARD_FLAG,
    MOVE_KEYS_PRESENT_FLAG,
    MOVE_MODE_MASK,
    MOVE_MODE_PRESENT_FLAG,
    MOVE_MODE_SHIFT,
    RELOAD_DOWN_FLAG,
    RELOAD_PRESSED_FLAG,
    TURN_LEFT_FLAG,
    TURN_RIGHT_FLAG,
    PackedPlayerInput,
    PackedTickInputs,
    ReplayTick,
)


def pack_player_input(inp: PlayerInput) -> PackedPlayerInput:
    flags = (
        (FIRE_DOWN_FLAG if inp.fire_down else 0)
        | (FIRE_PRESSED_FLAG if inp.fire_pressed else 0)
        | (RELOAD_PRESSED_FLAG if inp.reload_pressed else 0)
        | (RELOAD_DOWN_FLAG if inp.reload_down else 0)
        | (FIRE_BULLETS_KEY_DOWN_FLAG if inp.fire_bullets_key_down else 0)
        | (AIM_TURN_LEFT_FLAG if inp.aim_turn_left else 0)
        | (AIM_TURN_RIGHT_FLAG if inp.aim_turn_right else 0)
    )
    # Raw movement keys are recorded only when the input carries them.
    move_keys = (inp.move_forward_pressed, inp.move_backward_pressed, inp.turn_left_pressed, inp.turn_right_pressed)
    if any(key is not None for key in move_keys):
        flags |= (
            MOVE_KEYS_PRESENT_FLAG
            | (MOVE_FORWARD_FLAG if inp.move_forward_pressed else 0)
            | (MOVE_BACKWARD_FLAG if inp.move_backward_pressed else 0)
            | (TURN_LEFT_FLAG if inp.turn_left_pressed else 0)
            | (TURN_RIGHT_FLAG if inp.turn_right_pressed else 0)
        )
    if inp.move_mode is not None:
        flags |= MOVE_MODE_PRESENT_FLAG | (int(inp.move_mode) & MOVE_MODE_MASK) << MOVE_MODE_SHIFT
    if inp.aim_scheme is not None:
        flags |= AIM_SCHEME_PRESENT_FLAG | (int(inp.aim_scheme) & AIM_SCHEME_MASK) << AIM_SCHEME_SHIFT
    return (f32(inp.move.x), f32(inp.move.y), f32(inp.aim.x), f32(inp.aim.y), flags)


def unpack_player_input(packed: PackedPlayerInput) -> PlayerInput:
    mx, my, ax, ay, flags = packed
    move_mode = None
    if flags & MOVE_MODE_PRESENT_FLAG:
        move_mode = movement_control_type_from_value((flags >> MOVE_MODE_SHIFT) & MOVE_MODE_MASK)
    aim_scheme = None
    if flags & AIM_SCHEME_PRESENT_FLAG:
        aim_scheme_raw = (flags >> AIM_SCHEME_SHIFT) & AIM_SCHEME_MASK
        # The 3-bit field stores the -1 scheme as all ones.
        aim_scheme = aim_scheme_from_value(-1 if aim_scheme_raw == AIM_SCHEME_MASK else aim_scheme_raw)
    move_keys = bool(flags & MOVE_KEYS_PRESENT_FLAG)
    return PlayerInput(
        move=Vec2(float(mx), float(my)),
        aim=Vec2(float(ax), float(ay)),
        move_mode=move_mode,
        aim_scheme=aim_scheme,
        fire_down=bool(flags & FIRE_DOWN_FLAG),
        fire_pressed=bool(flags & FIRE_PRESSED_FLAG),
        reload_pressed=bool(flags & RELOAD_PRESSED_FLAG),
        reload_down=bool(flags & RELOAD_DOWN_FLAG),
        fire_bullets_key_down=bool(flags & FIRE_BULLETS_KEY_DOWN_FLAG),
        aim_turn_left=bool(flags & AIM_TURN_LEFT_FLAG),
        aim_turn_right=bool(flags & AIM_TURN_RIGHT_FLAG),
        move_forward_pressed=bool(flags & MOVE_FORWARD_FLAG) if move_keys else None,
        move_backward_pressed=bool(flags & MOVE_BACKWARD_FLAG) if move_keys else None,
        turn_left_pressed=bool(flags & TURN_LEFT_FLAG) if move_keys else None,
        turn_right_pressed=bool(flags & TURN_RIGHT_FLAG) if move_keys else None,
    )


def unpack_tick_inputs(packed_tick: PackedTickInputs) -> list[PlayerInput]:
    return [unpack_player_input(packed) for packed in packed_tick]


def pack_tick_inputs(inputs: Sequence[PlayerInput]) -> PackedTickInputs:
    return [pack_player_input(inp) for inp in inputs]


def pack_tick(inputs: Sequence[PlayerInput], commands: Sequence[GameCommand] = ()) -> ReplayTick:
    """The tick exactly as a replay stores it: f32 axes and only the recorded flags."""

    return ReplayTick(inputs=pack_tick_inputs(inputs), commands=list(commands))
