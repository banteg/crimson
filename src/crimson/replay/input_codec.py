from __future__ import annotations

from collections.abc import Sequence

from grim.geom import Vec2

from ..math_parity import f32
from ..sim.input import PlayerInput
from .types import (
    FIRE_BULLETS_KEY_DOWN_FLAG,
    PackedPlayerInput,
    PackedTickInputs,
    pack_input_flags,
    unpack_input_flags,
    unpack_input_mode_flags,
    unpack_input_move_key_flags,
)


def _quantize_f32(value: float) -> float:
    return float(f32(float(value)))


def pack_player_input(inp: PlayerInput) -> PackedPlayerInput:
    flags = pack_input_flags(
        fire_down=bool(inp.fire_down),
        fire_pressed=bool(inp.fire_pressed),
        reload_pressed=bool(inp.reload_pressed),
        reload_down=bool(inp.reload_down),
        fire_bullets_key_down=bool(inp.fire_bullets_key_down),
        move_mode=inp.move_mode,
        aim_scheme=inp.aim_scheme,
        move_forward_pressed=inp.move_forward_pressed,
        move_backward_pressed=inp.move_backward_pressed,
        turn_left_pressed=inp.turn_left_pressed,
        turn_right_pressed=inp.turn_right_pressed,
    )
    return (
        _quantize_f32(inp.move.x),
        _quantize_f32(inp.move.y),
        _quantize_f32(inp.aim.x),
        _quantize_f32(inp.aim.y),
        int(flags),
    )


def unpack_player_input(packed: PackedPlayerInput) -> PlayerInput:
    mx, my, ax, ay, flags = packed
    fire_down, fire_pressed, reload_pressed, reload_down = unpack_input_flags(flags)
    move_mode, aim_scheme = unpack_input_mode_flags(flags)
    move_forward_pressed, move_backward_pressed, turn_left_pressed, turn_right_pressed = unpack_input_move_key_flags(
        flags,
    )
    return PlayerInput(
        move=Vec2(float(mx), float(my)),
        aim=Vec2(float(ax), float(ay)),
        move_mode=move_mode,
        aim_scheme=aim_scheme,
        fire_down=fire_down,
        fire_pressed=fire_pressed,
        reload_pressed=reload_pressed,
        reload_down=reload_down,
        fire_bullets_key_down=bool(flags & FIRE_BULLETS_KEY_DOWN_FLAG),
        move_forward_pressed=move_forward_pressed,
        move_backward_pressed=move_backward_pressed,
        turn_left_pressed=turn_left_pressed,
        turn_right_pressed=turn_right_pressed,
    )


def unpack_tick_inputs(packed_tick: PackedTickInputs) -> list[PlayerInput]:
    return [unpack_player_input(packed) for packed in packed_tick]


def pack_tick_inputs(inputs: Sequence[PlayerInput]) -> PackedTickInputs:
    return [pack_player_input(inp) for inp in inputs]
