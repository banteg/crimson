from __future__ import annotations

import struct
from collections.abc import Sequence

from grim.geom import Vec2

from ..sim.input import PlayerInput
from .types import (
    InputQuantization,
    PackedPlayerInput,
    PackedTickInputs,
    pack_input_flags,
    unpack_input_flags,
    unpack_input_mode_flags,
    unpack_input_move_key_flags,
    unpack_packed_player_input,
)


def _quantize_f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def pack_player_input(inp: PlayerInput, *, quant: InputQuantization = "raw") -> PackedPlayerInput:
    mx = float(inp.move.x)
    my = float(inp.move.y)
    ax = float(inp.aim.x)
    ay = float(inp.aim.y)
    if str(quant) == "f32":
        mx = _quantize_f32(mx)
        my = _quantize_f32(my)
        ax = _quantize_f32(ax)
        ay = _quantize_f32(ay)
    flags = pack_input_flags(
        fire_down=bool(inp.fire_down),
        fire_pressed=bool(inp.fire_pressed),
        reload_pressed=bool(inp.reload_pressed),
        move_mode=inp.move_mode,
        aim_scheme=inp.aim_scheme,
        move_forward_pressed=inp.move_forward_pressed,
        move_backward_pressed=inp.move_backward_pressed,
        turn_left_pressed=inp.turn_left_pressed,
        turn_right_pressed=inp.turn_right_pressed,
    )
    return [mx, my, [ax, ay], int(flags)]


def unpack_player_input(packed: PackedPlayerInput) -> PlayerInput:
    mx, my, ax, ay, flags = unpack_packed_player_input(packed)
    fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
    move_mode, aim_scheme = unpack_input_mode_flags(int(flags))
    move_forward_pressed, move_backward_pressed, turn_left_pressed, turn_right_pressed = unpack_input_move_key_flags(
        int(flags),
    )
    return PlayerInput(
        move=Vec2(float(mx), float(my)),
        aim=Vec2(float(ax), float(ay)),
        move_mode=move_mode,
        aim_scheme=aim_scheme,
        fire_down=bool(fire_down),
        fire_pressed=bool(fire_pressed),
        reload_pressed=bool(reload_pressed),
        move_forward_pressed=move_forward_pressed,
        move_backward_pressed=move_backward_pressed,
        turn_left_pressed=turn_left_pressed,
        turn_right_pressed=turn_right_pressed,
    )


def unpack_tick_inputs(packed_tick: PackedTickInputs) -> list[PlayerInput]:
    return [unpack_player_input(packed) for packed in packed_tick]


def pack_tick_inputs(
    inputs: Sequence[PlayerInput],
    *,
    quant: InputQuantization = "raw",
) -> PackedTickInputs:
    return [pack_player_input(inp, quant=quant) for inp in inputs]
