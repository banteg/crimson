from __future__ import annotations

from collections.abc import Sequence

from ..sim.input import PlayerInput
from ..sim.world_state import WorldState


def _move_key_held(inp: PlayerInput) -> bool:
    return inp.move_forward_down or inp.move_backward_down or inp.turn_left_down or inp.turn_right_down


def tutorial_input_transform(world: WorldState, inputs: Sequence[PlayerInput]) -> Sequence[PlayerInput]:
    # `tutorial_timeline_update` polls players 0 and 1 whatever their movement scheme:
    # stage 1 any of the four move keys (0x00408d6b), stage 3 the fire key (0x00408f76).
    tutorial = world.state.tutorial
    tutorial.move_active_this_tick = any(_move_key_held(inp) for inp in inputs[:2])
    tutorial.fire_active_this_tick = any(inp.fire_pressed or inp.fire_down for inp in inputs[:2])
    return inputs
