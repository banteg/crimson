from __future__ import annotations

from collections.abc import Sequence

from ..sim.input import PlayerInput
from ..sim.world_state import WorldState


def tutorial_input_transform(world: WorldState, inputs: Sequence[PlayerInput]) -> Sequence[PlayerInput]:
    tutorial = world.state.tutorial
    if inputs:
        primary = inputs[0]
        tutorial.move_active_this_tick = primary.move.length_sq() > 0.0
        tutorial.fire_active_this_tick = bool(primary.fire_pressed or primary.fire_down)
    else:
        tutorial.move_active_this_tick = False
        tutorial.fire_active_this_tick = False
    return inputs
