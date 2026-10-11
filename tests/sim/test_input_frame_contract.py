from __future__ import annotations

from crimson.effects import FxQueue, FxQueueRotated
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.factories import player_input


def test_world_step_applies_per_player_inputs_by_index() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(300.0, 300.0)))
    world.players.append(PlayerState(index=1, pos=Vec2(700.0, 300.0)))

    before = [(player.pos.x, player.pos.y) for player in world.players]

    world.step(
        0.2,
        inputs=[
            player_input(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 300.0)),
            player_input(move=Vec2(-1.0, 0.0), aim=Vec2(400.0, 300.0)),
        ],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert world.players[0].pos.x > before[0][0]
    assert world.players[1].pos.x < before[1][0]
