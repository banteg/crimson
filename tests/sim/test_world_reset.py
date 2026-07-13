from __future__ import annotations

from crimson.sim.world_state import WorldState
from crimson.world.sim_world_state import reset_world_players


def test_reset_world_players_uses_native_alternating_layout() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    reset_world_players(
        world.players,
        state=world.state,
        world_size=1024.0,
        player_count=2,
    )

    assert world.players[0].pos.x == 512.0
    assert world.players[0].pos.y == 512.0
    assert world.players[1].pos.x == 432.0
    assert world.players[1].pos.y == 432.0
    assert world.players[0].spread_heat == 0.0
    assert world.players[1].spread_heat == 0.0
