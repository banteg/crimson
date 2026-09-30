from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import kill_creature, world_with_creature


def test_creature_handle_death_doubles_xp_when_double_xp_bonus_active() -> None:
    player = PlayerState(index=0, pos=Vec2(), experience=100)
    world = world_with_creature(CreatureState(active=True, hp=10.0, reward_value=12.7), players=[player])
    world.state.bonus_spawn_guard = True
    world.state.bonuses.double_experience = 5.0

    death = kill_creature(world)

    assert death.xp_awarded == 24  # 2 * int(12.7)
    assert player.experience == 124
