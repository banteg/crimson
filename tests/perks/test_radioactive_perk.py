from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE
from crimson.creatures.spawn import CreatureFlags
from crimson.perks import PerkId
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures


def test_radioactive_pulse_measures_distance_to_target_player() -> None:
    dt = 0.2
    world = make_world(player_count=2)
    state = world.state
    state.rng = Crand(0x1234)

    # The creature targets player slot one and is only in range of that selected target.
    player1, player2 = world.players
    player1.pos = Vec2(900.0, 900.0)
    state.perks[int(PerkId.RADIOACTIVE)] = 1
    player2.pos = Vec2()

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 50.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.dot_tick_timer = 0.1
    creature.target_player = 1

    step_creatures(world, dt)

    assert creature.hp < 50.0
    # Kill XP is credited to player 1 (native writes the global _player_experience).
    assert player2.experience == 0
