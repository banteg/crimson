from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE
from crimson.creatures.spawn import CreatureFlags
from crimson.perks import PerkId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures


def test_veins_of_poison_sets_self_damage_flag_on_contact_hit() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    world.state.perks[int(PerkId.VEINS_OF_POISON)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.dot_tick_timer = 0.1

    step_creatures(world, 0.2)

    assert creature.flags & CreatureFlags.POISONED


def test_veins_of_poison_skips_when_player_shielded() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.shield_timer = 1.0
    world.state.perks[int(PerkId.VEINS_OF_POISON)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.dot_tick_timer = 0.1

    step_creatures(world, 0.2)

    assert not (creature.flags & CreatureFlags.POISONED)
