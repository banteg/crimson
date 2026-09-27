from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE
from crimson.perks import PerkId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures
from tests.support.helpers import assert_float_close


def test_mr_melee_hits_attacking_creature_on_contact_damage_tick() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    world.state.perks[int(PerkId.MR_MELEE)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    step_creatures(world, 0.2)

    assert_float_close(creature.hp, 75.0)


def test_mr_melee_does_not_prevent_player_damage_when_killing_attacker() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.health = 100.0
    player.plaguebearer_active = True
    world.state.perks[int(PerkId.MR_MELEE)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    step_creatures(world, 0.2)

    assert_float_close(player.health, 90.0)
    assert creature.plague_infected
    # The live interaction tail finishes without an in-frame dt * 28 corpse step.
    assert creature.lifecycle_stage > CREATURE_LIFECYCLE_ALIVE - 1.0


def test_mr_melee_is_inert_when_not_active() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    step_creatures(world, 0.2)

    assert_float_close(creature.hp, 100.0)
