from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import make_creature_update_options


def test_veins_of_poison_sets_self_damage_flag_on_contact_hit() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.VEINS_OF_POISON)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK


def test_veins_of_poison_skips_when_player_shielded() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), shield_timer=1.0)
    player.perk_counts[int(PerkId.VEINS_OF_POISON)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.contact_damage = 10.0
    creature.collision_timer = 0.1

    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
