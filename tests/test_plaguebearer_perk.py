from __future__ import annotations

import math

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags, CreatureInfectionFlags
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId


def test_plaguebearer_infects_weak_creatures_near_player() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0)
    player.plaguebearer_active = True

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = 120.0
    creature.y = 100.0
    creature.hp = 100.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE

    pool.update(0.016, state=state, players=[player])

    assert creature.collision_flag == CreatureInfectionFlags.INFECTED


def test_plaguebearer_infection_tick_deals_damage_on_timer_wrap() -> None:
    dt = 0.2
    state = GameplayState()
    player = PlayerState(index=0, pos_x=500.0, pos_y=500.0)

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.collision_flag = CreatureInfectionFlags.INFECTED
    creature.collision_timer = 0.1
    creature.x = 100.0
    creature.y = 100.0
    creature.hp = 100.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE

    pool.update(dt, state=state, players=[player])

    assert math.isclose(creature.collision_timer, 0.4, abs_tol=1e-9)
    assert math.isclose(creature.hp, 85.0, abs_tol=1e-9)


def test_plaguebearer_spreads_between_nearby_creatures() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=500.0, pos_y=500.0)
    player.perk_counts[int(PerkId.PLAGUEBEARER)] = 1

    pool = CreaturePool()
    infected = pool.entries[0]
    infected.active = True
    infected.flags = CreatureFlags.ANIM_PING_PONG
    infected.collision_flag = CreatureInfectionFlags.INFECTED
    infected.x = 100.0
    infected.y = 100.0
    infected.hp = 100.0
    infected.hitbox_size = CREATURE_HITBOX_ALIVE

    other = pool.entries[1]
    other.active = True
    other.flags = CreatureFlags.ANIM_PING_PONG
    other.collision_flag = CreatureInfectionFlags(0)
    other.x = 130.0
    other.y = 100.0
    other.hp = 100.0
    other.hitbox_size = CREATURE_HITBOX_ALIVE

    pool.update(0.016, state=state, players=[player])

    assert other.collision_flag == CreatureInfectionFlags.INFECTED


def test_plaguebearer_infection_kill_increments_global_count() -> None:
    dt = 0.2
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos_x=500.0, pos_y=500.0)

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.collision_flag = CreatureInfectionFlags.INFECTED
    creature.collision_timer = 0.1
    creature.x = 100.0
    creature.y = 100.0
    creature.hp = 10.0
    creature.reward_value = 10.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE

    result = pool.update(dt, state=state, players=[player])

    assert state.plaguebearer_infection_count == 1
    assert len(result.deaths) == 1
