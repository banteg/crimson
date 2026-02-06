from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId


def test_radioactive_tick_deals_damage_and_spawns_fx() -> None:
    dt = 0.2
    state = GameplayState()

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = 46.0
    creature.y = 0.0
    creature.hp = 50.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)

    pool.update(dt, state=state, players=[player], rand=lambda: 0, fx_queue=fx_queue)

    expected_damage = (100.0 - 46.0) * 0.3
    assert math.isclose(creature.collision_timer, 0.5, abs_tol=1e-9)
    assert math.isclose(creature.hp, 50.0 - expected_damage, abs_tol=1e-6)
    assert fx_queue.count == 1


def test_radioactive_kill_awards_base_xp_and_bypasses_death_multipliers() -> None:
    dt = 0.2
    state = GameplayState()
    state.bonuses.double_experience = 5.0

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), experience=100)
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1
    player.perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = 46.0
    creature.y = 0.0
    creature.hp = 10.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.reward_value = 12.7
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)
    result = pool.update(dt, state=state, players=[player], rand=lambda: 0, fx_queue=fx_queue)

    assert player.experience == 112
    assert not result.deaths
    assert creature.hp < 0.0
    assert math.isclose(creature.hitbox_size, CREATURE_HITBOX_ALIVE - dt, abs_tol=1e-9)
    assert fx_queue.count == 1


def test_radioactive_sets_hp_to_one_for_type_id_one_creatures() -> None:
    dt = 0.2
    state = GameplayState()

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), experience=100)
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.type_id = 1
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = 46.0
    creature.y = 0.0
    creature.hp = 10.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.reward_value = 12.7
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)
    result = pool.update(dt, state=state, players=[player], rand=lambda: 0, fx_queue=fx_queue)

    assert player.experience == 100
    assert not result.deaths
    assert math.isclose(creature.hp, 1.0, abs_tol=1e-9)
    assert math.isclose(creature.hitbox_size, CREATURE_HITBOX_ALIVE, abs_tol=1e-9)
    assert math.isclose(creature.collision_timer, 0.5, abs_tol=1e-9)
    assert fx_queue.count == 1
