from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import make_creature_update_options
from tests.support.helpers import assert_float_close


def test_plaguebearer_apply_sets_active_flag_for_all_players() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2())
    other = PlayerState(index=1, pos=Vec2())

    perk_apply(state, [owner, other], PerkId.PLAGUEBEARER)

    assert owner.plaguebearer_active
    assert other.plaguebearer_active


def test_plaguebearer_infects_weak_creatures_near_player() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.plaguebearer_active = True

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(120.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    pool.update(0.016, options=make_creature_update_options(state=state, players=[player]))

    assert creature.plague_infected


def test_plaguebearer_infection_tick_deals_damage_on_timer_wrap() -> None:
    dt = 0.2
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.plague_infected = True
    creature.collision_timer = 0.1
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    pool.update(dt, options=make_creature_update_options(state=state, players=[player]))

    expected_timer = 0.1 - float(f32(float(dt))) + 0.5
    assert_float_close(creature.collision_timer, expected_timer)
    assert_float_close(creature.hp, 85.0)


def test_plaguebearer_spreads_between_nearby_creatures() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0))
    player.perk_counts[int(PerkId.PLAGUEBEARER)] = 1

    pool = CreaturePool()
    infected = pool.entries[0]
    infected.active = True
    infected.flags = CreatureFlags.ANIM_PING_PONG
    infected.plague_infected = True
    infected.pos = Vec2(100.0, 100.0)
    infected.hp = 100.0
    infected.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    other = pool.entries[1]
    other.active = True
    other.flags = CreatureFlags.ANIM_PING_PONG
    other.plague_infected = False
    other.pos = Vec2(130.0, 100.0)
    other.hp = 100.0
    other.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    pool.update(0.016, options=make_creature_update_options(state=state, players=[player]))

    assert other.plague_infected


def test_plaguebearer_spread_rejects_distance_rounded_to_native_radius() -> None:
    pool = CreaturePool(size=2)
    target = pool.entries[0]
    target.active = True
    target.pos = Vec2(14.757906913757324, -42.51122283935547)
    target.hp = 100.0

    origin = pool.entries[1]
    origin.active = True
    origin.plague_infected = True
    origin.pos = Vec2()
    origin.hp = 100.0

    pool._plaguebearer_spread_infection(1)

    assert not target.plague_infected


def test_plaguebearer_infection_kill_increments_global_count() -> None:
    dt = 0.2
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.plague_infected = True
    creature.collision_timer = 0.1
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.reward_value = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    result = pool.update(dt, options=make_creature_update_options(state=state, players=[player]))

    assert state.plaguebearer_infection_count == 1
    assert len(result.deaths) == 1


def test_plaguebearer_infection_kill_does_not_apply_immediate_dead_decay() -> None:
    dt = 0.063
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags(0)
    creature.plague_infected = True
    creature.collision_timer = 0.01
    creature.pos = Vec2(120.0, 370.0)
    creature.hp = 10.0
    creature.reward_value = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE

    result = pool.update(dt, options=make_creature_update_options(state=state, players=[player]))

    assert len(result.deaths) == 1
    # Native plague timer kills call creature_handle_death, then continue the
    # live branch without an immediate `_tick_dead` pass.
    assert creature.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE - float(f32(float(dt)))
