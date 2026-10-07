from __future__ import annotations

import pytest

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_sub
from crimson.perks import PerkId
from crimson.perks.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures
from tests.support.helpers import assert_float_close


def test_plaguebearer_apply_sets_active_flag_for_all_players() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2())
    other = PlayerState(index=1, pos=Vec2())

    perk_apply(state, [owner, other], PerkId.PLAGUEBEARER)

    assert owner.plaguebearer_active
    assert other.plaguebearer_active


def test_plaguebearer_preserve_bugs_sets_only_player_zero_active() -> None:
    state = GameplayState()
    state.preserve_bugs = True
    owner = PlayerState(index=0, pos=Vec2())
    other = PlayerState(index=1, pos=Vec2())

    perk_apply(state, [owner, other], PerkId.PLAGUEBEARER)

    assert owner.plaguebearer_active
    assert not other.plaguebearer_active


def test_plaguebearer_infects_weak_creatures_near_player() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.plaguebearer_active = True

    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.pos = Vec2(120.0, 100.0)
    creature.hp = 100.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE

    step_creatures(world, 0.016)

    assert creature.plague_infected


def test_plaguebearer_infection_tick_deals_damage_on_timer_wrap() -> None:
    dt = 0.2
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(500.0, 500.0)

    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.plague_infected = True
    creature.dot_tick_timer = 0.1
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE

    step_creatures(world, dt)

    expected_timer = x87_pc24_add(
        x87_pc24_sub(f32(0.1), float(dt)),
        f32(0.5),
    )
    assert_float_close(creature.dot_tick_timer, expected_timer)
    assert_float_close(creature.hp, 85.0)


def test_plaguebearer_spreads_between_nearby_creatures() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(500.0, 500.0)
    state.perks[int(PerkId.PLAGUEBEARER)] = 1

    pool = world.creatures
    infected = pool.entries[0]
    infected.active = True
    infected.flags = CreatureFlags.SPAWNER
    infected.plague_infected = True
    infected.pos = Vec2(100.0, 100.0)
    infected.hp = 100.0
    infected.death_timer = CREATURE_LIFECYCLE_ALIVE

    other = pool.entries[1]
    other.active = True
    other.flags = CreatureFlags.SPAWNER
    other.plague_infected = False
    other.pos = Vec2(130.0, 100.0)
    other.hp = 100.0
    other.death_timer = CREATURE_LIFECYCLE_ALIVE

    step_creatures(world, 0.016)

    assert other.plague_infected


def test_plaguebearer_spread_rejects_distance_rounded_to_native_radius() -> None:
    pool = CreaturePool()
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


@pytest.mark.parametrize("axis", [0, 1])
@pytest.mark.parametrize("sign", [-1.0, 1.0])
@pytest.mark.parametrize(
    ("distance", "infected"),
    [(44.999996185302734, True), (45.0, False), (45.000003814697266, False)],
)
def test_plaguebearer_spread_axis_radius_boundary(axis: int, sign: float, distance: float, infected: bool) -> None:
    pool = CreaturePool()
    target, origin = pool.entries[:2]
    target.active = origin.active = True
    target.hp = origin.hp = 100.0
    origin.plague_infected = True
    target.pos = Vec2(sign * distance, 0.0) if axis == 0 else Vec2(0.0, sign * distance)

    pool._plaguebearer_spread_infection(1)

    assert target.plague_infected is infected


def test_plaguebearer_spread_self_stops_before_later_neighbors() -> None:
    pool = CreaturePool()
    origin, target = pool.entries[:2]
    origin.active = target.active = True
    origin.hp = target.hp = 100.0
    origin.plague_infected = True
    target.pos = Vec2(10.0, 0.0)

    pool._plaguebearer_spread_infection(0)

    assert not target.plague_infected


@pytest.mark.parametrize(
    ("health", "infected"),
    [(149.99998474121094, True), (150.0, False), (150.00001525878906, False)],
)
def test_plaguebearer_spread_infection_health_boundary(health: float, infected: bool) -> None:
    pool = CreaturePool()
    source, origin = pool.entries[:2]
    source.active = origin.active = True
    source.plague_infected = True
    source.pos = Vec2(10.0, 0.0)
    source.hp = 100.0
    origin.hp = health

    pool._plaguebearer_spread_infection(1)

    assert origin.plague_infected is infected


def test_plaguebearer_spread_strong_infected_origin_can_infect_weak_neighbor() -> None:
    pool = CreaturePool()
    target, origin = pool.entries[:2]
    target.active = origin.active = True
    target.pos = Vec2(10.0, 0.0)
    target.hp = 100.0
    origin.hp = 500.0
    origin.plague_infected = True

    pool._plaguebearer_spread_infection(1)

    assert target.plague_infected


def test_plaguebearer_spread_first_neighbor_blocks_later_infected_neighbor() -> None:
    pool = CreaturePool()
    first, infected, origin = pool.entries[:3]
    for creature in (first, infected, origin):
        creature.active = True
        creature.hp = 100.0
    first.pos = Vec2(20.0, 0.0)
    infected.pos = Vec2(10.0, 0.0)
    infected.plague_infected = True

    pool._plaguebearer_spread_infection(2)

    assert not origin.plague_infected


def test_plaguebearer_spread_includes_active_corpses_and_current_positions() -> None:
    pool = CreaturePool()
    corpse, origin = pool.entries[:2]
    corpse.active = origin.active = True
    corpse.hp = origin.hp = 100.0
    corpse.death_timer = -1.0
    corpse.plague_infected = True
    corpse.pos = Vec2(45.0, 0.0)

    pool._plaguebearer_spread_infection(1)
    assert not origin.plague_infected

    corpse.pos = Vec2(44.999996185302734, 0.0)
    pool._plaguebearer_spread_infection(1)
    assert origin.plague_infected


def test_plaguebearer_infection_kill_increments_global_count() -> None:
    dt = 0.2
    world = make_world()
    state = world.state
    state.scripted_burst_active = True
    player = world.players[0]
    player.pos = Vec2(500.0, 500.0)

    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.plague_infected = True
    creature.dot_tick_timer = 0.1
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.reward_value = 10.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE

    step_runtime = step_creatures(world, dt)

    assert state.plaguebearer_infection_count == 1
    assert len(step_runtime.deaths) == 1


def test_plaguebearer_infection_kill_does_not_apply_immediate_dead_decay() -> None:
    dt = 0.063
    world = make_world()
    state = world.state
    state.scripted_burst_active = True
    player = world.players[0]
    player.pos = Vec2(500.0, 500.0)

    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags(0)
    creature.plague_infected = True
    creature.dot_tick_timer = 0.01
    creature.pos = Vec2(120.0, 370.0)
    creature.hp = 10.0
    creature.reward_value = 10.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE

    step_runtime = step_creatures(world, dt)

    assert len(step_runtime.deaths) == 1
    # Native plague timer kills call creature_handle_death, then continue the
    # live branch without an immediate `_tick_dead` pass.
    assert creature.death_timer == x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, f32(float(dt)))


def test_plaguebearer_kill_finishes_contact_and_small_creature_tail() -> None:
    dt = f32(0.063)
    world = make_world()
    state = world.state
    state.scripted_burst_active = True
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.health = 100.0

    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.plague_infected = True
    creature.dot_tick_timer = 0.01
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10.0
    creature.max_hp = 10.0
    creature.size = 20.0
    creature.move_speed = 0.0
    creature.contact_damage = 7.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE

    step_runtime = step_creatures(world, dt)

    assert len(step_runtime.deaths) == 1
    assert_float_close(player.health, 93.0)
    assert creature.hp == 0.0
    expected_lifecycle = x87_pc24_sub(
        x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, dt),
        dt,
    )
    assert_float_close(creature.death_timer, expected_lifecycle)
