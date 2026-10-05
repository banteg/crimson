from __future__ import annotations

from functools import partial

from crimson.creatures.runtime import CreatureState
from crimson.owner_id import OWNER_LOCAL_PLAYER, player_owner_id
from crimson.projectiles.runtime import fx_spawn_secondary_projectile, projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import (
    fire_player_weapon,
    make_creature_state,
    make_step_runtime,
    place_creatures,
    player_input,
)

_creature = partial(make_creature_state, size=200.0)


def _fire_pistol_right() -> WorldState:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2()
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    player.spread_heat = 0.0
    player.aim_dir = Vec2(1.0, 0.0)

    fire_player_weapon(world, player, player_input(fire_down=True, aim=Vec2(200.0, 0.0)), 0.016)
    return world


def _step_rocket_into(creature: CreatureState) -> GameplayState:
    world = make_world()
    state = world.state
    place_creatures(world, [creature])
    fx_spawn_secondary_projectile(
        state, world.players[0], world.creatures.entries, pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.ROCKET,
    )

    state.secondary_projectiles.step(
        make_step_runtime(world, dt=0.1),
    )
    return state


def test_shots_fired_and_hit_increment() -> None:
    world = _fire_pistol_right()
    state = world.state

    assert state.shots_fired == 1
    assert state.shots_hit == 0

    place_creatures(world, [_creature(pos=Vec2(22.0, 0.0), hp=1000.0)])
    hits = state.projectiles.step(
        make_step_runtime(world, dt=0.1),
    )
    assert hits
    assert state.shots_hit == 1


def test_primary_projectile_hit_on_corpse_does_not_increment_shots_hit() -> None:
    world = _fire_pistol_right()
    state = world.state

    place_creatures(world, [_creature(pos=Vec2(22.0, 0.0), hp=1000.0, death_timer=8.0)])
    hits = state.projectiles.step(
        make_step_runtime(world, dt=0.1),
    )

    assert hits
    assert state.shots_hit == 0


def test_secondary_projectile_direct_hit_increments_shots_hit_for_alive_targets() -> None:
    state = _step_rocket_into(_creature(pos=Vec2(0.0, -9.0), hp=1000.0, death_timer=16.0))

    assert state.shots_hit == 1


def test_secondary_projectile_direct_hit_on_corpse_does_not_increment_shots_hit() -> None:
    state = _step_rocket_into(_creature(pos=Vec2(0.0, -9.0), hp=1000.0, death_timer=12.0))

    assert state.shots_hit == 0


def test_projectile_spawn_increments_shots_fired_for_owner_minus_100() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())

    projectile_spawn(
        state,
        players=[player0, player1],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=OWNER_LOCAL_PLAYER,
        owner_player_index=1,
    )

    assert state.shots_fired == 1


def test_projectile_spawn_increments_shots_fired_for_owner_minus_2() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())

    projectile_spawn(
        state,
        players=[player0, player1],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=player_owner_id(1),
        owner_player_index=1,
    )

    assert state.shots_fired == 1


def test_projectile_spawn_fire_bullets_conversion_increments_shots_fired_twice() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)

    proj_id = projectile_spawn(
        state,
        players=[player],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=OWNER_LOCAL_PLAYER,
        owner_player_index=0,
    )

    assert proj_id >= 0
    assert state.shots_fired == 2
    assert int(state.projectiles.entries[proj_id].type_id) == int(ProjectileTemplateId.FIRE_BULLETS)


def test_projectile_spawn_does_not_increment_shots_fired_when_bonus_guard_is_on() -> None:
    state = GameplayState()
    state.scripted_burst_active = True
    player = PlayerState(index=0, pos=Vec2())

    projectile_spawn(
        state,
        players=[player],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=OWNER_LOCAL_PLAYER,
        owner_player_index=0,
    )

    assert state.shots_fired == 0
