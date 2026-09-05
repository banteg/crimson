from __future__ import annotations

from functools import partial

from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import PrimaryStepCtx, SecondarySpawnSpec, SecondaryStepCtx
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import (
    WeaponFireCtx,
    fire_weapon,
    weapon_assign_player,
)
from crimson.weapon_runtime.spawn import projectile_spawn
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.factories import make_creature_state, make_projectile_update_options

_creature = partial(make_creature_state, size=200.0)


def test_shots_fired_and_hit_increment() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    player.spread_heat = 0.0
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    assert state.shots_fired[0] == 1
    assert state.shots_hit[0] == 0

    creature = _creature(pos=Vec2(22.0, 0.0))
    hits = state.projectiles.step(
        PrimaryStepCtx(
            dt=0.1,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=1024.0,
                damage_scale_by_type={},
                rng=state.rng,
                runtime_state=state,
            ),
        ),
    )
    assert hits
    assert state.shots_hit[0] == 1


def test_primary_projectile_hit_on_corpse_does_not_increment_shots_hit() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    player.spread_heat = 0.0
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    corpse = _creature(pos=Vec2(22.0, 0.0), lifecycle_stage=8.0)
    hits = state.projectiles.step(
        PrimaryStepCtx(
            dt=0.1,
            creatures=[corpse],
            options=make_projectile_update_options(
                world_size=1024.0,
                damage_scale_by_type={},
                rng=state.rng,
                runtime_state=state,
            ),
        ),
    )

    assert hits
    assert state.shots_hit[0] == 0


def test_secondary_projectile_direct_hit_increments_shots_hit_for_alive_targets() -> None:
    state = GameplayState()
    state.secondary_projectiles.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.ROCKET,
            owner=OwnerRef.from_local_player(0),
        ),
    )
    creatures = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0, lifecycle_stage=16.0)]

    state.secondary_projectiles.step(
        SecondaryStepCtx(dt=0.1, creatures=creatures, runtime_state=state),
    )

    assert state.shots_hit[0] == 1


def test_secondary_projectile_direct_hit_on_corpse_does_not_increment_shots_hit() -> None:
    state = GameplayState()
    state.secondary_projectiles.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.ROCKET,
            owner=OwnerRef.from_local_player(0),
        ),
    )
    creatures = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0, lifecycle_stage=12.0)]

    state.secondary_projectiles.step(
        SecondaryStepCtx(dt=0.1, creatures=creatures, runtime_state=state),
    )

    assert state.shots_hit[0] == 0


def test_projectile_spawn_increments_shots_fired_for_owner_minus_100_with_owner_index() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())

    projectile_spawn(
        state,
        players=[player0, player1],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        owner_player_index=1,
    )

    assert state.shots_fired[0] == 0
    assert state.shots_fired[1] == 1
    assert state.shots_fired_total == 1


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
        owner=OwnerRef.from_player(1),
    )

    assert state.shots_fired[0] == 0
    assert state.shots_fired[1] == 1
    assert state.shots_fired_total == 1


def test_projectile_spawn_fire_bullets_conversion_increments_shots_fired_twice() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)

    proj_id = projectile_spawn(
        state,
        players=[player],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        owner_player_index=0,
    )

    assert proj_id >= 0
    assert state.shots_fired[0] == 2
    assert state.shots_fired_total == 2
    assert int(state.projectiles.entries[proj_id].type_id) == int(ProjectileTemplateId.FIRE_BULLETS)


def test_projectile_spawn_does_not_increment_shots_fired_when_bonus_guard_is_on() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2())

    projectile_spawn(
        state,
        players=[player],
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        owner_player_index=0,
    )

    assert state.shots_fired[0] == 0
    assert state.shots_fired_total == 0
