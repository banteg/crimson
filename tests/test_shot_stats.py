from __future__ import annotations

from dataclasses import dataclass

from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import GameplayState
from crimson.projectiles import ProjectileTypeId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import (
    player_fire_weapon,
    weapon_assign_player,
)
from crimson.weapon_runtime.spawn import projectile_spawn
from grim.geom import Vec2


@dataclass(slots=True)
class _DummyCreature:
    pos: Vec2
    hp: float = 100.0
    size: float = 200.0
    active: bool = True
    hitbox_size: float = 16.0
    flags: CreatureFlags = CreatureFlags(0)
    plague_infected: bool = False


def test_shots_fired_and_hit_increment() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, 1)
    player.spread_heat = 0.0
    player.aim_dir = Vec2(1.0, 0.0)

    player_fire_weapon(
        player,
        PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
        dt=0.016,
        state=state,
    )

    assert state.shots_fired[0] == 1
    assert state.shots_hit[0] == 0

    creature = _DummyCreature(pos=Vec2(22.0, 0.0))
    hits = state.projectiles.update(
        0.1,
        [creature],
        world_size=1024.0,
        damage_scale_by_type={},
        rng=state.rng.rand,
        runtime_state=state,
    )
    assert hits
    assert state.shots_hit[0] == 1


def test_projectile_spawn_increments_shots_fired_for_owner_minus_100_with_owner_index() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())

    projectile_spawn(
        state,
        players=[player0, player1],
        pos=Vec2(),
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-100,
        owner_player_index=1,
    )

    assert state.shots_fired[0] == 0
    assert state.shots_fired[1] == 1


def test_projectile_spawn_increments_shots_fired_for_owner_minus_2() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())

    projectile_spawn(
        state,
        players=[player0, player1],
        pos=Vec2(),
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-2,
    )

    assert state.shots_fired[0] == 0
    assert state.shots_fired[1] == 1


def test_projectile_spawn_does_not_increment_shots_fired_when_bonus_guard_is_on() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2())

    projectile_spawn(
        state,
        players=[player],
        pos=Vec2(),
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-100,
        owner_player_index=0,
    )

    assert state.shots_fired[0] == 0
