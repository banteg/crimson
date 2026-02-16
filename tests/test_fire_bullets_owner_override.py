from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState
from crimson.projectiles import ProjectileTypeId
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime.spawn import projectile_spawn


def _spawn_type(
    state: GameplayState,
    *,
    players: list[PlayerState],
    owner_id: int,
    owner_player_index: int | None = None,
) -> int:
    proj_id = projectile_spawn(
        state,
        players=players,
        pos=Vec2(100.0, 100.0),
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=int(owner_id),
        owner_player_index=owner_player_index,
    )
    assert proj_id >= 0
    return int(state.projectiles.entries[proj_id].type_id)


def test_projectile_spawn_fire_bullets_default_uses_owner_timer() -> None:
    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=0.0)
    players = [player0, player1]

    player1_type = _spawn_type(state, players=players, owner_id=-2)
    player0_type = _spawn_type(state, players=players, owner_id=-1)

    assert player1_type == int(ProjectileTypeId.PISTOL)
    assert player0_type == int(ProjectileTypeId.FIRE_BULLETS)


def test_projectile_spawn_fire_bullets_default_uses_owner_player_index_with_owner_minus_100() -> None:
    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=0.0)
    players = [player0, player1]

    player1_type = _spawn_type(state, players=players, owner_id=-100, owner_player_index=1)
    player0_type = _spawn_type(state, players=players, owner_id=-100, owner_player_index=0)

    assert player1_type == int(ProjectileTypeId.PISTOL)
    assert player0_type == int(ProjectileTypeId.FIRE_BULLETS)


def test_projectile_spawn_fire_bullets_preserve_bugs_keeps_global_gate() -> None:
    state = GameplayState(preserve_bugs=True)
    player0 = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=0.0)
    players = [player0, player1]

    player1_type = _spawn_type(state, players=players, owner_id=-2)

    assert player1_type == int(ProjectileTypeId.FIRE_BULLETS)
