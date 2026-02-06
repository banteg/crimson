from __future__ import annotations

from grim.geom import Vec2

from dataclasses import dataclass

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon, weapon_assign_player


@dataclass(slots=True)
class _DummyCreature:
    pos: Vec2
    hp: float = 100.0
    size: float = 200.0
    active: bool = True
    hitbox_size: float = 16.0
    flags: int = 0
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
