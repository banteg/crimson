from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import (
    most_used_weapon_id_for_player,
    player_fire_weapon,
    weapon_assign_player,
)
from crimson.weapons import WeaponId
from grim.geom import Vec2


def test_weapon_usage_tracks_most_used_weapon() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)
    assert state.weapon_shots_fired[0][1] == 1

    weapon_assign_player(player, WeaponId.ASSAULT_RIFLE, state=state)
    for _ in range(3):
        player.weapon.shot_cooldown = 0.0
        player.spread_heat = 0.0
        player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)
    assert state.weapon_shots_fired[0][2] == 3

    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=WeaponId.PISTOL) == 2


def test_most_used_weapon_falls_back_to_current_weapon() -> None:
    state = GameplayState()
    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=WeaponId.MEAN_MINIGUN) == 7
