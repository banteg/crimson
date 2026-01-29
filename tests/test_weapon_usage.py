from __future__ import annotations

from crimson.gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    most_used_weapon_id_for_player,
    player_fire_weapon,
    weapon_assign_player,
)


def test_weapon_usage_tracks_most_used_weapon() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 0)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)
    assert state.weapon_shots_fired[0][0] == 1

    weapon_assign_player(player, 2)
    player.spread_heat = 0.0
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)
    assert state.weapon_shots_fired[0][2] == 12

    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=0) == 2


def test_most_used_weapon_falls_back_to_current_weapon() -> None:
    state = GameplayState()
    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=7) == 7
