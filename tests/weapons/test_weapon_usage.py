from __future__ import annotations

from crimson.gameplay import gameplay_accumulate_weapon_usage_time
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import (
    WeaponFireCtx,
    fire_weapon,
    most_used_weapon_id_for_player,
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
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )
    assert state.weapon_shots_fired[0][1] == 1

    weapon_assign_player(player, WeaponId.ASSAULT_RIFLE, state=state)
    for _ in range(3):
        player.weapon.shot_cooldown = 0.0
        player.spread_heat = 0.0
        fire_weapon(
            WeaponFireCtx(
                player=player,
                input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
                dt=0.016,
                state=state,
            ),
        )
    assert state.weapon_shots_fired[0][2] == 3

    state.weapon_usage_time[WeaponId.PISTOL] = 16
    state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] = 48
    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=WeaponId.PISTOL) == 2


def test_most_used_weapon_uses_pistol_for_zero_time_and_ties() -> None:
    state = GameplayState()
    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=WeaponId.MEAN_MINIGUN) == 1

    state.weapon_usage_time[WeaponId.PISTOL] = 100
    state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] = 100
    assert most_used_weapon_id_for_player(state, player_index=1, fallback_weapon_id=WeaponId.MEAN_MINIGUN) == 1


def test_most_used_weapon_compares_native_u32_slots_as_signed() -> None:
    state = GameplayState()
    state.weapon_usage_time[WeaponId.PISTOL] = 0xFFFFFFFF
    state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] = 0

    assert most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=WeaponId.PISTOL) == 2


def test_weapon_usage_time_accumulates_fixed_player_zero_with_u32_wrapping() -> None:
    state = GameplayState()
    players = [
        PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
        PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL)),
    ]
    state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] = 0xFFFFFFFB

    gameplay_accumulate_weapon_usage_time(state, players, 16)

    assert state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] == 11
    assert state.weapon_usage_time[WeaponId.PISTOL] == 0
