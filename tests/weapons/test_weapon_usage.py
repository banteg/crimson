from __future__ import annotations

from crimson.gameplay import gameplay_accumulate_weapon_usage_time
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import most_used_weapon_id_for_player
from crimson.weapons import WeaponId
from grim.geom import Vec2


def test_most_used_weapon_uses_pistol_for_zero_time_and_ties() -> None:
    state = GameplayState()
    assert most_used_weapon_id_for_player(state, fallback_weapon_id=WeaponId.MEAN_MINIGUN) == 1

    state.weapon_usage_time[WeaponId.PISTOL] = 100
    state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] = 100
    assert most_used_weapon_id_for_player(state, fallback_weapon_id=WeaponId.MEAN_MINIGUN) == 1


def test_most_used_weapon_compares_native_u32_slots_as_signed() -> None:
    state = GameplayState()
    state.weapon_usage_time[WeaponId.PISTOL] = 0xFFFFFFFF
    state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] = 0

    assert most_used_weapon_id_for_player(state, fallback_weapon_id=WeaponId.PISTOL) == 2


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
