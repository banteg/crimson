from __future__ import annotations

from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.typo.player import TYPO_WEAPON_ID, build_typo_player_input, enforce_typo_player_frame
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2


def test_typo_weapon_matches_native_shotgun_id() -> None:
    assert TYPO_WEAPON_ID == WeaponId.SHOTGUN
    assert int(TYPO_WEAPON_ID) == 3


def test_enforce_typo_player_frame_resets_timers_and_ammo() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    player.weapon.shot_cooldown = 0.5
    player.spread_heat = 0.25
    player.weapon.ammo = 0
    player.weapon.reload_active = True
    player.weapon.reload_timer = 1.25
    player.weapon.reload_timer_max = 1.25

    enforce_typo_player_frame(player, state=state)

    assert player.weapon.weapon_id == WeaponId.SHOTGUN
    assert player.weapon.shot_cooldown == 0.0
    assert player.spread_heat == 0.0
    assert player.weapon.reload_active is False
    assert player.weapon.reload_timer == 0.0
    assert player.weapon.reload_timer_max == 0.0
    assert player.weapon.ammo == player.weapon.clip_size


def test_build_typo_player_input_pulses_fire() -> None:
    input_state = build_typo_player_input(
        aim=Vec2(123.0, 456.0),
        fire_requested=True,
        reload_requested=False,
    )
    assert input_state.fire_down is True
    assert input_state.fire_pressed is True
    assert input_state.reload_pressed is False

    input_state = build_typo_player_input(
        aim=Vec2(),
        fire_requested=False,
        reload_requested=True,
    )
    assert input_state.fire_down is False
    assert input_state.fire_pressed is False
    assert input_state.reload_pressed is True
