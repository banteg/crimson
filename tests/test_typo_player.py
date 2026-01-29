from __future__ import annotations

from crimson.gameplay import PlayerState, weapon_assign_player
from crimson.typo.player import TYPO_WEAPON_ID, build_typo_player_input, enforce_typo_player_frame


def test_enforce_typo_player_frame_resets_timers_and_ammo() -> None:
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    weapon_assign_player(player, 1)
    player.shot_cooldown = 0.5
    player.spread_heat = 0.25
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 1.25
    player.reload_timer_max = 1.25

    enforce_typo_player_frame(player)

    assert player.weapon_id == TYPO_WEAPON_ID
    assert player.shot_cooldown == 0.0
    assert player.spread_heat == 0.0
    assert player.reload_active is False
    assert player.reload_timer == 0.0
    assert player.reload_timer_max == 0.0
    assert player.ammo == player.clip_size


def test_build_typo_player_input_pulses_fire() -> None:
    input_state = build_typo_player_input(
        aim_x=123.0,
        aim_y=456.0,
        fire_requested=True,
        reload_requested=False,
    )
    assert input_state.fire_down is True
    assert input_state.fire_pressed is True
    assert input_state.reload_pressed is False

    input_state = build_typo_player_input(
        aim_x=0.0,
        aim_y=0.0,
        fire_requested=False,
        reload_requested=True,
    )
    assert input_state.fire_down is False
    assert input_state.fire_pressed is False
    assert input_state.reload_pressed is True
