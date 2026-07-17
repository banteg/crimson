from __future__ import annotations

from grim.geom import Vec2

from ..sim.input import PlayerInput
from ..sim.state_types import GameplayState, PlayerState
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId

TYPO_WEAPON_ID = WeaponId.SHOTGUN


def enforce_typo_player_frame(player: PlayerState, *, state: GameplayState) -> None:
    """Match Typ-o Shooter's bespoke player loop (`player_fire_weapon @ 0x00444980`).

    Typ-o forces the native shotgun (weapon id 3), resets timers, and tops up
    ammo each frame, so typing speed (not weapon cooldown) controls rate of fire.
    """

    if player.weapon.weapon_id != TYPO_WEAPON_ID:
        weapon_assign_player(player, TYPO_WEAPON_ID, state=state)

    player.weapon.shot_cooldown = 0.0
    player.spread_heat = 0.0
    player.weapon.ammo = float(max(0, int(player.weapon.clip_size)))

    player.weapon.reload_active = False
    player.weapon.reload_timer = 0.0
    player.weapon.reload_timer_max = 0.0


def build_typo_player_input(
    *,
    aim: Vec2,
    fire_requested: bool,
    reload_requested: bool,
) -> PlayerInput:
    fire = bool(fire_requested)
    return PlayerInput(
        move=Vec2(),
        aim=aim,
        fire_down=fire,
        fire_pressed=fire,
        reload_pressed=bool(reload_requested),
    )
