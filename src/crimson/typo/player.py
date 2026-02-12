from __future__ import annotations

from grim.geom import Vec2

from ..sim.input import PlayerInput
from ..sim.state_types import PlayerState
from ..weapon_runtime import weapon_assign_player

TYPO_WEAPON_ID = 4


def enforce_typo_player_frame(player: PlayerState) -> None:
    """Match Typ-o Shooter's bespoke player loop (`player_fire_weapon @ 0x00444980`).

    Typ-o resets timers and tops up ammo each frame, so typing speed (not weapon
    cooldown) controls rate of fire.
    """

    if int(player.weapon_id) != TYPO_WEAPON_ID:
        weapon_assign_player(player, TYPO_WEAPON_ID)

    player.shot_cooldown = 0.0
    player.spread_heat = 0.0
    player.ammo = float(max(0, int(player.clip_size)))

    player.reload_active = False
    player.reload_timer = 0.0
    player.reload_timer_max = 0.0


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
