from __future__ import annotations

import math
from typing import TYPE_CHECKING

from grim.color import RGBA
from grim.geom import Vec2
from grim.sfx_types import SfxRequest

from ..math_parity import (
    NATIVE_HALF_PI,
    f32,
    x87_fpatan,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ..owner_id import OWNER_LOCAL_PLAYER
from ..perks import PerkId
from ..projectiles.runtime import projectile_spawn
from ..projectiles.types import ProjectileTemplateId
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import TERRAIN_SIZE, PlayerState
from ..weapon_runtime import player_start_reload, weapon_entry
from ..weapons import WeaponId

if TYPE_CHECKING:
    from ..sim.gameplay_state import GameplayState


def player_fire_weapon(
    state: GameplayState,
    players: list[PlayerState],
    player: PlayerState,
    aim: Vec2,
    *,
    fire_requested: bool,
    reload_requested: bool,
    dt: float,
) -> None:
    """Typ-o's player frame, `player_fire_weapon` (0x00444980), in place of `player_update`.

    Cooldown, spread and reload are cleared and the clip refilled every frame, so
    typed words (not the weapon) set the rate of fire. Only the shotgun spawns
    pellets; the ammo never drops.
    """

    if player.health <= 0.0:
        player.death_timer = x87_pc24_sub(player.death_timer, x87_pc24_mul(dt, 20.0))
        return

    player.muzzle_flash_alpha = x87_pc24_sub(player.muzzle_flash_alpha, x87_pc24_add(dt, dt))
    if player.muzzle_flash_alpha < 0.0:
        player.muzzle_flash_alpha = 0.0

    player.weapon.shot_cooldown = 0.0
    player.spread_heat = 0.0
    player.weapon.ammo = float(player.weapon.clip_size)
    player.weapon.reload_timer = 0.0

    if reload_requested:
        player_start_reload(player, state)

    normal_fire_ready = False
    player.aim = aim
    player.aim_heading = x87_pc24_sub(
        x87_fpatan(x87_pc24_sub(player.pos.y, aim.y), x87_pc24_sub(player.pos.x, aim.x)),
        NATIVE_HALF_PI,
    )

    perk_fire_ready = False
    if player.weapon.shot_cooldown <= 0.0 and player.weapon.reload_timer == 0.0:
        normal_fire_ready = True
        player.weapon.reload_active = False

    if (
        player.weapon.shot_cooldown <= 0.0
        and player.experience > 0
        and (PerkId.REGRESSION_BULLETS in state.perks or PerkId.AMMUNITION_WITHIN in state.perks)
    ):
        perk_fire_ready = True

    if normal_fire_ready or perk_fire_ready:
        shot_heading = player.aim_heading
        if fire_requested:
            muzzle_angle = x87_pc24_sub(x87_pc24_sub(shot_heading, NATIVE_HALF_PI), f32(0.150915))
            local_offset = Vec2(x87_pc24_cos_mul(muzzle_angle, 16.0), x87_pc24_sin_mul(muzzle_angle, 16.0))

            weapon = weapon_entry(player.weapon.weapon_id)
            if (weapon.flags or 0) & 1:
                state.rng.rand_tagged(RngCallerStatic.PLAYER_FIRE_WEAPON_DISCARDED_1)
                state.rng.rand_tagged(RngCallerStatic.PLAYER_FIRE_WEAPON_DISCARDED_2)

            if player.muzzle_flash_alpha > 1.0:
                player.muzzle_flash_alpha = 1.0
            player.muzzle_flash_alpha = x87_pc24_add(f32(weapon.spread_heat_inc), player.muzzle_flash_alpha)
            # `shot_sfx_base_id`: no variant draw, unlike `player_update`.
            state.sfx_queue.append(SfxRequest(weapon.fire_sounds[0], player.pos))

            if player.weapon.weapon_id == WeaponId.SHOTGUN:
                muzzle = Vec2(x87_pc24_add(player.pos.x, local_offset.x), x87_pc24_add(player.pos.y, local_offset.y))
                # `fcos`/`fsin` stay wide for the first sprite; the second reloads their float stores.
                heading_cos = math.cos(shot_heading)
                heading_sin = math.sin(shot_heading)
                state.sprite_effects.spawn(
                    pos=muzzle,
                    vel=Vec2(x87_pc24_mul(heading_cos, 25.0), x87_pc24_mul(heading_sin, 25.0)),
                    scale=1.0,
                    color=RGBA(0.5, 0.5, 0.5, 0.25),
                    rng=state.rng,
                )
                state.sprite_effects.spawn(
                    pos=muzzle,
                    vel=Vec2(x87_pc24_mul(f32(heading_cos), 15.0), x87_pc24_mul(f32(heading_sin), 15.0)),
                    scale=2.0,
                    color=RGBA(0.5, 0.5, 0.5, 0.223),
                    rng=state.rng,
                )
                for _ in range(12):
                    jitter = state.rng.rand_tagged(RngCallerStatic.PLAYER_FIRE_WEAPON_SHOTGUN_PELLET_JITTER) % 200 - 100
                    projectile_index = projectile_spawn(
                        state,
                        players=players,
                        pos=muzzle,
                        angle=x87_pc24_add(x87_pc24_mul(float(jitter), f32(0.0013)), shot_heading),
                        type_id=ProjectileTemplateId.SHOTGUN,
                        owner_id=OWNER_LOCAL_PLAYER,
                        owner_player_index=player.index,
                    )
                    speed_roll = state.rng.rand_tagged(RngCallerStatic.PLAYER_FIRE_WEAPON_SHOTGUN_PELLET_SPEED_SCALE) % 100
                    state.projectiles.entries[projectile_index].speed_scale = x87_pc24_add(
                        x87_pc24_mul(float(speed_roll), f32(0.01)),
                        1.0,
                    )

            damping = f32(state.player_spread_damping_scalar)
            if PerkId.SHARPSHOOTER not in state.perks:
                player.spread_heat = x87_pc24_add(x87_pc24_mul(x87_pc24_mul(damping, dt), 150.0), player.spread_heat)
            if x87_pc24_add(damping, damping) < player.spread_heat:
                player.spread_heat = x87_pc24_add(damping, damping)
            player.spread_heat = x87_pc24_mul(damping, player.spread_heat)

            if PerkId.FASTSHOT in state.perks:
                player.weapon.shot_cooldown = x87_pc24_mul(player.weapon.shot_cooldown, f32(0.88))
            if PerkId.SHARPSHOOTER in state.perks:
                player.weapon.shot_cooldown = x87_pc24_mul(player.weapon.shot_cooldown, f32(1.05))
            if player.weapon.ammo <= 0.0:
                player_start_reload(player, state)

    while player.move_phase > 14.0:
        player.move_phase = x87_pc24_sub(player.move_phase, 14.0)

    half_size = x87_pc24_mul(player.size, 0.5)
    if player.pos.x < half_size:
        player.pos = Vec2(half_size, player.pos.y)
    if x87_pc24_sub(TERRAIN_SIZE, half_size) < player.pos.x:
        player.pos = Vec2(x87_pc24_sub(TERRAIN_SIZE, half_size), player.pos.y)
    if player.pos.y < half_size:
        player.pos = Vec2(player.pos.x, half_size)
    if x87_pc24_sub(TERRAIN_SIZE, half_size) < player.pos.y:
        player.pos = Vec2(player.pos.x, x87_pc24_sub(TERRAIN_SIZE, half_size))
    if player.muzzle_flash_alpha > f32(0.8):
        player.muzzle_flash_alpha = f32(0.8)
