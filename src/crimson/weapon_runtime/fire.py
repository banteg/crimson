from __future__ import annotations

import math
from collections.abc import Sequence

from grim.color import RGBA
from grim.geom import Vec2

from ..perks import PerkId
from ..perks.helpers import perk_active
from ..projectiles import Damageable, ProjectileTypeId, SecondaryProjectileTypeId
from ..sim.input import PlayerInput
from ..sim.state_types import GameplayState, PlayerState
from ..weapons import WEAPON_TABLE, WeaponId, projectile_type_id_from_weapon_id, weapon_entry_for_projectile_type_id
from .assign import player_start_reload, weapon_entry
from .spawn import owner_id_for_player, owner_id_for_player_projectiles, projectile_meta_for_type_id

WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1

_NATIVE_FIRE_MUZZLE_SPRITES: dict[int, tuple[tuple[float, float, float], ...]] = {
    int(WeaponId.PISTOL): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.ASSAULT_RIFLE): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.SHOTGUN): ((25.0, 1.0, 0.25), (15.0, 2.0, 0.223)),
    int(WeaponId.SAWED_OFF_SHOTGUN): ((25.0, 1.0, 0.26), (15.0, 2.0, 0.233)),
    int(WeaponId.SUBMACHINE_GUN): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.GAUSS_GUN): ((25.0, 1.0, 0.33), (15.0, 2.0, 0.263)),
    int(WeaponId.ROCKET_LAUNCHER): ((25.0, 1.0, 0.34), (15.0, 2.0, 0.283)),
    int(WeaponId.SEEKER_ROCKETS): ((25.0, 1.0, 0.31), (15.0, 2.0, 0.243)),
    int(WeaponId.MINI_ROCKET_SWARMERS): ((25.0, 1.0, 0.34), (15.0, 2.0, 0.283)),
    int(WeaponId.ROCKET_MINIGUN): ((25.0, 1.0, 0.34),),
    int(WeaponId.JACKHAMMER): ((15.0, 2.0, 0.223),),
    int(WeaponId.SHRINKIFIER_5K): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.GAUSS_SHOTGUN): ((25.0, 1.0, 0.33), (15.0, 2.0, 0.263)),
}

_NATIVE_FIRE_MUZZLE_AFTER_PROJECTILE: frozenset[int] = frozenset(
    {
        int(WeaponId.PISTOL),
        int(WeaponId.SHRINKIFIER_5K),
    }
)


def _spawn_native_fire_muzzle_sprites(
    *,
    state: GameplayState,
    weapon_id: int,
    muzzle: Vec2,
    aim_heading: float,
    fire_bullets_active: bool,
) -> None:
    if fire_bullets_active:
        specs: tuple[tuple[float, float, float], ...] = ((25.0, 1.0, 0.413),)
    else:
        specs = _NATIVE_FIRE_MUZZLE_SPRITES.get(int(weapon_id), ())
    if not specs:
        return

    for speed, scale, alpha in specs:
        state.sprite_effects.spawn(
            pos=muzzle,
            vel=Vec2.from_heading(aim_heading) * float(speed),
            scale=float(scale),
            color=RGBA(0.5, 0.5, 0.5, float(alpha)),
        )


def player_fire_weapon(
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    state: GameplayState,
    *,
    detail_preset: int = 5,
    creatures: Sequence[Damageable] | None = None,
) -> None:
    dt = float(dt)

    weapon_id = int(player.weapon_id)
    weapon = weapon_entry(weapon_id)
    if weapon is None:
        return

    if player.shot_cooldown > 0.0:
        return
    if not input_state.fire_down:
        return

    ammo_cost = 1.0
    is_fire_bullets = float(player.fire_bullets_timer) > 0.0
    if player.reload_timer > 0.0:
        if player.experience <= 0:
            return
        if perk_active(player, PerkId.REGRESSION_BULLETS):
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            reload_time = float(weapon.reload_time) if weapon.reload_time is not None else 0.0
            factor = 4.0 if ammo_class == 1 else 200.0
            player.experience = int(float(player.experience) - reload_time * factor)
            if player.experience < 0:
                player.experience = 0
        elif perk_active(player, PerkId.AMMUNITION_WITHIN):
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            from ..player_damage import player_take_damage

            cost = 0.15 if ammo_class == 1 else 1.0
            player_take_damage(state, player, cost, dt=dt, rand=state.rng.rand)
        else:
            return

    pellet_count = int(weapon.pellet_count) if weapon.pellet_count is not None else 0
    fire_bullets_weapon = weapon_entry_for_projectile_type_id(int(ProjectileTypeId.FIRE_BULLETS))

    shot_cooldown = float(weapon.shot_cooldown) if weapon.shot_cooldown is not None else 0.0
    weapon_spread_heat = float(weapon.spread_heat_inc) if weapon.spread_heat_inc is not None else 0.0
    fire_bullets_spread_heat = weapon_spread_heat
    if fire_bullets_weapon is not None and fire_bullets_weapon.spread_heat_inc is not None:
        fire_bullets_spread_heat = float(fire_bullets_weapon.spread_heat_inc)

    if is_fire_bullets and pellet_count == 1 and fire_bullets_weapon is not None:
        shot_cooldown = (
            float(fire_bullets_weapon.shot_cooldown) if fire_bullets_weapon.shot_cooldown is not None else 0.0
        )

    spread_heat_base = fire_bullets_spread_heat if is_fire_bullets else weapon_spread_heat
    spread_inc = spread_heat_base * 1.3

    if perk_active(player, PerkId.FASTSHOT):
        shot_cooldown *= 0.88
    if perk_active(player, PerkId.SHARPSHOOTER):
        shot_cooldown *= 1.05
    player.shot_cooldown = max(0.0, shot_cooldown)

    aim = input_state.aim
    aim_delta = aim - player.pos
    aim_heading = aim_delta.to_heading()

    muzzle = player.pos + Vec2.from_heading(aim_heading).rotated(-0.150915) * 16.0
    state.effects.spawn_shell_casing(
        pos=muzzle,
        aim_heading=aim_heading,
        weapon_flags=int(weapon.flags or 0),
        rand=state.rng.rand,
        detail_preset=int(detail_preset),
    )

    dist = aim_delta.length()
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(int(state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    aim_jitter = aim + Vec2.from_angle(dir_angle) * offset
    shot_angle = (aim_jitter - player.pos).to_heading()
    particle_angle = Vec2.from_heading(shot_angle).to_angle()
    if weapon_id in (WeaponId.FLAMETHROWER, WeaponId.BLOW_TORCH, WeaponId.HR_FLAMER):
        particle_angle = Vec2.from_heading(aim_heading).to_angle()

    # Native `player_fire_weapon` consumes one RNG draw for shot SFX variant
    # selection on every non-Fire-Bullets shot.
    if not is_fire_bullets:
        state.rng.rand()

    owner_id = owner_id_for_player(player.index)
    projectile_owner_id = owner_id_for_player_projectiles(state, player.index)
    shot_count = 1
    spawn_muzzle_after_projectile = bool(is_fire_bullets) or int(weapon_id) in _NATIVE_FIRE_MUZZLE_AFTER_PROJECTILE
    if not spawn_muzzle_after_projectile:
        _spawn_native_fire_muzzle_sprites(
            state=state,
            weapon_id=int(weapon_id),
            muzzle=muzzle,
            aim_heading=float(aim_heading),
            fire_bullets_active=bool(is_fire_bullets),
        )

    # `player_fire_weapon` (crimsonland.exe) uses weapon-specific extra angular jitter for pellet
    # weapons. This is separate from aim-point jitter driven by `player.spread_heat`.
    def _pellet_jitter_step(weapon_id: int) -> float:
        weapon_id = int(weapon_id)
        if weapon_id == WeaponId.SHOTGUN:
            return 0.0013
        if weapon_id == WeaponId.SAWED_OFF_SHOTGUN:
            return 0.004
        if weapon_id == WeaponId.JACKHAMMER:
            return 0.0013
        return 0.0015

    if is_fire_bullets:
        pellets = max(0, int(pellet_count))
        shot_count = pellets
        meta = projectile_meta_for_type_id(ProjectileTypeId.FIRE_BULLETS)
        for _ in range(pellets):
            angle = shot_angle + float(int(state.rng.rand()) % 200 - 100) * 0.0015
            state.projectiles.spawn(
                pos=muzzle,
                angle=angle,
                type_id=ProjectileTypeId.FIRE_BULLETS,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
    elif weapon_id == WeaponId.ROCKET_LAUNCHER:
        # Rocket Launcher -> secondary type 1.
        state.secondary_projectiles.spawn(
            pos=muzzle,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.ROCKET,
            owner_id=owner_id,
        )
    elif weapon_id == WeaponId.SEEKER_ROCKETS:
        # Seeker Rockets -> secondary type 2.
        state.secondary_projectiles.spawn(
            pos=muzzle,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
            owner_id=owner_id,
            target_hint=aim,
            creatures=creatures,
        )
    elif weapon_id == WeaponId.MINI_ROCKET_SWARMERS:
        # Mini-Rocket Swarmers -> secondary type 2 (fires the full clip in a spread).
        rocket_count = max(1, int(player.ammo))
        step = float(rocket_count) * (math.pi / 3.0)
        angle = (shot_angle - math.pi) - step * float(rocket_count) * 0.5
        for _ in range(rocket_count):
            state.secondary_projectiles.spawn(
                pos=muzzle,
                angle=angle,
                type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
                owner_id=owner_id,
                target_hint=aim,
                creatures=creatures,
            )
            angle += step
        ammo_cost = float(rocket_count)
        shot_count = rocket_count
    elif weapon_id == WeaponId.ROCKET_MINIGUN:
        # Rocket Minigun -> secondary type 4.
        state.secondary_projectiles.spawn(
            pos=muzzle,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.ROCKET_MINIGUN,
            owner_id=owner_id,
        )
    elif weapon_id == WeaponId.FLAMETHROWER:
        # Flamethrower -> fast particle weapon (style 0), fractional ammo drain.
        state.particles.spawn_particle(pos=muzzle, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        ammo_cost = 0.1
    elif weapon_id == WeaponId.BLOW_TORCH:
        # Blow Torch -> fast particle weapon (style 1), fractional ammo drain.
        particle_id = state.particles.spawn_particle(pos=muzzle, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        state.particles.entries[particle_id].style_id = 1
        ammo_cost = 0.05
    elif weapon_id == WeaponId.HR_FLAMER:
        # HR Flamer -> fast particle weapon (style 2), fractional ammo drain.
        particle_id = state.particles.spawn_particle(pos=muzzle, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        state.particles.entries[particle_id].style_id = 2
        ammo_cost = 0.1
    elif weapon_id == WeaponId.BUBBLEGUN:
        # Bubblegun -> slow particle weapon (style 8), fractional ammo drain.
        state.particles.spawn_particle_slow(
            pos=muzzle,
            angle=Vec2.from_heading(shot_angle).to_angle(),
            owner_id=owner_id,
        )
        ammo_cost = 0.15
    elif weapon_id == WeaponId.MULTI_PLASMA:
        # Multi-Plasma: 5-shot fixed spread using type 0x09 and 0x0B.
        # (`player_update` weapon_id==0x0a in crimsonland.exe)
        shot_count = 5
        # Native literals: 0.31415927 (~ pi/10), 0.5235988 (~ pi/6).
        spread_small = math.pi / 10
        spread_large = math.pi / 6
        patterns: tuple[tuple[float, ProjectileTypeId], ...] = (
            (-spread_small, ProjectileTypeId.PLASMA_RIFLE),
            (-spread_large, ProjectileTypeId.PLASMA_MINIGUN),
            (0.0, ProjectileTypeId.PLASMA_RIFLE),
            (spread_large, ProjectileTypeId.PLASMA_MINIGUN),
            (spread_small, ProjectileTypeId.PLASMA_RIFLE),
        )
        for angle_offset, type_id in patterns:
            state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + angle_offset,
                type_id=type_id,
                owner_id=projectile_owner_id,
                base_damage=projectile_meta_for_type_id(type_id),
            )
    elif weapon_id == WeaponId.PLASMA_SHOTGUN:
        # Plasma Shotgun: 14 plasma-minigun pellets with wide jitter and random speed_scale.
        # (`player_update` weapon_id==0x0e in crimsonland.exe)
        shot_count = 14
        meta = projectile_meta_for_type_id(int(ProjectileTypeId.PLASMA_MINIGUN))
        for _ in range(14):
            jitter = float((int(state.rng.rand()) & 0xFF) - 0x80) * 0.002
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.PLASMA_MINIGUN,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            state.projectiles.entries[int(proj_id)].speed_scale = 1.0 + float(int(state.rng.rand()) % 100) * 0.01
    elif weapon_id == WeaponId.GAUSS_SHOTGUN:
        # Gauss Shotgun: 6 gauss pellets, jitter 0.002 and speed_scale 1.4..(1.4 + 0.79).
        # (`player_update` weapon_id==0x1e in crimsonland.exe)
        shot_count = 6
        meta = projectile_meta_for_type_id(int(ProjectileTypeId.GAUSS_GUN))
        for _ in range(6):
            jitter = float(int(state.rng.rand()) % 200 - 100) * 0.002
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.GAUSS_GUN,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            state.projectiles.entries[int(proj_id)].speed_scale = 1.4 + float(int(state.rng.rand()) % 0x50) * 0.01
    elif weapon_id == WeaponId.ION_SHOTGUN:
        # Ion Shotgun: 8 ion-minigun pellets, jitter 0.0026 and speed_scale 1.4..(1.4 + 0.79).
        # (`player_update` weapon_id==0x1f in crimsonland.exe)
        shot_count = 8
        meta = projectile_meta_for_type_id(int(ProjectileTypeId.ION_MINIGUN))
        for _ in range(8):
            jitter = float(int(state.rng.rand()) % 200 - 100) * 0.0026
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.ION_MINIGUN,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            state.projectiles.entries[int(proj_id)].speed_scale = 1.4 + float(int(state.rng.rand()) % 0x50) * 0.01
    else:
        pellets = max(1, int(pellet_count))
        shot_count = pellets
        type_id = projectile_type_id_from_weapon_id(weapon_id)
        if type_id is None:
            return
        meta = projectile_meta_for_type_id(type_id)
        jitter_step = _pellet_jitter_step(weapon_id)
        for _ in range(pellets):
            angle = shot_angle
            if pellets > 1:
                angle += float(int(state.rng.rand()) % 200 - 100) * jitter_step
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=angle,
                type_id=type_id,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            # Shotgun variants randomize speed_scale per pellet (rand%100 * 0.01 + 1.0).
            if pellets > 1 and weapon_id in (WeaponId.SHOTGUN, WeaponId.SAWED_OFF_SHOTGUN, WeaponId.JACKHAMMER):
                state.projectiles.entries[int(proj_id)].speed_scale = 1.0 + float(int(state.rng.rand()) % 100) * 0.01

    if 0 <= int(player.index) < len(state.shots_fired):
        state.shots_fired[int(player.index)] += int(shot_count)
        if 0 <= weapon_id < WEAPON_COUNT_SIZE:
            state.weapon_shots_fired[int(player.index)][weapon_id] += int(shot_count)

    if spawn_muzzle_after_projectile:
        _spawn_native_fire_muzzle_sprites(
            state=state,
            weapon_id=int(weapon_id),
            muzzle=muzzle,
            aim_heading=float(aim_heading),
            fire_bullets_active=bool(is_fire_bullets),
        )

    if not perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = min(0.48, max(0.0, player.spread_heat + spread_inc))

    muzzle_inc = weapon_spread_heat
    if is_fire_bullets and pellet_count == 1:
        muzzle_inc = fire_bullets_spread_heat
    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha)
    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha + muzzle_inc)
    player.muzzle_flash_alpha = min(0.8, player.muzzle_flash_alpha)

    player.shot_seq += 1
    if state.bonuses.reflex_boost <= 0.0 and not is_fire_bullets:
        # Native allows ammo to cross below zero for reload-time firing paths
        # (for example Regression Bullets), and replay checkpoints rely on that.
        player.ammo = float(player.ammo) - float(ammo_cost)
    if player.ammo <= 0.0 and player.reload_timer <= 0.0:
        player_start_reload(player, state)
