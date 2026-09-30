from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import i32
from grim.rand import CrandLike
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..effects import ParticleStyleId
from ..math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    f32,
    native_fire_muzzle_pos,
    native_shot_angle_from_jitter_draws,
    x87_pc24_add,
    x87_pc24_div,
    x87_pc24_mul,
    x87_pc24_sub,
)
from ..owner_id import player_projectile_owner_id
from ..perks import PerkId
from ..projectiles.runtime import fx_spawn_secondary_projectile, projectile_spawn
from ..projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from ..rng_caller_static import RngCallerStatic
from ..sim.input import PlayerInput
from ..sim.state_types import PerkCounts, PlayerState
from ..weapons import WEAPON_TABLE, WeaponId, weapon_entry_for_projectile_type_id
from .assign import player_start_reload, weapon_entry

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureState
    from ..sim.world_state import WorldStepRuntime

WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1


class WeaponFireGate(msgspec.Struct, frozen=True):
    normal_ready: bool
    perk_ready: bool


def capture_fire_gate(player: PlayerState, perks: PerkCounts) -> WeaponFireGate:
    """Snapshot native firing readiness before Alternate Weapon exchanges slots."""
    cooldown_ready = player.weapon.shot_cooldown <= 0.0
    return WeaponFireGate(
        normal_ready=cooldown_ready and player.weapon.reload_timer == 0.0,
        perk_ready=cooldown_ready and player.experience > 0 and (
            PerkId.REGRESSION_BULLETS in perks
            or PerkId.AMMUNITION_WITHIN in perks
        ),
    )


class WeaponFireCtx(msgspec.Struct):
    player: PlayerState
    input_state: PlayerInput
    dt: float
    step_runtime: WorldStepRuntime
    fire_gate: WeaponFireGate


class WeaponFireResult(msgspec.Struct, frozen=True):
    fired: bool
    shot_count: int = 0
    ammo_cost: float = 0.0


class _ShotSpawner(msgspec.Struct, frozen=True):
    """The muzzle, owner and pools every `player_update` fire branch spawns into."""

    state: GameplayState
    players: list[PlayerState]
    creatures: Sequence[CreatureState]
    player_index: int
    muzzle: Vec2
    aim_heading: float
    # Native encodes friendly fire in the owner id (-1 - player_index): with the
    # cvar enabled, primary player shots can hit other players for 10 damage.
    owner_id: int

    def projectile(self, type_id: ProjectileTemplateId, angle: float) -> int:
        return projectile_spawn(
            self.state,
            players=self.players,
            pos=self.muzzle,
            angle=angle,
            type_id=type_id,
            owner_id=self.owner_id,
            owner_player_index=self.player_index,
        )

    def secondary(self, type_id: SecondaryProjectileTypeId, angle: float) -> None:
        fx_spawn_secondary_projectile(
            self.state,
            self.players[self.player_index],
            self.creatures,
            pos=self.muzzle,
            angle=angle,
            type_id=type_id,
        )

    def muzzle_sprite(self, speed: float, scale: float, alpha: float) -> None:
        # Native uses raw (cos h, sin h) of the aim heading - the aim direction
        # rotated 90 degrees - matching the Fire Cough and shell-casing ports.
        self.state.sprite_effects.spawn(
            pos=self.muzzle,
            vel=Vec2.from_angle(self.aim_heading) * speed,
            scale=scale,
            color=RGBA(0.5, 0.5, 0.5, alpha),
            rng=self.state.rng,
        )


def _native_shot_angle_with_jitter(
    *,
    aim: Vec2,
    player_pos: Vec2,
    spread_heat: float,
    rng: CrandLike,
) -> float:
    # Native gameplay fire owns two exact `player_update` draw sites for the
    # disc-spread direction and magnitude before the later projectile work.
    dir_draw = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SHOT_JITTER_DIR)
    mag_draw = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SHOT_JITTER_MAG)
    return native_shot_angle_from_jitter_draws(
        aim=aim,
        player_pos=player_pos,
        spread_heat=spread_heat,
        dir_draw=dir_draw,
        mag_draw=mag_draw,
    )


def _pellet_angle(shot_angle: float, roll: int, step: float) -> float:
    # Native pellet loops (e.g. shotgun @ 0x00416378): `fild roll; fmul float step;
    # fadd shot_angle`, each rounded at PC24.
    return x87_pc24_add(x87_pc24_mul(float(roll), f32(step)), shot_angle)


def _pellet_speed_scale(roll: int, base: float) -> float:
    # Native (e.g. shotgun @ 0x004163b1): `fild roll; fmul 0.01f; fadd base` at
    # PC24, then a float store into the projectile.
    return x87_pc24_add(x87_pc24_mul(float(roll), f32(0.01)), f32(base))


def fire_weapon(ctx: WeaponFireCtx) -> WeaponFireResult:
    player = ctx.player
    input_state = ctx.input_state
    dt = float(ctx.dt)
    state = ctx.step_runtime.world.state
    creatures = ctx.step_runtime.world.creatures.entries
    fire_gate = ctx.fire_gate

    weapon_id = player.weapon.weapon_id
    weapon = weapon_entry(weapon_id)

    if not (fire_gate.normal_ready or fire_gate.perk_ready):
        return WeaponFireResult(fired=False)
    if not input_state.fire_down:
        return WeaponFireResult(fired=False)

    perk_fire_ready = not fire_gate.normal_ready
    use_regression_bullets = False
    use_ammunition_within = False
    if perk_fire_ready:
        use_regression_bullets = PerkId.REGRESSION_BULLETS in state.perks
        use_ammunition_within = (not use_regression_bullets) and PerkId.AMMUNITION_WITHIN in state.perks

    # Native writes this after the ready/input gates, but before charging the
    # reload-bypass perk and dispatching the shot.
    state.survival_reward_fire_seen = True

    if perk_fire_ready:
        if use_regression_bullets:
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            reload_time = float(weapon.reload_time)
            factor = 4.0 if ammo_class == 1 else 200.0
            # Native rounds FMUL and FSUBP at PC=24 before the truncating _ftol.
            cost = x87_pc24_mul(reload_time, factor)
            # _ftol returns the low signed 32 bits in EAX before the negative clamp.
            player.experience = i32(int(x87_pc24_sub(float(player.experience), cost)))
            if player.experience < 0:
                player.experience = 0
        elif use_ammunition_within:
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            from ..player_damage import player_take_damage

            cost = 0.15 if ammo_class == 1 else 1.0
            player_take_damage(ctx.step_runtime, player, cost, dt=dt)
    # Native player_update grants ten seconds for DIK_G on an eligible shot.
    # Keep this legacy cheat opt-in, including when replay input supplies it.
    if state.preserve_bugs and input_state.fire_bullets_key_down:
        player.fire_bullets_timer = 10.0
    is_fire_bullets = float(player.fire_bullets_timer) > 0.0

    pellet_count = int(weapon.pellet_count)
    fire_bullets_weapon = weapon_entry_for_projectile_type_id(ProjectileTemplateId.FIRE_BULLETS)

    shot_cooldown = f32(weapon.shot_cooldown)
    weapon_spread_heat = float(weapon.spread_heat_inc)
    fire_bullets_spread_heat = float(fire_bullets_weapon.spread_heat_inc)

    if is_fire_bullets and pellet_count == 1:
        shot_cooldown = f32(fire_bullets_weapon.shot_cooldown)

    spread_heat_base = fire_bullets_spread_heat if is_fire_bullets else weapon_spread_heat
    spread_inc = x87_pc24_mul(spread_heat_base, f32(1.3))

    if PerkId.FASTSHOT in state.perks:
        shot_cooldown = x87_pc24_mul(shot_cooldown, f32(0.88))
    if PerkId.SHARPSHOOTER in state.perks:
        shot_cooldown = x87_pc24_mul(shot_cooldown, f32(1.05))
    player.weapon.shot_cooldown = max(0.0, f32(shot_cooldown))

    # `player_update` computes and stores aim and aim_heading before entering the
    # fire branch; the spread jitter reads `player_state_table[i].aim` (0x00415c24)
    # and later muzzle and presentation math reload that exact heading field.
    aim_heading = f32(player.aim_heading)

    muzzle = native_fire_muzzle_pos(player.pos, aim_heading)
    weapon_flags = int(weapon.flags or 0)
    if weapon_flags & 0x1:
        # The casing's four `player_update` RNG draws precede the later shot-angle jitter work.
        state.effects.spawn_shell_casing(
            pos=muzzle,
            aim_heading=aim_heading,
            rng=state.rng,
            detail_preset=int(ctx.step_runtime.world.state.detail_preset),
        )

    shot_angle = _native_shot_angle_with_jitter(
        aim=player.aim,
        player_pos=player.pos,
        spread_heat=float(player.spread_heat),
        rng=state.rng,
    )

    rng = state.rng
    shot = _ShotSpawner(
        state=state,
        players=ctx.step_runtime.world.players,
        creatures=creatures,
        player_index=player.index,
        muzzle=muzzle,
        aim_heading=aim_heading,
        owner_id=player_projectile_owner_id(friendly_fire=state.friendly_fire_enabled, player_index=player.index),
    )
    ammo_cost = 1.0
    # Shots fired are counted where native counts them, in `projectile_spawn` and
    # `fx_spawn_secondary_projectile`; the per-weapon usage counter keeps the
    # rewrite's most-used-weapon heuristic.
    shot_count = 1

    if is_fire_bullets:
        # `fire_bullets_primary_shot_sfx_id` and `fire_bullets_secondary_shot_sfx_id`.
        state.sfx_queue.append(SfxRequest(SfxId.AUTORIFLE_FIRE, player.pos))
        state.sfx_queue.append(SfxRequest(SfxId.PLASMAMINIGUN_FIRE, player.pos))
        for _ in range(pellet_count):
            jitter = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_FIRE_BULLETS_PELLET_JITTER) % 200 - 100
            shot.projectile(ProjectileTemplateId.FIRE_BULLETS, _pellet_angle(shot_angle, jitter, 0.0015))
        shot_count = pellet_count
        shot.muzzle_sprite(25.0, 1.0, 0.413)
    else:
        sfx_variant = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SHOT_SFX) % len(weapon.fire_sounds)
        state.sfx_queue.append(SfxRequest(weapon.fire_sounds[sfx_variant], player.pos))

        match weapon_id:
            case WeaponId.SHRINKIFIER_5K | WeaponId.PISTOL:
                shot.projectile(ProjectileTemplateId(weapon_id), shot_angle)
                shot.muzzle_sprite(25.0, 1.0, 0.23)
                shot.muzzle_sprite(15.0, 2.0, 0.213)
            case WeaponId.ASSAULT_RIFLE | WeaponId.SUBMACHINE_GUN:
                shot.muzzle_sprite(25.0, 1.0, 0.23)
                shot.muzzle_sprite(15.0, 2.0, 0.213)
                shot.projectile(ProjectileTemplateId(weapon_id), shot_angle)
            case WeaponId.SHOTGUN:
                shot.muzzle_sprite(25.0, 1.0, 0.25)
                shot.muzzle_sprite(15.0, 2.0, 0.223)
                for _ in range(12):
                    jitter = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SHOTGUN_PELLET_JITTER) % 200 - 100
                    pellet = shot.projectile(ProjectileTemplateId.SHOTGUN, _pellet_angle(shot_angle, jitter, 0.0013))
                    speed = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SHOTGUN_PELLET_SPEED_SCALE) % 100
                    state.projectiles.entries[pellet].speed_scale = _pellet_speed_scale(speed, 1.0)
                shot_count = 12
            case WeaponId.JACKHAMMER:
                shot.muzzle_sprite(15.0, 2.0, 0.223)
                for _ in range(4):
                    jitter = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_JACKHAMMER_PELLET_JITTER) % 200 - 100
                    pellet = shot.projectile(ProjectileTemplateId.SHOTGUN, _pellet_angle(shot_angle, jitter, 0.0013))
                    speed = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_JACKHAMMER_PELLET_SPEED_SCALE) % 100
                    state.projectiles.entries[pellet].speed_scale = _pellet_speed_scale(speed, 1.0)
                shot_count = 4
            case WeaponId.SAWED_OFF_SHOTGUN:
                shot.muzzle_sprite(25.0, 1.0, 0.26)
                shot.muzzle_sprite(15.0, 2.0, 0.233)
                for _ in range(12):
                    jitter = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SAWED_OFF_SHOTGUN_PELLET_JITTER) % 200 - 100
                    pellet = shot.projectile(ProjectileTemplateId.SHOTGUN, _pellet_angle(shot_angle, jitter, 0.004))
                    speed = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SAWED_OFF_SHOTGUN_PELLET_SPEED_SCALE) % 100
                    state.projectiles.entries[pellet].speed_scale = _pellet_speed_scale(speed, 1.0)
                shot_count = 12
            # Native passes the unwrapped `heading - 1.5707964f`: the aim heading
            # for the flamers (stored at 0x00415a29), the shot angle for Bubblegun
            # (0x0041744a).
            case WeaponId.FLAMETHROWER:
                state.particles.spawn_particle(
                    pos=muzzle,
                    angle=x87_pc24_sub(aim_heading, NATIVE_HALF_PI),
                    intensity=1.0,
                    rng=state.rng,
                )
                ammo_cost = f32(0.1)
            case WeaponId.HR_FLAMER:
                particle = state.particles.spawn_particle(
                    pos=muzzle,
                    angle=x87_pc24_sub(aim_heading, NATIVE_HALF_PI),
                    intensity=1.0,
                    rng=state.rng,
                )
                state.particles.entries[particle].style_id = ParticleStyleId.HR_FLAMER
                ammo_cost = f32(0.1)
            case WeaponId.BLOW_TORCH:
                particle = state.particles.spawn_particle(
                    pos=muzzle,
                    angle=x87_pc24_sub(aim_heading, NATIVE_HALF_PI),
                    intensity=1.0,
                    rng=state.rng,
                )
                state.particles.entries[particle].style_id = ParticleStyleId.BLOW_TORCH
                ammo_cost = f32(0.05)
            case (
                WeaponId.PLASMA_RIFLE
                | WeaponId.PULSE_GUN
                | WeaponId.BLADE_GUN
                | WeaponId.SPLITTER_GUN
                | WeaponId.ION_RIFLE
                | WeaponId.ION_MINIGUN
                | WeaponId.ION_CANNON
                | WeaponId.PLASMA_CANNON
                | WeaponId.PLASMA_MINIGUN
                | WeaponId.PLAGUE_SPREADER_GUN
                | WeaponId.RAINBOW_GUN
            ):
                shot.projectile(ProjectileTemplateId(weapon_id), shot_angle)
            case WeaponId.MULTI_PLASMA:
                shot.projectile(ProjectileTemplateId.PLASMA_RIFLE, x87_pc24_sub(shot_angle, f32(0.31415927)))
                shot.projectile(ProjectileTemplateId.PLASMA_MINIGUN, x87_pc24_sub(shot_angle, f32(0.5235988)))
                shot.projectile(ProjectileTemplateId.PLASMA_RIFLE, shot_angle)
                shot.projectile(ProjectileTemplateId.PLASMA_MINIGUN, x87_pc24_add(shot_angle, f32(0.5235988)))
                shot.projectile(ProjectileTemplateId.PLASMA_RIFLE, x87_pc24_add(shot_angle, f32(0.31415927)))
                shot_count = 5
            case WeaponId.ION_SHOTGUN:
                for _ in range(8):
                    jitter = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_ION_SHOTGUN_PELLET_JITTER) % 200 - 100
                    pellet = shot.projectile(ProjectileTemplateId.ION_MINIGUN, _pellet_angle(shot_angle, jitter, 0.0026))
                    speed = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_ION_SHOTGUN_PELLET_SPEED_SCALE) % 80
                    state.projectiles.entries[pellet].speed_scale = _pellet_speed_scale(speed, 1.4)
                shot_count = 8
            case WeaponId.GAUSS_SHOTGUN:
                shot.muzzle_sprite(25.0, 1.0, 0.33)
                shot.muzzle_sprite(15.0, 2.0, 0.263)
                for _ in range(6):
                    jitter = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_GAUSS_SHOTGUN_PELLET_JITTER) % 200 - 100
                    pellet = shot.projectile(ProjectileTemplateId.GAUSS_GUN, _pellet_angle(shot_angle, jitter, 0.002))
                    speed = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_GAUSS_SHOTGUN_PELLET_SPEED_SCALE) % 80
                    state.projectiles.entries[pellet].speed_scale = _pellet_speed_scale(speed, 1.4)
                shot_count = 6
            case WeaponId.GAUSS_GUN:
                shot.muzzle_sprite(25.0, 1.0, 0.33)
                shot.muzzle_sprite(15.0, 2.0, 0.263)
                shot.projectile(ProjectileTemplateId.GAUSS_GUN, shot_angle)
            case WeaponId.ROCKET_LAUNCHER:
                shot.muzzle_sprite(25.0, 1.0, 0.34)
                shot.muzzle_sprite(15.0, 2.0, 0.283)
                shot.secondary(SecondaryProjectileTypeId.ROCKET, shot_angle)
            case WeaponId.MINI_ROCKET_SWARMERS:
                shot.muzzle_sprite(25.0, 1.0, 0.34)
                shot.muzzle_sprite(15.0, 2.0, 0.283)
                # Fires the full clip in a spread. Native spawns one rocket per
                # integer counter step below the float ammo value (ceil), and zero
                # rockets when firing with an empty/negative clip (reachable via
                # Regression Bullets / Ammunition Within).
                clip_ammo = float(player.weapon.ammo)
                rocket_count = math.ceil(clip_ammo) if clip_ammo > 0.0 else 0
                if state.preserve_bugs:
                    # Native bug: step scales by ammo (`ammo * pi/3`), which aliases
                    # to near-identical headings for common clip sizes.
                    step = x87_pc24_mul(clip_ammo, f32(1.0471976))
                    angle = x87_pc24_sub(
                        x87_pc24_sub(shot_angle, NATIVE_PI),
                        x87_pc24_mul(x87_pc24_mul(step, clip_ammo), 0.5),
                    )
                else:
                    # Port fix: spread the clip evenly over 120 degrees, in the same
                    # per-operation f32 steps as the rest of the fire path.
                    spread = x87_pc24_mul(NATIVE_PI, f32(2.0 / 3.0))
                    step = 0.0 if rocket_count <= 1 else x87_pc24_div(spread, float(rocket_count - 1))
                    angle = x87_pc24_sub(shot_angle, x87_pc24_mul(NATIVE_PI, f32(1.0 / 3.0)))
                for _ in range(rocket_count):
                    shot.secondary(SecondaryProjectileTypeId.HOMING_ROCKET, angle)
                    angle = x87_pc24_add(angle, step)
                # Native subtracts the full clip value, zeroing the ammo even when
                # the clip was fractional or negative.
                ammo_cost = clip_ammo
                shot_count = rocket_count
            case WeaponId.ROCKET_MINIGUN:
                shot.muzzle_sprite(25.0, 1.0, 0.34)
                shot.secondary(SecondaryProjectileTypeId.ROCKET_MINIGUN, shot_angle)
            case WeaponId.SEEKER_ROCKETS:
                shot.muzzle_sprite(25.0, 1.0, 0.31)
                shot.muzzle_sprite(15.0, 2.0, 0.243)
                shot.secondary(SecondaryProjectileTypeId.HOMING_ROCKET, shot_angle)
            case WeaponId.MEAN_MINIGUN:
                shot.projectile(ProjectileTemplateId.PISTOL, shot_angle)
            case WeaponId.PLASMA_SHOTGUN:
                for _ in range(14):
                    jitter = (rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_PLASMA_SHOTGUN_PELLET_JITTER) & 0xFF) - 0x80
                    pellet = shot.projectile(
                        ProjectileTemplateId.PLASMA_MINIGUN,
                        _pellet_angle(shot_angle, jitter, 0.002),
                    )
                    speed = rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_PLASMA_SHOTGUN_PELLET_SPEED_SCALE) % 100
                    state.projectiles.entries[pellet].speed_scale = _pellet_speed_scale(speed, 1.0)
                shot_count = 14
            case WeaponId.BUBBLEGUN:
                state.particles.spawn_particle_slow(
                    pos=muzzle,
                    angle=x87_pc24_sub(shot_angle, NATIVE_HALF_PI),
                    rng=state.rng,
                )
                ammo_cost = f32(0.15)
            case _:
                # Native `player_update` has no branch for the other ids (Spider
                # Plasma, Fire Bullets as a weapon, the unused weapons): the shot
                # costs its cooldown, sound and ammo but spawns nothing.
                shot_count = 0

    if 0 <= weapon_id < WEAPON_COUNT_SIZE:
        state.weapon_shots_fired[player.index][weapon_id] += shot_count

    if PerkId.SHARPSHOOTER not in state.perks:
        player.spread_heat = min(f32(0.48), max(0.0, x87_pc24_add(player.spread_heat, spread_inc)))

    muzzle_inc = weapon_spread_heat
    if is_fire_bullets and pellet_count == 1:
        muzzle_inc = fire_bullets_spread_heat
    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha)
    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha + muzzle_inc)
    player.muzzle_flash_alpha = min(0.8, player.muzzle_flash_alpha)

    if state.bonuses.reflex_boost <= 0.0 and not is_fire_bullets:
        # Native allows ammo to cross below zero for reload-time firing paths
        # (for example Regression Bullets), and replay checkpoints rely on that.
        player.weapon.ammo = x87_pc24_sub(player.weapon.ammo, ammo_cost)
    reload_start_gate_open = bool(player.weapon.reload_timer <= 0.0)
    if fire_gate.normal_ready:
        # Alt-weapon same-tick fire uses the pre-swap gate (reload_timer==0) for
        # reload restart eligibility after ammo drains below zero.
        reload_start_gate_open = True
    if player.weapon.ammo <= 0.0 and reload_start_gate_open:
        player_start_reload(player, state)
    return WeaponFireResult(fired=True, shot_count=int(shot_count), ammo_cost=float(ammo_cost))
