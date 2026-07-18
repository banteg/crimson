from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike

from ..math_parity import (
    NATIVE_PI,
    f32,
    native_fire_muzzle_pos,
    native_shot_angle_from_jitter_draws,
    x87_pc24_add,
    x87_pc24_mul,
    x87_pc24_sub,
)
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..player_damage import PlayerDeathRuntime
from ..projectiles.runtime import SecondarySpawnSpec
from ..projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from ..rng_caller_static import RngCallerStatic
from ..sim.input import PlayerInput
from ..sim.state_types import GameplayState, PlayerState
from ..weapons import WEAPON_TABLE, WeaponId, weapon_entry_for_projectile_type_id
from .assign import player_start_reload, weapon_entry
from .fire_recipes import (
    MaskCenteredJitter,
    ModuloCenteredJitter,
    ModuloSpeedScale,
    MultiPlasmaFanMode,
    NoJitter,
    NoSpeedScale,
    ParticleStreamMode,
    PrimaryPelletsMode,
    SecondaryShotMode,
    SwarmerDumpMode,
    UseAimTargetHint,
    resolve_fire_recipe,
)
from .spawn import owner_ref_for_player, owner_ref_for_player_projectiles, travel_budget_for_type_id

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureState

WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1

_NATIVE_FIRE_MUZZLE_SPRITES: dict[int, tuple[tuple[float, float, float], ...]] = {
    WeaponId.PISTOL: ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    WeaponId.ASSAULT_RIFLE: ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    WeaponId.SHOTGUN: ((25.0, 1.0, 0.25), (15.0, 2.0, 0.223)),
    WeaponId.SAWED_OFF_SHOTGUN: ((25.0, 1.0, 0.26), (15.0, 2.0, 0.233)),
    WeaponId.SUBMACHINE_GUN: ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    WeaponId.GAUSS_GUN: ((25.0, 1.0, 0.33), (15.0, 2.0, 0.263)),
    WeaponId.ROCKET_LAUNCHER: ((25.0, 1.0, 0.34), (15.0, 2.0, 0.283)),
    WeaponId.SEEKER_ROCKETS: ((25.0, 1.0, 0.31), (15.0, 2.0, 0.243)),
    WeaponId.MINI_ROCKET_SWARMERS: ((25.0, 1.0, 0.34), (15.0, 2.0, 0.283)),
    WeaponId.ROCKET_MINIGUN: ((25.0, 1.0, 0.34),),
    WeaponId.JACKHAMMER: ((15.0, 2.0, 0.223),),
    WeaponId.SHRINKIFIER_5K: ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    WeaponId.GAUSS_SHOTGUN: ((25.0, 1.0, 0.33), (15.0, 2.0, 0.263)),
}

_NATIVE_FIRE_MUZZLE_AFTER_PROJECTILE: frozenset[int] = frozenset(
    {
        WeaponId.PISTOL,
        WeaponId.SHRINKIFIER_5K,
    },
)

_PELLET_JITTER_CALLER_BY_WEAPON: dict[WeaponId, int] = {
    WeaponId.SHOTGUN: RngCallerStatic.PLAYER_UPDATE_SHOTGUN_PELLET_JITTER,
    WeaponId.SAWED_OFF_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_SAWED_OFF_SHOTGUN_PELLET_JITTER,
    WeaponId.JACKHAMMER: RngCallerStatic.PLAYER_UPDATE_JACKHAMMER_PELLET_JITTER,
    WeaponId.ION_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_ION_SHOTGUN_PELLET_JITTER,
    WeaponId.GAUSS_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_GAUSS_SHOTGUN_PELLET_JITTER,
    WeaponId.PLASMA_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_PLASMA_SHOTGUN_PELLET_JITTER,
}

_PELLET_SPEED_SCALE_CALLER_BY_WEAPON: dict[WeaponId, int] = {
    WeaponId.SHOTGUN: RngCallerStatic.PLAYER_UPDATE_SHOTGUN_PELLET_SPEED_SCALE,
    WeaponId.SAWED_OFF_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_SAWED_OFF_SHOTGUN_PELLET_SPEED_SCALE,
    WeaponId.JACKHAMMER: RngCallerStatic.PLAYER_UPDATE_JACKHAMMER_PELLET_SPEED_SCALE,
    WeaponId.ION_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_ION_SHOTGUN_PELLET_SPEED_SCALE,
    WeaponId.GAUSS_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_GAUSS_SHOTGUN_PELLET_SPEED_SCALE,
    WeaponId.PLASMA_SHOTGUN: RngCallerStatic.PLAYER_UPDATE_PLASMA_SHOTGUN_PELLET_SPEED_SCALE,
}


class WeaponFireCtx(msgspec.Struct):
    player: PlayerState
    input_state: PlayerInput
    dt: float
    state: GameplayState
    detail_preset: int = 5
    creatures: Sequence[CreatureState] | None = None
    players: Sequence[PlayerState] | None = None
    force_pre_swap_fire_gate: bool = False
    player_death_runtime: PlayerDeathRuntime | None = None


class WeaponFireResult(msgspec.Struct, frozen=True):
    fired: bool
    shot_count: int = 0
    ammo_cost: float = 0.0


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
        # Native uses raw (cos h, sin h) of the aim heading - the aim direction
        # rotated 90 degrees - matching the Fire Cough and shell-casing ports.
        state.sprite_effects.spawn(
            pos=muzzle,
            vel=Vec2.from_angle(aim_heading) * float(speed),
            scale=float(scale),
            color=RGBA(0.5, 0.5, 0.5, float(alpha)),
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


def _apply_pellet_jitter(
    *,
    shot_angle: float,
    rng: CrandLike,
    jitter_rule: ModuloCenteredJitter | MaskCenteredJitter,
    caller: int,
) -> float:
    match jitter_rule:
        case ModuloCenteredJitter(modulo=modulo, center=center, step=step):
            return float(shot_angle) + float(
                rng.rand_tagged(caller) % int(modulo) - int(center),
            ) * float(step)
        case MaskCenteredJitter(mask=mask, center=center, step=step):
            return float(shot_angle) + float(
                (rng.rand_tagged(caller) & int(mask)) - int(center),
            ) * float(step)


def _apply_speed_scale_rule(
    *,
    state: GameplayState,
    proj_id: int,
    speed_rule: NoSpeedScale | ModuloSpeedScale,
    caller: int,
) -> None:
    match speed_rule:
        case NoSpeedScale():
            return
        case ModuloSpeedScale(base=base, modulo=modulo, step=step):
            state.projectiles.entries[int(proj_id)].speed_scale = float(base) + float(
                state.rng.rand_tagged(caller) % int(modulo),
            ) * float(step)


def fire_weapon(ctx: WeaponFireCtx) -> WeaponFireResult:
    player = ctx.player
    input_state = ctx.input_state
    dt = float(ctx.dt)
    state = ctx.state
    creatures = ctx.creatures
    players = ctx.players
    force_pre_swap_fire_gate = bool(ctx.force_pre_swap_fire_gate)
    player_death_runtime = ctx.player_death_runtime
    perk_player = players[0] if state.preserve_bugs and players else player

    weapon_id = player.weapon.weapon_id
    weapon = weapon_entry(weapon_id)

    if (not force_pre_swap_fire_gate) and player.weapon.shot_cooldown > 0.0:
        return WeaponFireResult(fired=False)
    if not input_state.fire_down:
        return WeaponFireResult(fired=False)

    ammo_cost = 1.0
    is_fire_bullets = float(player.fire_bullets_timer) > 0.0
    if (not force_pre_swap_fire_gate) and player.weapon.reload_timer > 0.0:
        if player.experience <= 0:
            return WeaponFireResult(fired=False)
        if perk_active(perk_player, PerkId.REGRESSION_BULLETS):
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            reload_time = float(weapon.reload_time)
            factor = 4.0 if ammo_class == 1 else 200.0
            player.experience = int(float(player.experience) - reload_time * factor)
            if player.experience < 0:
                player.experience = 0
        elif perk_active(perk_player, PerkId.AMMUNITION_WITHIN):
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            from ..player_damage import player_take_damage

            cost = 0.15 if ammo_class == 1 else 1.0
            player_take_damage(
                state,
                player,
                cost,
                dt=dt,
                players=players,
                death_runtime=player_death_runtime,
            )
        else:
            return WeaponFireResult(fired=False)

    pellet_count = int(weapon.pellet_count)
    fire_bullets_weapon = weapon_entry_for_projectile_type_id(ProjectileTemplateId.FIRE_BULLETS)

    shot_cooldown = float(f32(float(weapon.shot_cooldown)))
    weapon_spread_heat = float(weapon.spread_heat_inc)
    fire_bullets_spread_heat = float(fire_bullets_weapon.spread_heat_inc)

    if is_fire_bullets and pellet_count == 1:
        shot_cooldown = float(f32(float(fire_bullets_weapon.shot_cooldown)))

    spread_heat_base = fire_bullets_spread_heat if is_fire_bullets else weapon_spread_heat
    spread_inc = x87_pc24_mul(spread_heat_base, f32(1.3))

    if perk_active(perk_player, PerkId.FASTSHOT):
        shot_cooldown = float(f32(float(shot_cooldown) * 0.88))
    if perk_active(perk_player, PerkId.SHARPSHOOTER):
        shot_cooldown = float(f32(float(shot_cooldown) * 1.05))
    player.weapon.shot_cooldown = max(0.0, float(f32(float(shot_cooldown))))

    aim = input_state.aim
    # `player_update` computes and stores aim_heading before entering the fire
    # branch; later muzzle and presentation math reload that exact float field.
    aim_heading = float(f32(player.aim_heading))

    muzzle = native_fire_muzzle_pos(player.pos, aim_heading)
    weapon_flags = int(weapon.flags or 0)
    if weapon_flags & 0x1:
        # Native gameplay fire uses four exact `player_update` RNG sites for
        # the casing effect before the later shot-angle jitter work.
        shell_casing_draws = (
            state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_ANGLE),
            state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_SPEED),
            state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_ROTATION),
            state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_ROTATION_STEP),
        )
        state.effects.spawn_shell_casing(
            pos=muzzle,
            aim_heading=aim_heading,
            draws=shell_casing_draws,
            detail_preset=int(ctx.detail_preset),
        )

    shot_angle = _native_shot_angle_with_jitter(
        aim=aim,
        player_pos=player.pos,
        spread_heat=float(player.spread_heat),
        rng=state.rng,
    )
    particle_angle = Vec2.from_heading(shot_angle).to_angle()
    if weapon_id in (WeaponId.FLAMETHROWER, WeaponId.BLOW_TORCH, WeaponId.HR_FLAMER):
        particle_angle = Vec2.from_heading(aim_heading).to_angle()

    # Native gameplay fire consumes one exact `player_update` RNG draw for shot
    # SFX variant selection on every non-Fire-Bullets shot.
    if not is_fire_bullets:
        state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_SHOT_SFX)

    owner = owner_ref_for_player(player.index)
    projectile_owner = owner_ref_for_player_projectiles(state, player.index)
    # Native encodes friendly fire in the owner id (-1 - player_index): with the
    # cvar enabled, primary player shots can hit other players for 10 damage.
    projectile_hits_players = bool(state.friendly_fire_enabled)
    shot_count = 1
    # Native increments the accuracy counter only inside projectile_spawn /
    # fx_spawn_secondary_projectile; particle weapons (flamethrowers, bubblegun)
    # never count toward shots fired. The per-weapon usage counter keeps
    # incrementing as the rewrite's most-used-weapon heuristic.
    counts_accuracy_shots = True
    spawn_muzzle_after_projectile = bool(is_fire_bullets) or int(weapon_id) in _NATIVE_FIRE_MUZZLE_AFTER_PROJECTILE
    if not spawn_muzzle_after_projectile:
        _spawn_native_fire_muzzle_sprites(
            state=state,
            weapon_id=int(weapon_id),
            muzzle=muzzle,
            aim_heading=float(aim_heading),
            fire_bullets_active=bool(is_fire_bullets),
        )

    recipe = resolve_fire_recipe(
        weapon_id=weapon_id,
        pellet_count=pellet_count,
        fire_bullets_active=is_fire_bullets,
    )
    ammo_cost = float(recipe.ammo_cost)

    match recipe.mode:
        case PrimaryPelletsMode(type_id=type_id, count=count, jitter=jitter_rule, speed_scale=speed_rule):
            if type_id is None:
                raise ValueError(f"missing projectile type in recipe for weapon {int(weapon_id)}")
            pellets = max(0, int(count if count is not None else 0))
            shot_count = pellets
            meta = travel_budget_for_type_id(type_id)
            pellet_jitter_caller = (
                RngCallerStatic.PLAYER_UPDATE_FIRE_BULLETS_PELLET_JITTER
                if is_fire_bullets
                else _PELLET_JITTER_CALLER_BY_WEAPON.get(WeaponId(weapon_id))
            )
            pellet_speed_caller = _PELLET_SPEED_SCALE_CALLER_BY_WEAPON.get(WeaponId(weapon_id))
            if not isinstance(speed_rule, NoSpeedScale) and pellet_speed_caller is None:
                raise ValueError(f"missing pellet speed caller for weapon {int(weapon_id)}")
            for _ in range(pellets):
                match jitter_rule:
                    case NoJitter():
                        angle = float(shot_angle)
                    case ModuloCenteredJitter() | MaskCenteredJitter():
                        if pellet_jitter_caller is None:
                            raise ValueError(f"missing pellet jitter caller for weapon {int(weapon_id)}")
                        angle = _apply_pellet_jitter(
                            shot_angle=float(shot_angle),
                            rng=state.rng,
                            jitter_rule=jitter_rule,
                            caller=int(pellet_jitter_caller),
                        )
                proj_id = state.projectiles.spawn(
                    pos=muzzle,
                    angle=angle,
                    type_id=type_id,
                    owner=projectile_owner,
                    travel_budget=meta,
                    hits_players=projectile_hits_players,
                )
                if isinstance(speed_rule, ModuloSpeedScale):
                    assert pellet_speed_caller is not None
                    _apply_speed_scale_rule(
                        state=state,
                        proj_id=int(proj_id),
                        speed_rule=speed_rule,
                        caller=int(pellet_speed_caller),
                    )
        case SecondaryShotMode(type_id=type_id, targeting=targeting):
            target_hint = None
            spawn_creatures = None
            match targeting:
                case UseAimTargetHint():
                    target_hint = aim
                    spawn_creatures = creatures
                case _:
                    pass
            state.secondary_projectiles.spawn_from_spec(
                SecondarySpawnSpec(
                    pos=muzzle,
                    angle=shot_angle,
                    type_id=type_id,
                    owner=projectile_owner,
                    target_hint=target_hint,
                    creatures=spawn_creatures,
                    preserve_bugs=bool(state.preserve_bugs),
                ),
            )
        case ParticleStreamMode(style=style, slow=slow):
            counts_accuracy_shots = False
            if slow:
                state.particles.spawn_particle_slow(
                    pos=muzzle,
                    angle=Vec2.from_heading(shot_angle).to_angle(),
                    owner=owner,
                )
            else:
                particle_id = state.particles.spawn_particle(
                    pos=muzzle,
                    angle=particle_angle,
                    intensity=1.0,
                    owner=owner,
                )
                if style is not None:
                    state.particles.entries[particle_id].style_id = style
        case MultiPlasmaFanMode():
            # Multi-Plasma: 5-shot fixed spread using type 0x09 and 0x0B.
            shot_count = 5
            spread_small = f32(0.31415927)
            spread_large = f32(0.5235988)
            patterns: tuple[tuple[float, ProjectileTemplateId], ...] = (
                (x87_pc24_sub(shot_angle, spread_small), ProjectileTemplateId.PLASMA_RIFLE),
                (x87_pc24_sub(shot_angle, spread_large), ProjectileTemplateId.PLASMA_MINIGUN),
                (shot_angle, ProjectileTemplateId.PLASMA_RIFLE),
                (x87_pc24_add(shot_angle, spread_large), ProjectileTemplateId.PLASMA_MINIGUN),
                (x87_pc24_add(shot_angle, spread_small), ProjectileTemplateId.PLASMA_RIFLE),
            )
            for angle, type_id in patterns:
                state.projectiles.spawn(
                    pos=muzzle,
                    angle=angle,
                    type_id=type_id,
                    owner=projectile_owner,
                    travel_budget=travel_budget_for_type_id(type_id),
                    hits_players=projectile_hits_players,
                )
        case SwarmerDumpMode():
            # Mini-Rocket Swarmers -> secondary type 2 (fires the full clip in a spread).
            # Native spawns one rocket per integer counter step below the float ammo
            # value (ceil), and zero rockets when firing with an empty/negative clip
            # (reachable via Regression Bullets / Ammunition Within).
            clip_ammo = float(player.weapon.ammo)
            rocket_count = math.ceil(clip_ammo) if clip_ammo > 0.0 else 0
            preserve_swarmer_bug = bool(state.preserve_bugs)
            if preserve_swarmer_bug:
                # Native bug: step scales by ammo (`ammo * pi/3`), which aliases
                # to near-identical headings for common clip sizes.
                step = x87_pc24_mul(clip_ammo, f32(1.0471976))
                angle = x87_pc24_sub(
                    x87_pc24_sub(shot_angle, NATIVE_PI),
                    x87_pc24_mul(x87_pc24_mul(step, clip_ammo), 0.5),
                )
            else:
                spread = math.pi * (2.0 / 3.0)
                step = 0.0 if rocket_count <= 1 else spread / float(rocket_count - 1)
                angle = shot_angle - spread * 0.5
            for _ in range(rocket_count):
                state.secondary_projectiles.spawn_from_spec(
                    SecondarySpawnSpec(
                        pos=muzzle,
                        angle=angle,
                        type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
                        owner=projectile_owner,
                        target_hint=aim,
                        creatures=creatures,
                        preserve_bugs=bool(state.preserve_bugs),
                    ),
                )
                angle = x87_pc24_add(angle, step) if preserve_swarmer_bug else angle + step
            # Native subtracts the full clip value, zeroing the ammo even when
            # the clip was fractional or negative.
            ammo_cost = clip_ammo
            shot_count = rocket_count

    if 0 <= int(player.index) < len(state.shots_fired):
        if counts_accuracy_shots:
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

    if not perk_active(perk_player, PerkId.SHARPSHOOTER):
        player.spread_heat = min(f32(0.48), max(0.0, x87_pc24_add(player.spread_heat, spread_inc)))

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
        player.weapon.ammo = float(player.weapon.ammo) - float(ammo_cost)
    reload_start_gate_open = bool(player.weapon.reload_timer <= 0.0)
    if force_pre_swap_fire_gate:
        # Alt-weapon same-tick fire uses the pre-swap gate (reload_timer==0) for
        # reload restart eligibility after ammo drains below zero.
        reload_start_gate_open = True
    if player.weapon.ammo <= 0.0 and reload_start_gate_open:
        player_start_reload(player, state, players=ctx.players)
    return WeaponFireResult(fired=True, shot_count=int(shot_count), ammo_cost=float(ammo_cost))
