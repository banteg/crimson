from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.color import RGBA
from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..creatures.damage import creature_apply_damage
from ..creatures.damage_types import CreatureDamageType
from ..math_parity import (
    f32,
    native_chain_angle_from_delta,
    x87_pc24_add,
    x87_pc24_mul,
    x87_pc24_sqrt,
    x87_pc24_sub,
)
from ..owner_ref import OwnerRef
from ..perks import PerkId
from ..projectiles.runtime.collision import creature_find_nearest_alive
from ..projectiles.types import ProjectileTemplateId
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import PlayerState
from ..weapon_runtime.assign import weapon_assign_player
from ..weapon_runtime.spawn import owner_ref_for_player, projectile_spawn, spawn_projectile_ring
from ..weapons import WeaponId
from .hud import bonus_timer_values
from .ids import BONUS_BY_ID, BonusId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureState
    from ..sim.world_state import WorldStepRuntime

# `bonus_apply` (crimsonland.exe @ 0x00409890) starts the Nuke screen shake.
NUKE_CAMERA_SHAKE_PULSES = 0x14
NUKE_CAMERA_SHAKE_TIMER = f32(0.2)


def _activate_hud_slot(state: GameplayState, players: list[PlayerState], bonus_id: BonusId) -> None:
    # `bonus_hud_slot_activate` runs only while no timer of this bonus is live.
    if any(timer > 0.0 for timer in bonus_timer_values(state, players, bonus_id)):
        return
    meta = BONUS_BY_ID[bonus_id]
    state.bonus_hud.register(bonus_id, label=meta.name, icon_id=int(meta.icon_id) if meta.icon_id is not None else -1)


def bonus_apply(
    state: GameplayState,
    player: PlayerState,
    bonus_id: BonusId,
    *,
    amount: int,
    origin: Vec2,
    creatures: Sequence[CreatureState],
    players: list[PlayerState],
    detail_preset: int = 5,
    step_runtime: WorldStepRuntime,
) -> None:
    """Port of `bonus_apply` (0x00409890)."""

    meta = BONUS_BY_ID.get(bonus_id)
    if meta is None:
        return
    multiplier = 1.5 if PerkId.BONUS_ECONOMIST in state.perks else 1.0
    player_owner = owner_ref_for_player(player.index) if state.friendly_fire_enabled else OwnerRef.from_local_player(0)

    match bonus_id:
        case BonusId.WEAPON:
            # The old weapon is never stashed: the alt slot is preloaded with a
            # pistol at player reset.
            weapon_assign_player(player, WeaponId(amount), state=state)

        case BonusId.MEDIKIT:
            if float(player.health) < 100.0:
                player.health = min(100.0, f32(float(player.health) + 10.0))

        case BonusId.REFLEX_BOOST:
            old = float(state.bonuses.reflex_boost)
            _activate_hud_slot(state, players, bonus_id)
            state.bonuses.reflex_boost = f32(old + float(amount) * multiplier)
            for target in players:
                target.weapon.ammo = float(target.weapon.clip_size)
                target.weapon.reload_timer = 0.0
            state.effects.spawn_ring(pos=origin, detail_preset=detail_preset, color=RGBA(0.6, 0.6, 1.0, 1.0))

        case BonusId.WEAPON_POWER_UP:
            old = float(state.bonuses.weapon_power_up)
            _activate_hud_slot(state, players, bonus_id)
            state.bonuses.weapon_power_up = f32(old + float(amount) * multiplier)
            player.weapon_reset_latch = 0
            player.weapon.shot_cooldown = 0.0
            player.weapon.reload_timer = 0.0
            player.weapon.ammo = float(player.weapon.clip_size)

        case BonusId.SPEED:
            _activate_hud_slot(state, players, bonus_id)
            player.speed_bonus_timer = f32(float(player.speed_bonus_timer) + float(amount) * multiplier)

        case BonusId.FREEZE:
            old = float(state.bonuses.freeze)
            _activate_hud_slot(state, players, bonus_id)
            state.bonuses.freeze = f32(old + float(amount) * multiplier)
            # Every active corpse shatters, including kills earlier in this tick
            # and entries below the normal despawn threshold.
            for creature in creatures:
                if not creature.active or creature.hp > 0.0:
                    continue
                for _ in range(8):
                    angle = float(state.rng.rand_tagged(RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE) % 612) * 0.01
                    state.effects.spawn_freeze_shard(
                        pos=creature.pos, angle=angle, rng=state.rng, detail_preset=detail_preset,
                    )
                angle = float(state.rng.rand_tagged(RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE) % 612) * 0.01
                state.effects.spawn_freeze_shatter(
                    pos=creature.pos, angle=angle, rng=state.rng, detail_preset=detail_preset,
                )
                creature.active = False
            state.effects.spawn_ring(pos=origin, detail_preset=detail_preset, color=RGBA(0.3, 0.5, 0.8, 1.0))
            state.sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, origin))

        case BonusId.SHIELD:
            _activate_hud_slot(state, players, bonus_id)
            player.shield_timer = f32(float(player.shield_timer) + float(amount) * multiplier)

        case BonusId.SHOCK_CHAIN:
            target_idx = creature_find_nearest_alive(
                creatures=creatures, origin=origin, preserve_bugs=bool(state.preserve_bugs),
            )
            if target_idx >= 0:
                target = creatures[target_idx]
                angle = native_chain_angle_from_delta(
                    dx=x87_pc24_sub(target.pos.x, origin.x),
                    dy=x87_pc24_sub(target.pos.y, origin.y),
                )
                state.bonus_spawn_guard = True
                state.shock_chain_links_left = 0x20
                state.shock_chain_projectile_id = projectile_spawn(
                    state,
                    players=players,
                    pos=origin,
                    angle=angle,
                    type_id=ProjectileTemplateId.ION_RIFLE,
                    owner=player_owner,
                    owner_player_index=player.index,
                )
                state.bonus_spawn_guard = False
                state.sfx_queue.append(SfxRequest(SfxId.SHOCK_HIT_01, origin))

        case BonusId.FIREBLAST:
            state.bonus_spawn_guard = True
            spawn_projectile_ring(
                state,
                origin,
                count=16,
                angle_offset=0.0,
                type_id=ProjectileTemplateId.PLASMA_RIFLE,
                owner=player_owner,
                owner_player_index=player.index,
                players=players,
            )
            state.bonus_spawn_guard = False
            state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_MEDIUM, origin))

        case BonusId.FIRE_BULLETS:
            _activate_hud_slot(state, players, bonus_id)
            player.fire_bullets_timer = f32(float(player.fire_bullets_timer) + 5.0 * multiplier)
            player.weapon_reset_latch = 0
            player.weapon.shot_cooldown = 0.0
            player.weapon.reload_timer = 0.0
            player.weapon.ammo = float(player.weapon.clip_size)

        case BonusId.ENERGIZER:
            old = float(state.bonuses.energizer)
            _activate_hud_slot(state, players, bonus_id)
            state.bonuses.energizer = f32(old + 8.0 * multiplier)

        case BonusId.DOUBLE_EXPERIENCE:
            old = float(state.bonuses.double_experience)
            _activate_hud_slot(state, players, bonus_id)
            state.bonuses.double_experience = f32(old + 6.0 * multiplier)

        case BonusId.NUKE:
            state.camera_shake_pulses = NUKE_CAMERA_SHAKE_PULSES
            state.camera_shake_timer = NUKE_CAMERA_SHAKE_TIMER
            rng = state.rng
            bullet_count = (int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_BULLET_COUNT)) & 3) + 4
            for _ in range(bullet_count):
                angle = x87_pc24_mul(
                    float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_ANGLE)) % 628), f32(0.01),
                )
                proj_id = projectile_spawn(
                    state,
                    players=players,
                    pos=origin,
                    angle=float(angle),
                    type_id=ProjectileTemplateId.PISTOL,
                    owner=OwnerRef.from_local_player(0),
                    owner_player_index=player.index,
                )
                if proj_id != -1:
                    speed_scale = x87_pc24_add(
                        x87_pc24_mul(
                            float(int(rng.rand_tagged(RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_SPEED_SCALE)) % 50),
                            f32(0.01),
                        ),
                        f32(0.5),
                    )
                    projectile = state.projectiles.entries[proj_id]
                    projectile.speed_scale = x87_pc24_mul(projectile.speed_scale, speed_scale)
            for caller in (RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_1, RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_2):
                gauss_angle = x87_pc24_mul(float(int(rng.rand_tagged(caller)) % 628), f32(0.01))
                projectile_spawn(
                    state,
                    players=players,
                    pos=origin,
                    angle=float(gauss_angle),
                    type_id=ProjectileTemplateId.GAUSS_GUN,
                    owner=OwnerRef.from_local_player(0),
                    owner_player_index=player.index,
                )
            state.effects.spawn_explosion_burst(pos=origin, scale=1.0, rng=rng, detail_preset=int(detail_preset))
            state.bonus_spawn_guard = True
            for idx, creature in enumerate(creatures):
                # Corpses take the blast too, which shrinks them faster.
                if not creature.active:
                    continue
                dx = x87_pc24_sub(creature.pos.x, origin.x)
                dy = x87_pc24_sub(creature.pos.y, origin.y)
                if abs(dx) > 256.0 or abs(dy) > 256.0:
                    continue
                distance = x87_pc24_sqrt(x87_pc24_add(x87_pc24_mul(dx, dx), x87_pc24_mul(dy, dy)))
                damage_base = x87_pc24_sub(256.0, distance)
                if damage_base > 0.0:
                    creature_apply_damage(
                        step_runtime,
                        idx,
                        x87_pc24_mul(damage_base, 5.0),
                        CreatureDamageType.EXPLOSION,
                        Vec2(),
                        owner_ref_for_player(player.index),
                    )
            state.bonus_spawn_guard = False
            state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_LARGE, origin))
            state.sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, origin))

        case BonusId.POINTS:
            players[0].experience += int(amount)

    # The pickup burst draws RNG before `bonus_apply` returns, so it precedes
    # any later pickup applied in the same `bonus_update` pass.
    if bonus_id != BonusId.NUKE:
        state.effects.spawn_burst(
            pos=origin,
            count=12,
            rng=state.rng,
            detail_preset=int(detail_preset),
            lifetime=0.4,
            scale_step=0.1,
            color=RGBA(0.4, 0.5, 1.0, 0.5),
            rotation_caller=RngCallerStatic.BONUS_APPLY_PICKUP_BURST_ROTATION,
            vel_x_caller=RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_X,
            vel_y_caller=RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_Y,
        )
