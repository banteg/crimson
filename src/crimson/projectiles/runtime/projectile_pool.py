from __future__ import annotations

import math
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ...collision_math import within_native_find_radius
from ...creatures.damage import creatures_apply_radius_damage
from ...creatures.damage_types import CreatureDamageType
from ...creatures.lifecycle import creature_lifecycle_is_alive, creature_lifecycle_is_collidable
from ...creatures.spawn_ids import CreatureFlags
from ...math_parity import (
    NATIVE_HALF_PI,
    f32,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_hypot,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ...owner_ref import OwnerRef
from ...perks import PerkId
from ...rng_caller_static import RngCallerStatic
from ...sim.state_types import TERRAIN_SIZE
from ...weapons import weapon_entry_for_projectile_type_id
from ..types import (
    MAIN_PROJECTILE_POOL_SIZE,
    Projectile,
    ProjectileCollisionProfile,
    ProjectileHit,
    ProjectileTemplateId,
)
from .behaviors import (
    _post_hit_ion_common,
    _post_hit_ion_rifle,
    _post_hit_plague_spreader,
    _post_hit_plasma_cannon,
    _post_hit_pulse_gun,
    _post_hit_shrinkifier,
    _pre_hit_splitter,
    _ProjectileHitInfo,
    _ProjectileUpdateCtx,
)
from .collision import _apply_damage_to_creature
from .spatial_hash import CreatureSpatialHash

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState
    from ...sim.world_state import WorldStepRuntime


class PrimaryStepCtx(msgspec.Struct, frozen=True):
    step_runtime: WorldStepRuntime
    dt: float


_DEFAULT_PROJECTILE_COLLISION_PROFILE = ProjectileCollisionProfile(
    hit_radius=1.0,
    initial_damage_pool=1.0,
)

_PROJECTILE_COLLISION_PROFILE_BY_TYPE_ID: dict[ProjectileTemplateId, ProjectileCollisionProfile] = {
    ProjectileTemplateId.ION_MINIGUN: ProjectileCollisionProfile(hit_radius=3.0, initial_damage_pool=1.0),
    ProjectileTemplateId.ION_RIFLE: ProjectileCollisionProfile(hit_radius=5.0, initial_damage_pool=1.0),
    ProjectileTemplateId.ION_CANNON: ProjectileCollisionProfile(hit_radius=10.0, initial_damage_pool=1.0),
    ProjectileTemplateId.PLASMA_CANNON: ProjectileCollisionProfile(hit_radius=10.0, initial_damage_pool=1.0),
    ProjectileTemplateId.GAUSS_GUN: ProjectileCollisionProfile(hit_radius=1.0, initial_damage_pool=300.0),
    ProjectileTemplateId.FIRE_BULLETS: ProjectileCollisionProfile(hit_radius=1.0, initial_damage_pool=240.0),
    ProjectileTemplateId.BLADE_GUN: ProjectileCollisionProfile(hit_radius=1.0, initial_damage_pool=50.0),
}


def _projectile_damage_amount_f32(dist: float, damage_scale: float) -> float:
    """Mirror native PC_24 arithmetic stores in the projectile damage formula."""

    distance = f32(float(dist))
    if distance < 50.0:
        distance = 50.0
    damage = f32(100.0 / float(distance))
    damage = f32(float(damage) * float(f32(float(damage_scale))))
    damage = f32(float(damage) * 30.0)
    damage = f32(float(damage) + 10.0)
    return f32(float(damage) * float(f32(0.95)))


def _stop_on_hit_jitter_axis_f32(direction: float, jitter: int, pos: float) -> float:
    offset = x87_pc24_mul(direction, float(jitter))
    return x87_pc24_add(offset, pos)


def projectile_collision_profile(type_id: ProjectileTemplateId) -> ProjectileCollisionProfile:
    return _PROJECTILE_COLLISION_PROFILE_BY_TYPE_ID.get(
        type_id,
        _DEFAULT_PROJECTILE_COLLISION_PROFILE,
    )


class ProjectilePool:
    def __init__(self) -> None:
        self._entries = [Projectile() for _ in range(MAIN_PROJECTILE_POOL_SIZE)]

    @property
    def entries(self) -> list[Projectile]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.generation = 0
            entry.active = False

    def spawn(
        self,
        *,
        pos: Vec2,
        angle: float,
        type_id: ProjectileTemplateId,
        owner: OwnerRef,
        hits_players: bool = False,
    ) -> int:
        index = None
        for i, entry in enumerate(self._entries):
            if not entry.active:
                index = i
                break
        if index is None:
            index = len(self._entries) - 1
        entry = self._entries[index]

        entry.generation += 1
        entry.active = True
        # Native projectile spawn writes angle/pos as float32 fields; keep those
        # stores narrowed so next-tick movement uses the same precision.
        angle_f32 = float(f32(float(angle)))
        pos_f32 = Vec2(float(f32(float(pos.x))), float(f32(float(pos.y))))
        entry.angle = angle_f32
        entry.pos = pos_f32
        entry.origin = pos_f32
        entry.vel = Vec2(
            float(f32(math.cos(float(angle_f32)) * 1.5)),
            float(f32(math.sin(float(angle_f32)) * 1.5)),
        )
        entry.type_id = type_id
        # Native stores the f32 literal 0.4.
        entry.life_timer = float(f32(0.4))
        entry.reserved = 0.0
        entry.speed_scale = 1.0
        weapon_entry = weapon_entry_for_projectile_type_id(type_id)
        entry.travel_budget = float(weapon_entry.travel_budget)
        entry.owner = owner
        entry.hits_players = bool(hits_players)

        collision_profile = projectile_collision_profile(type_id)
        entry.hit_radius = float(collision_profile.hit_radius)
        entry.damage_pool = float(collision_profile.initial_damage_pool)
        return index

    def iter_active(self) -> list[Projectile]:
        return [entry for entry in self._entries if entry.active]

    def step(self, ctx: PrimaryStepCtx) -> list[ProjectileHit]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.
        """
        dt = float(f32(float(ctx.dt)))
        step_runtime = ctx.step_runtime
        world = step_runtime.world
        creatures = world.creatures.entries
        detail_preset = int(step_runtime.world.state.detail_preset)
        runtime_state = world.state
        rng = runtime_state.rng
        players = world.players

        if dt <= 0.0:
            return []

        perks = runtime_state.perks
        barrel_greaser_active = PerkId.BARREL_GREASER in perks
        ion_gun_master_active = PerkId.ION_GUN_MASTER in perks
        poison_bullets_active = PerkId.POISON_BULLETS in perks
        # Native `ion_damage_scale` is the float 1.2f under Ion Gun Master.
        ion_scale = f32(1.2) if ion_gun_master_active else 1.0

        effects = runtime_state.effects
        sfx_queue = runtime_state.sfx_queue

        hits: list[ProjectileHit] = []
        margin = 64.0

        def _creature_is_collidable(creature: CreatureState) -> bool:
            if not creature.active:
                return False
            return creature_lifecycle_is_collidable(creature.lifecycle_stage)

        creature_spatial = CreatureSpatialHash(pool=world.creatures, is_collidable=_creature_is_collidable)

        def _damage_scale(type_id: int) -> float:
            return float(weapon_entry_for_projectile_type_id(ProjectileTemplateId(type_id)).damage_scale)

        def _damage_distance_f32(origin: Vec2, pos: Vec2) -> float:
            dx = float(f32(float(origin.x) - float(pos.x)))
            dy = float(f32(float(origin.y) - float(pos.y)))
            dist_sq = float(f32(float(f32(float(dx) * float(dx))) + float(f32(float(dy) * float(dy)))))
            return float(f32(math.sqrt(float(dist_sq))))

        def _damage_type_for() -> int:
            return int(CreatureDamageType.BULLET)

        update_ctx = _ProjectileUpdateCtx(
            pool=self,
            creatures=creatures,
            dt=float(dt),
            detail_preset=int(detail_preset),
            rng=rng,
            runtime_state=runtime_state,
            effects=effects,
            sfx_queue=sfx_queue,
            step_runtime=step_runtime,
            sync_creature_index=creature_spatial.sync_index,
        )

        def _reset_shock_chain_if_owner(index: int) -> None:
            if runtime_state.shock_chain_projectile_id != index:
                return
            runtime_state.shock_chain_projectile_id = -1
            runtime_state.shock_chain_links_left = 0

        for proj_index, proj in enumerate(self._entries):
            if not proj.active:
                continue
            if proj.life_timer <= 0.0:
                proj.active = False
                # Native `projectile_update` clears the active flag but still
                # runs this tick's life_timer branch, so expired ion projectiles
                # can apply one final linger AoE pass.

            if proj.life_timer < 0.4:
                match proj.type_id:
                    case ProjectileTemplateId.ION_RIFLE | ProjectileTemplateId.ION_MINIGUN:
                        _reset_shock_chain_if_owner(proj_index)
                        proj.life_timer = x87_pc24_sub(proj.life_timer, dt)
                        if proj.type_id == ProjectileTemplateId.ION_RIFLE:
                            radius, damage = x87_pc24_mul(ion_scale, 88.0), x87_pc24_mul(dt, 100.0)
                        else:
                            radius, damage = x87_pc24_mul(ion_scale, 60.0), x87_pc24_mul(dt, 40.0)
                        creatures_apply_radius_damage(
                            step_runtime, proj.pos, radius, damage, CreatureDamageType.ION, proj.owner,
                        )
                    case ProjectileTemplateId.ION_CANNON:
                        proj.life_timer = x87_pc24_sub(proj.life_timer, x87_pc24_mul(dt, f32(0.7)))
                        creatures_apply_radius_damage(
                            step_runtime,
                            proj.pos,
                            x87_pc24_mul(ion_scale, 128.0),
                            x87_pc24_mul(dt, 300.0),
                            CreatureDamageType.ION,
                            proj.owner,
                        )
                    case ProjectileTemplateId.GAUSS_GUN:
                        proj.life_timer = x87_pc24_sub(proj.life_timer, x87_pc24_mul(dt, f32(0.1)))
                    case _:
                        proj.life_timer = x87_pc24_sub(proj.life_timer, dt)
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > TERRAIN_SIZE + margin
                or proj.pos.y > TERRAIN_SIZE + margin
            ):
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            steps = int(proj.travel_budget)
            if barrel_greaser_active and proj.owner.is_player():
                steps *= 2

            # Decompile parity (`projectile_update`, 0x00420b90):
            #   local_cc += (float)(cos(angle - pi/2) * frame_dt * 20.0f) * speed_scale * 3.0f
            #   local_c8 += (float)(sin(angle - pi/2) * frame_dt * 20.0f) * speed_scale * 3.0f
            # The game leaves x87 in 24-bit precision mode, so every arithmetic
            # operation in the integration chain rounds to a 24-bit significand.
            # Transcendental results stay wide until the first multiply.
            heading_radians = x87_pc24_sub(float(proj.angle), NATIVE_HALF_PI)
            step_x = x87_pc24_cos_mul(
                heading_radians,
                dt,
                20.0,
                proj.speed_scale,
                3.0,
            )
            step_y = x87_pc24_sin_mul(
                heading_radians,
                dt,
                20.0,
                proj.speed_scale,
                3.0,
            )
            dir_x = math.cos(heading_radians)
            dir_y = math.sin(heading_radians)
            acc = Vec2()
            step = 0
            while step < steps:
                acc = Vec2(
                    x87_pc24_add(acc.x, step_x),
                    x87_pc24_add(acc.y, step_y),
                )

                # PC24 length rounding controls when movement and collision checks run.
                if x87_pc24_hypot(acc.x, acc.y) >= 4.0 or steps <= step + 3:
                    move = acc
                    proj.pos = Vec2(
                        float(f32(float(proj.pos.x) + float(move.x))),
                        float(f32(float(proj.pos.y) + float(move.y))),
                    )
                    acc = Vec2()

                    hit_idx = None
                    owner_creature_idx = proj.owner.creature_index_in_bounds(len(creatures))
                    for idx in creature_spatial.candidate_indices(pos=proj.pos, radius=float(proj.hit_radius)):
                        creature = creatures[idx]
                        if not _creature_is_collidable(creature):
                            continue
                        if within_native_find_radius(
                            origin=proj.pos,
                            target=creature.pos,
                            radius=float(proj.hit_radius),
                            target_size=float(creature.size),
                        ):
                            hit_idx = idx
                            break

                    owner_collision = (
                        hit_idx is not None and owner_creature_idx is not None and int(hit_idx) == owner_creature_idx
                    )
                    if owner_collision:
                        # Native `creature_find_in_radius` does not skip owner id during
                        # search; owner hits are discarded after the first match instead of
                        # continuing to a later candidate in the same tick.
                        hit_idx = None

                    if hit_idx is None:
                        can_hit_players = True
                        if int(proj_index) == int(
                            runtime_state.shock_chain_projectile_id,
                        ):
                            # Native skips `player_find_in_radius` for the currently tracked
                            # shock-chain projectile slot in this branch.
                            can_hit_players = False

                        if proj.hits_players and can_hit_players:
                            hit_player_idx = None
                            owner_player_index = proj.owner.player_index_in_bounds(len(players))
                            for idx, player in enumerate(players):
                                if owner_player_index is not None and idx == owner_player_index:
                                    continue
                                if float(player.health) <= 0.0:
                                    continue
                                if within_native_find_radius(
                                    origin=proj.pos,
                                    target=player.pos,
                                    radius=float(proj.hit_radius),
                                    target_size=float(player.size),
                                ):
                                    hit_player_idx = idx
                                    break

                            if hit_player_idx is None:
                                step += 3
                                continue

                            proj.life_timer = 0.25
                            step_runtime.apply_player_damage(int(hit_player_idx), 10.0)

                            step += 3
                            continue

                        step += 3
                        continue

                    type_id = proj.type_id
                    creature = creatures[hit_idx]

                    # Native gates on player slot zero, including hits by
                    # creature-owned splitter children and shock-chain segments.
                    if (
                        poison_bullets_active
                        and (rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE) & 7) == 1
                    ):
                        creature.flags |= CreatureFlags.SELF_DAMAGE_TICK

                    if type_id == ProjectileTemplateId.SPLITTER_GUN:
                        _pre_hit_splitter(update_ctx, proj, int(hit_idx))

                    # Native increments the global shots-hit counter for any
                    # owner (creature-owned splitter children included) when the
                    # target is still at the alive sentinel; non-player owners
                    # map to the player-1 global slot.
                    owner_player_index = proj.owner.player_index_in_bounds(len(runtime_state.shots_hit))
                    if creature_lifecycle_is_alive(creature.lifecycle_stage) and runtime_state.shots_hit:
                        shots_hit = runtime_state.shots_hit
                        shots_hit[owner_player_index if owner_player_index is not None else 0] += 1

                    target = creature.pos
                    hit = ProjectileHit(
                        type_id=type_id,
                        origin=proj.origin,
                        hit=proj.pos,
                        target=target,
                        angle=proj.angle,
                    )
                    hits.append(hit)
                    hit_presentation = step_runtime.begin_hit_presentation(hit)

                    stop_on_hit = type_id not in (
                        ProjectileTemplateId.FIRE_BULLETS,
                        ProjectileTemplateId.GAUSS_GUN,
                        ProjectileTemplateId.BLADE_GUN,
                    )
                    if proj.life_timer != 0.25 and stop_on_hit:
                        proj.life_timer = 0.25
                        jitter = rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER) & 3
                        # Native rounds the multiply and add as separate PC24 operations.
                        proj.pos = Vec2(
                            _stop_on_hit_jitter_axis_f32(dir_x, jitter, proj.pos.x),
                            _stop_on_hit_jitter_axis_f32(dir_y, jitter, proj.pos.y),
                        )

                    dist = _damage_distance_f32(proj.origin, proj.pos)

                    hit_info = _ProjectileHitInfo(
                        proj_index=int(proj_index), proj=proj, hit_idx=int(hit_idx), move=move, target=target,
                    )
                    match type_id:
                        case ProjectileTemplateId.ION_MINIGUN | ProjectileTemplateId.ION_CANNON:
                            _post_hit_ion_common(update_ctx, hit_info)
                        case ProjectileTemplateId.ION_RIFLE:
                            _post_hit_ion_rifle(update_ctx, hit_info)
                        case ProjectileTemplateId.PLASMA_CANNON:
                            _post_hit_plasma_cannon(update_ctx, hit_info)
                        case ProjectileTemplateId.SHRINKIFIER:
                            _post_hit_shrinkifier(update_ctx, hit_info)
                        case ProjectileTemplateId.PULSE_GUN:
                            _post_hit_pulse_gun(update_ctx, hit_info)
                        case ProjectileTemplateId.PLAGUE_SPREADER:
                            _post_hit_plague_spreader(update_ctx, hit_info)

                    damage_scale = _damage_scale(type_id)
                    damage_amount = _projectile_damage_amount_f32(dist, damage_scale)

                    if damage_amount > 0.0 and creature.hp > 0.0:
                        # `damage_pool` is a float field: native `projectile_update`
                        # (0x00420b90) subtracts 1.0f and then the target's health
                        # at PC24, storing each result.
                        remaining = x87_pc24_sub(proj.damage_pool, 1.0)
                        proj.damage_pool = remaining
                        # Native `projectile_update` writes both impulse components from the
                        # same cosine term (`cos(angle - pi/2) * speed_scale`).
                        impulse_angle = f32(float(proj.angle) - NATIVE_HALF_PI)
                        impulse_axis = f32(math.cos(float(impulse_angle)) * float(proj.speed_scale))
                        impulse = Vec2(float(impulse_axis), float(impulse_axis))
                        damage_type = _damage_type_for()
                        if remaining <= 0.0:
                            _apply_damage_to_creature(
                                int(hit_idx),
                                float(damage_amount),
                                damage_type=damage_type,
                                impulse=impulse,
                                owner=proj.owner,
                                step_runtime=step_runtime,
                            )
                            creature_spatial.sync_index(int(hit_idx))
                            if proj.life_timer != 0.25:
                                proj.life_timer = 0.25
                        else:
                            _apply_damage_to_creature(
                                int(hit_idx),
                                float(remaining),
                                damage_type=damage_type,
                                impulse=impulse,
                                owner=proj.owner,
                                step_runtime=step_runtime,
                            )
                            creature_spatial.sync_index(int(hit_idx))
                            proj.damage_pool = x87_pc24_sub(proj.damage_pool, creature.hp)

                    # The default single freeze shard (`crt_rand` @ 0x4215fa ->
                    # caller_static 0x4215ff) is presentation: it spawns inside the
                    # post-hit decal branch, after the burn draw, in
                    # `queue_projectile_decals_post_hit`.

                    if proj.damage_pool == 1.0:
                        # Native clears damage_pool to 0.0 whenever it's exactly 1.0
                        # in this branch, even if life_timer is already 0.25.
                        life_before = float(proj.life_timer)
                        proj.damage_pool = 0.0
                        if life_before != 0.25:
                            proj.life_timer = 0.25

                    # Pre-hit splatter uses the collision point. Native post-hit
                    # effects/audio read the live positions after jitter and damage.
                    post_hit = msgspec.structs.replace(hit, hit=proj.pos, target=creatures[hit_idx].pos)
                    if proj.life_timer == 0.25 and stop_on_hit:
                        if hit_presentation is not None:
                            step_runtime.finish_hit_presentation(post_hit, hit_presentation)
                        break

                    if proj.damage_pool <= 0.0:
                        if hit_presentation is not None:
                            step_runtime.finish_hit_presentation(post_hit, hit_presentation)
                        break

                    if hit_presentation is not None:
                        step_runtime.finish_hit_presentation(post_hit, hit_presentation)

                step += 3

        return hits
