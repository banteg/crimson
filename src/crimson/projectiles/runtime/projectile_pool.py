from __future__ import annotations

import math
from collections.abc import MutableSequence, Sequence
from typing import TYPE_CHECKING, TypeAlias

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId

from ...creatures.damage_runtime import CreatureDamageRuntime, DirectCreatureDamageRuntime
from ...creatures.damage_types import CreatureDamageType
from ...creatures.lifecycle import creature_lifecycle_is_alive, creature_lifecycle_is_collidable
from ...effects import EffectPool
from ...math_parity import NATIVE_HALF_PI, f32
from ...owner_ref import OwnerRef
from ...perks import PerkId
from ...rng_caller_static import RngCallerStatic
from ...weapons import weapon_entry_for_projectile_type_id
from ..types import (
    MAIN_PROJECTILE_POOL_SIZE,
    Projectile,
    ProjectileCollisionProfile,
    ProjectileHit,
    ProjectileTemplateId,
)
from .behaviors import (
    _PROJECTILE_HIT_PERK_HOOKS,
    _ProjectileHitInfo,
    _ProjectileHitPerkCtx,
    _ProjectileUpdateCtx,
)
from .collision import _apply_damage_to_creature, _hit_radius_for, _within_native_find_radius
from .primary_rules import primary_rule_for_type_id
from .spatial_hash import CreatureSpatialHash

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState
    from ...gameplay import GameplayState
    from ...sim.state_types import PlayerState

ProjectileHitPresentation: TypeAlias = object


class ProjectileHitRuntime(msgspec.Struct):
    def apply_player_damage(self, player_index: int, damage: float) -> None:
        _ = player_index, damage

    def begin_hit_presentation(self, hit: ProjectileHit) -> ProjectileHitPresentation | None:
        _ = hit
        return None

    def finish_hit_presentation(self, hit: ProjectileHit, presentation: ProjectileHitPresentation) -> None:
        _ = hit, presentation


class ProjectileUpdateOptions(msgspec.Struct, frozen=True):
    world_size: float
    damage_scale_by_type: dict[int, float]
    rng: CrandLike
    runtime_state: GameplayState
    players: Sequence[PlayerState]
    hit_runtime: ProjectileHitRuntime
    creature_damage_runtime: CreatureDamageRuntime | None = None
    ion_aoe_scale: float = 1.0
    detail_preset: int = 5


class PrimaryStepCtx(msgspec.Struct, frozen=True):
    dt: float
    creatures: Sequence[CreatureState]
    options: ProjectileUpdateOptions


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


def projectile_collision_profile(type_id: ProjectileTemplateId) -> ProjectileCollisionProfile:
    return _PROJECTILE_COLLISION_PROFILE_BY_TYPE_ID.get(
        type_id,
        _DEFAULT_PROJECTILE_COLLISION_PROFILE,
    )


class ProjectilePool:
    def __init__(self, *, size: int = MAIN_PROJECTILE_POOL_SIZE) -> None:
        self._entries = [Projectile() for _ in range(size)]

    @property
    def entries(self) -> list[Projectile]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def spawn(
        self,
        *,
        pos: Vec2,
        angle: float,
        type_id: ProjectileTemplateId,
        owner: OwnerRef,
        travel_budget: float = 0.0,
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
        entry.life_timer = 0.4
        entry.reserved = 0.0
        entry.speed_scale = 1.0
        entry.travel_budget = float(travel_budget)
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
        creatures = ctx.creatures
        options = ctx.options
        world_size = float(f32(float(options.world_size)))
        damage_scale_by_type = options.damage_scale_by_type
        ion_aoe_scale = float(options.ion_aoe_scale)
        detail_preset = int(options.detail_preset)
        rng = options.rng
        runtime_state = options.runtime_state
        players = options.players
        hit_runtime = options.hit_runtime
        creature_damage_runtime = options.creature_damage_runtime
        if creature_damage_runtime is None:
            creature_damage_runtime = DirectCreatureDamageRuntime(creatures=creatures)

        if dt <= 0.0:
            return []

        barrel_greaser_active = False
        ion_gun_master_active = False
        poison_bullets_active = False
        ion_scale = float(ion_aoe_scale)
        poison_idx = int(PerkId.POISON_BULLETS)
        barrel_idx = int(PerkId.BARREL_GREASER)
        ion_idx = int(PerkId.ION_GUN_MASTER)
        for player in players:
            perk_counts = player.perk_counts

            if 0 <= barrel_idx < len(perk_counts) and int(perk_counts[barrel_idx]) > 0:
                barrel_greaser_active = True
            if 0 <= ion_idx < len(perk_counts) and int(perk_counts[ion_idx]) > 0:
                ion_gun_master_active = True
            if 0 <= poison_idx < len(perk_counts) and int(perk_counts[poison_idx]) > 0:
                poison_bullets_active = True

        if ion_scale == 1.0 and ion_gun_master_active:
            ion_scale = 1.2

        effects: EffectPool | None = runtime_state.effects
        sfx_queue: MutableSequence[SfxId] | None = runtime_state.sfx_queue

        hits: list[ProjectileHit] = []
        margin = 64.0

        def _creature_is_collidable(creature: CreatureState) -> bool:
            if not creature.active:
                return False
            if not creature_lifecycle_is_collidable(creature.lifecycle_stage):
                return False
            return True

        creature_spatial = CreatureSpatialHash(creatures=creatures, is_collidable=_creature_is_collidable)

        def _damage_scale(type_id: int) -> float:
            value = damage_scale_by_type.get(type_id)
            if value is not None:
                return float(value)
            return float(weapon_entry_for_projectile_type_id(ProjectileTemplateId(type_id)).damage_scale)

        def _damage_distance_f32(origin: Vec2, pos: Vec2) -> float:
            dx = float(f32(float(origin.x) - float(pos.x)))
            dy = float(f32(float(origin.y) - float(pos.y)))
            dist_sq = float(f32(float(f32(float(dx) * float(dx))) + float(f32(float(dy) * float(dy)))))
            return float(f32(math.sqrt(float(dist_sq))))

        def _projectile_damage_amount_f32(dist: float, damage_scale: float) -> float:
            # `projectile_update` computes this from float locals (`fVar11/fVar23`),
            # so keep the damage path rounded through float32.
            dist_f32 = float(f32(float(dist)))
            if dist_f32 < 50.0:
                dist_f32 = 50.0
            damage_scale_f32 = float(f32(float(damage_scale)))
            return float(f32(((100.0 / float(dist_f32)) * float(damage_scale_f32) * 30.0 + 10.0) * 0.95))

        def _damage_type_for() -> int:
            return int(CreatureDamageType.BULLET)

        update_ctx = _ProjectileUpdateCtx(
            pool=self,
            creatures=creatures,
            dt=float(dt),
            ion_scale=float(ion_scale),
            detail_preset=int(detail_preset),
            rng=rng,
            runtime_state=runtime_state,
            effects=effects,
            sfx_queue=sfx_queue,
            creature_damage_runtime=creature_damage_runtime,
        )

        def _reset_shock_chain_if_owner(index: int) -> None:
            if runtime_state.shock_chain_projectile_id != index:
                return
            runtime_state.shock_chain_projectile_id = -1
            runtime_state.shock_chain_links_left = 0

        for proj_index, proj in enumerate(self._entries):
            if not proj.active:
                continue
            rule = primary_rule_for_type_id(ProjectileTemplateId(proj.type_id))

            if proj.life_timer <= 0.0:
                proj.active = False
                # Native `projectile_update` clears the active flag but still
                # runs this tick's life_timer branch, so expired ion projectiles
                # can apply one final linger AoE pass.

            if proj.life_timer < 0.4:
                if rule.reset_shock_chain_on_linger:
                    _reset_shock_chain_if_owner(proj_index)
                rule.linger(update_ctx, proj)
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > world_size + margin
                or proj.pos.y > world_size + margin
            ):
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            steps = int(proj.travel_budget)
            if barrel_greaser_active and proj.owner.is_player():
                steps *= 2

            # Decompile parity (`projectile_update`, 0x00420b90):
            #   local_cc += (float)(cos(angle - pi/2) * frame_dt * 20.0f) * speed_scale * 3.0f
            #   local_c8 += (float)(sin(angle - pi/2) * frame_dt * 20.0f) * speed_scale * 3.0f
            # Keep the float32 cast before `* speed_scale * 3.0`.
            heading_radians = float(proj.angle) - NATIVE_HALF_PI
            dir_x = math.cos(heading_radians)
            dir_y = math.sin(heading_radians)
            acc = Vec2()
            step = 0
            while step < steps:
                acc = Vec2(
                    float(
                        f32(
                            float(acc.x)
                            + float(
                                f32(float(dir_x) * float(dt) * 20.0) * float(proj.speed_scale) * 3.0,
                            ),
                        ),
                    ),
                    float(
                        f32(
                            float(acc.y)
                            + float(
                                f32(float(dir_y) * float(dt) * 20.0) * float(proj.speed_scale) * 3.0,
                            ),
                        ),
                    ),
                )

                if acc.length() >= 4.0 or steps <= step + 3:
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
                        if _within_native_find_radius(
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
                                if _within_native_find_radius(
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
                            hit_runtime.apply_player_damage(int(hit_player_idx), 10.0)

                            step += 3
                            continue

                        step += 3
                        continue

                    type_id = proj.type_id
                    creature = creatures[hit_idx]

                    perk_ctx = _ProjectileHitPerkCtx(
                        proj=proj,
                        creature=creature,
                        rng=rng,
                        poison_bullets_active=poison_bullets_active,
                    )
                    for hook in _PROJECTILE_HIT_PERK_HOOKS:
                        hook(perk_ctx)

                    rule.pre_hit(update_ctx, proj, int(hit_idx))

                    owner_player_index = proj.owner.player_index_in_bounds(len(runtime_state.shots_hit))
                    if owner_player_index is not None and creature_lifecycle_is_alive(creature.lifecycle_stage):
                        shots_hit = runtime_state.shots_hit
                        shots_hit[owner_player_index] += 1

                    target = creature.pos
                    hit = ProjectileHit(
                        type_id=type_id,
                        origin=proj.origin,
                        hit=proj.pos,
                        target=target,
                    )
                    hits.append(hit)
                    hit_presentation = hit_runtime.begin_hit_presentation(hit)

                    if proj.life_timer != 0.25 and rule.stop_on_hit:
                        proj.life_timer = 0.25
                        jitter = rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER) & 3
                        jitter_dx = float(f32(float(dir_x) * float(jitter)))
                        jitter_dy = float(f32(float(dir_y) * float(jitter)))
                        proj.pos = Vec2(
                            float(f32(float(proj.pos.x) + float(jitter_dx))),
                            float(f32(float(proj.pos.y) + float(jitter_dy))),
                        )

                    dist = _damage_distance_f32(proj.origin, proj.pos)

                    rule.post_hit(
                        update_ctx,
                        _ProjectileHitInfo(
                            proj_index=int(proj_index),
                            proj=proj,
                            hit_idx=int(hit_idx),
                            move=move,
                            target=target,
                        ),
                    )

                    damage_scale = _damage_scale(type_id)
                    damage_amount = _projectile_damage_amount_f32(dist, damage_scale)

                    if damage_amount > 0.0 and creature.hp > 0.0:
                        remaining = proj.damage_pool - 1.0
                        proj.damage_pool = remaining
                        # Native `projectile_update` writes both impulse components from the
                        # same cosine term (`cos(angle - pi/2) * speed_scale`).
                        impulse_axis = f32(math.cos(float(proj.angle) - NATIVE_HALF_PI) * float(proj.speed_scale))
                        impulse = Vec2(float(impulse_axis), float(impulse_axis))
                        damage_type = _damage_type_for()
                        if remaining <= 0.0:
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(damage_amount),
                                damage_type=damage_type,
                                impulse=impulse,
                                owner=proj.owner,
                                creature_damage_runtime=creature_damage_runtime,
                            )
                            creature_spatial.sync_index(int(hit_idx))
                            if proj.life_timer != 0.25:
                                proj.life_timer = 0.25
                        else:
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(remaining),
                                damage_type=damage_type,
                                impulse=impulse,
                                owner=proj.owner,
                                creature_damage_runtime=creature_damage_runtime,
                            )
                            creature_spatial.sync_index(int(hit_idx))
                            proj.damage_pool -= float(creature.hp)

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

                    if proj.life_timer == 0.25 and rule.stop_on_hit:
                        if hit_presentation is not None:
                            hit_runtime.finish_hit_presentation(hit, hit_presentation)
                        break

                    if proj.damage_pool <= 0.0:
                        if hit_presentation is not None:
                            hit_runtime.finish_hit_presentation(hit, hit_presentation)
                        break

                    if hit_presentation is not None:
                        hit_runtime.finish_hit_presentation(hit, hit_presentation)

                step += 3

        return hits

    def update_demo(
        self,
        dt: float,
        creatures: Sequence[CreatureState],
        *,
        world_size: float,
        speed_by_type: dict[int, float],
        damage_by_type: dict[int, float],
    ) -> list[ProjectileHit]:
        """Update a small projectile subset for the demo view."""

        if dt <= 0.0:
            return []

        hits: list[ProjectileHit] = []
        margin = 64.0

        for proj in self._entries:
            if not proj.active:
                continue

            if proj.life_timer <= 0.0:
                proj.active = False
                continue

            if proj.life_timer < 0.4:
                if proj.type_id == ProjectileTemplateId.ION_RIFLE:
                    damage = dt * 100.0
                    radius = 88.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                            creature.hp -= damage
                elif proj.type_id == ProjectileTemplateId.ION_MINIGUN:
                    damage = dt * 40.0
                    radius = 60.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                            creature.hp -= damage
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > world_size + margin
                or proj.pos.y > world_size + margin
            ):
                proj.life_timer = float(f32(float(proj.life_timer) - float(dt)))
                continue

            speed = speed_by_type.get(proj.type_id, 650.0) * proj.speed_scale
            direction = Vec2.from_heading(float(proj.angle))
            proj.pos = proj.pos + direction * (speed * dt)

            hit_idx = None
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = proj.hit_radius + creature_radius
                if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is None:
                continue

            creature = creatures[hit_idx]
            hits.append(
                ProjectileHit(
                    type_id=proj.type_id,
                    origin=proj.origin,
                    hit=proj.pos,
                    target=creature.pos,
                ),
            )

            creature = creatures[hit_idx]
            creature.hp -= damage_by_type.get(proj.type_id, 10.0)

            proj.life_timer = 0.25

        return hits
