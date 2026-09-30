from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ...collision_math import within_native_find_radius
from ...creatures.damage import creature_apply_damage, creatures_apply_radius_damage
from ...creatures.damage_types import CreatureDamageType
from ...creatures.lifecycle import creature_lifecycle_is_alive, creature_lifecycle_is_collidable
from ...creatures.spawn_ids import CreatureFlags
from ...math_parity import (
    NATIVE_HALF_PI,
    f32,
    native_chain_angle_from_delta,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_distance,
    x87_pc24_hypot,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ...owner_id import OWNER_LOCAL_PLAYER
from ...perks import PerkId
from ...rng_caller_static import RngCallerStatic
from ...sim.state_types import TERRAIN_SIZE
from ...weapons import weapon_entry_for_projectile_type_id
from ..effects import (
    effect_spawn_ion_hit_core,
    effect_spawn_ion_hit_sparks,
    effect_spawn_plasma_hit_core,
    effect_spawn_shrinkifier_hit,
    effect_spawn_splitter_hit_burst,
)
from ..types import (
    MAIN_PROJECTILE_POOL_SIZE,
    Projectile,
    ProjectileHit,
    ProjectileTemplateId,
)
from .collision import creature_find_nearest_active
from .spatial_hash import CreatureSpatialHash

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState
    from ...sim.state_types import PlayerState
    from ...sim.world_state import WorldStepRuntime


def _projectile_damage_amount_f32(dist: float, damage_scale: float) -> float:
    """Mirror native PC_24 arithmetic stores in the projectile damage formula."""

    distance = f32(dist)
    if distance < 50.0:
        distance = 50.0
    damage = f32(100.0 / float(distance))
    damage = f32(float(damage) * f32(damage_scale))
    damage = f32(float(damage) * 30.0)
    damage = f32(float(damage) + 10.0)
    return f32(float(damage) * f32(0.95))


def _stop_on_hit_jitter_axis_f32(direction: float, jitter: int, pos: float) -> float:
    offset = x87_pc24_mul(direction, float(jitter))
    return x87_pc24_add(offset, pos)


def projectile_spawn(
    state: GameplayState,
    *,
    players: Sequence[PlayerState],
    pos: Vec2,
    angle: float,
    type_id: ProjectileTemplateId,
    owner_id: int,
    owner_player_index: int,
) -> int:
    """Port of `projectile_spawn` (0x00420440): a player's shot counts as fired and becomes Fire Bullets."""

    if not state.bonus_spawn_guard:
        # Native lists -100, -1, -2 and -3, so a fourth player's friendly-fire shots skip it; the rewrite takes any player.
        if state.preserve_bugs:
            player_owned = owner_id == OWNER_LOCAL_PLAYER or -3 <= owner_id <= -1
        else:
            player_owned = owner_id < 0
        # Native loops once more after converting, so a converted shot counts twice.
        while player_owned:
            state.shots_fired += 1
            if type_id == ProjectileTemplateId.FIRE_BULLETS:
                break
            # Native reads both players' timers whoever fired; the rewrite reads the shooter's.
            if state.preserve_bugs:
                fire_bullets_active = any(player.fire_bullets_timer > 0.0 for player in players[:2])
            else:
                fire_bullets_active = players[owner_player_index].fire_bullets_timer > 0.0
            if not fire_bullets_active:
                break
            type_id = ProjectileTemplateId.FIRE_BULLETS

    entries = state.projectiles.entries
    index = next((i for i, entry in enumerate(entries) if not entry.active), MAIN_PROJECTILE_POOL_SIZE - 1)
    entry = entries[index]
    entry.generation += 1
    entry.owner_id = owner_id
    entry.active = True
    entry.travel_budget = float(weapon_entry_for_projectile_type_id(type_id).travel_budget)
    entry.pos = Vec2(f32(pos.x), f32(pos.y))
    entry.origin = entry.pos
    entry.angle = f32(angle)
    entry.type_id = type_id
    entry.life_timer = f32(0.4)
    entry.reserved = 0.0
    entry.speed_scale = 1.0
    entry.vel = Vec2(f32(math.cos(entry.angle) * 1.5), f32(math.sin(entry.angle) * 1.5))

    match type_id:
        case ProjectileTemplateId.ION_MINIGUN:
            entry.hit_radius = 3.0
            entry.damage_pool = 1.0
        case ProjectileTemplateId.ION_RIFLE:
            entry.hit_radius = 5.0
            entry.damage_pool = 1.0
        case ProjectileTemplateId.ION_CANNON | ProjectileTemplateId.PLASMA_CANNON:
            entry.hit_radius = 10.0
            entry.damage_pool = 1.0
        case ProjectileTemplateId.GAUSS_GUN:
            entry.hit_radius = 1.0
            entry.damage_pool = 300.0
        case ProjectileTemplateId.FIRE_BULLETS:
            entry.hit_radius = 1.0
            entry.damage_pool = 240.0
        case ProjectileTemplateId.BLADE_GUN:
            entry.hit_radius = 1.0
            entry.damage_pool = 50.0
        case _:
            entry.hit_radius = 1.0
            entry.damage_pool = 1.0
    return index


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

    def iter_active(self) -> list[Projectile]:
        return [entry for entry in self._entries if entry.active]

    def step(self, step_runtime: WorldStepRuntime) -> list[ProjectileHit]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.
        """
        dt = f32(step_runtime.dt)
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
                        if proj_index == runtime_state.shock_chain_projectile_id:
                            runtime_state.shock_chain_projectile_id = -1
                            runtime_state.shock_chain_links_left = 0
                        proj.life_timer = x87_pc24_sub(proj.life_timer, dt)
                        if proj.type_id == ProjectileTemplateId.ION_RIFLE:
                            radius, damage = x87_pc24_mul(ion_scale, 88.0), x87_pc24_mul(dt, 100.0)
                        else:
                            radius, damage = x87_pc24_mul(ion_scale, 60.0), x87_pc24_mul(dt, 40.0)
                        creatures_apply_radius_damage(
                            step_runtime, proj.pos, radius, damage, CreatureDamageType.ION,
                        )
                    case ProjectileTemplateId.ION_CANNON:
                        proj.life_timer = x87_pc24_sub(proj.life_timer, x87_pc24_mul(dt, f32(0.7)))
                        creatures_apply_radius_damage(
                            step_runtime,
                            proj.pos,
                            x87_pc24_mul(ion_scale, 128.0),
                            x87_pc24_mul(dt, 300.0),
                            CreatureDamageType.ION,
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
                proj.life_timer = f32(float(proj.life_timer) - float(dt))
                continue

            steps = int(proj.travel_budget)
            if barrel_greaser_active and proj.owner_id < 0:
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
                        f32(float(proj.pos.x) + float(move.x)),
                        f32(float(proj.pos.y) + float(move.y)),
                    )
                    acc = Vec2()

                    hit_idx = None
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

                    if hit_idx == proj.owner_id:
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

                        # Only -100, the local player's shots with friendly fire off, never hit players;
                        # `player_find_in_radius` skips the shooter at `-1 - owner_id`.
                        if proj.owner_id != OWNER_LOCAL_PLAYER and can_hit_players:
                            hit_player_idx = None
                            skip_index = -1 - proj.owner_id
                            for idx, player in enumerate(players):
                                if idx == skip_index:
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
                        effect_spawn_splitter_hit_burst(effects, pos=proj.pos, rng=rng, detail_preset=detail_preset)
                        # The children belong to the creature hit, so they can hit players even when the
                        # parent was the local player's.
                        projectile_spawn(
                            runtime_state,
                            players=players,
                            pos=proj.pos,
                            angle=x87_pc24_sub(proj.angle, f32(1.0471976)),
                            type_id=ProjectileTemplateId.SPLITTER_GUN,
                            owner_id=hit_idx,
                            owner_player_index=0,
                        )
                        projectile_spawn(
                            runtime_state,
                            players=players,
                            pos=proj.pos,
                            angle=x87_pc24_add(proj.angle, f32(1.0471976)),
                            type_id=ProjectileTemplateId.SPLITTER_GUN,
                            owner_id=hit_idx,
                            owner_player_index=0,
                        )

                    # Native counts a hit for any owner (creature-owned splitter children included)
                    # while the target is still at the alive sentinel.
                    if creature_lifecycle_is_alive(creature.lifecycle_stage):
                        runtime_state.shots_hit += 1

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

                    dist = x87_pc24_distance(proj.origin, proj.pos)

                    match type_id:
                        case ProjectileTemplateId.ION_MINIGUN:
                            effect_spawn_ion_hit_core(
                                effects, pos=proj.pos, scale_step=1.5, lifetime=0.1, detail_preset=detail_preset,
                            )
                            effect_spawn_ion_hit_sparks(effects, pos=proj.pos, scale=0.8, rng=rng, detail_preset=detail_preset)
                        case ProjectileTemplateId.ION_RIFLE:
                            if (
                                runtime_state.shock_chain_links_left > 0
                                and proj_index == runtime_state.shock_chain_projectile_id
                            ):
                                runtime_state.shock_chain_links_left -= 1
                                next_idx = creature_find_nearest_active(
                                    creatures=creatures,
                                    origin=proj.pos,
                                    exclude_id=hit_idx,
                                    min_dist=100.0,
                                    preserve_bugs=bool(runtime_state.preserve_bugs),
                                )
                                # Native chains to slot 0 when nothing qualifies; the rewrite ends the chain.
                                if next_idx >= 0:
                                    runtime_state.bonus_spawn_guard = True
                                    runtime_state.shock_chain_projectile_id = projectile_spawn(
                                        runtime_state,
                                        players=players,
                                        pos=proj.pos,
                                        angle=native_chain_angle_from_delta(
                                            dx=x87_pc24_sub(creatures[next_idx].pos.x, creature.pos.x),
                                            dy=x87_pc24_sub(creatures[next_idx].pos.y, creature.pos.y),
                                        ),
                                        type_id=ProjectileTemplateId.ION_RIFLE,
                                        owner_id=hit_idx,
                                        owner_player_index=0,
                                    )
                                    runtime_state.bonus_spawn_guard = False
                            effect_spawn_ion_hit_core(
                                effects, pos=proj.pos, scale_step=1.2, lifetime=0.4, detail_preset=detail_preset,
                            )
                            effect_spawn_ion_hit_sparks(effects, pos=proj.pos, scale=1.2, rng=rng, detail_preset=detail_preset)
                        case ProjectileTemplateId.ION_CANNON:
                            effect_spawn_ion_hit_core(
                                effects, pos=proj.pos, scale_step=1.0, lifetime=1.0, detail_preset=detail_preset,
                            )
                            effect_spawn_ion_hit_sparks(effects, pos=proj.pos, scale=2.2, rng=rng, detail_preset=detail_preset)
                            sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, proj.pos))
                        case ProjectileTemplateId.PLASMA_CANNON:
                            runtime_state.bonus_spawn_guard = True
                            # Native 0x00421370: each PC=24 op rounds; the ring angle is a float32 local.
                            ring_radius = x87_pc24_add(x87_pc24_mul(creature.size, 0.5), 1.0)
                            for ring_idx in range(12):
                                ring_angle = x87_pc24_mul(float(ring_idx), f32(0.5235988))
                                projectile_spawn(
                                    runtime_state,
                                    players=players,
                                    pos=Vec2(
                                        x87_pc24_add(x87_pc24_cos_mul(ring_angle, ring_radius), proj.pos.x),
                                        x87_pc24_add(x87_pc24_sin_mul(ring_angle, ring_radius), proj.pos.y),
                                    ),
                                    angle=ring_angle,
                                    type_id=ProjectileTemplateId.PLASMA_RIFLE,
                                    owner_id=OWNER_LOCAL_PLAYER,
                                    owner_player_index=0,
                                )
                            runtime_state.bonus_spawn_guard = False
                            sfx_queue.append(SfxRequest(SfxId.EXPLOSION_MEDIUM, proj.pos))
                            sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, proj.pos))
                            effect_spawn_plasma_hit_core(
                                effects, pos=proj.pos, scale_step=1.5, lifetime=1.0, detail_preset=detail_preset,
                            )
                            effect_spawn_plasma_hit_core(
                                effects, pos=proj.pos, scale_step=1.0, lifetime=1.0, detail_preset=detail_preset,
                            )
                        case ProjectileTemplateId.SHRINKIFIER:
                            effect_spawn_shrinkifier_hit(effects, pos=proj.pos, rng=rng, detail_preset=detail_preset)
                            creature.size = x87_pc24_mul(creature.size, f32(0.65))
                            proj.life_timer = 0.25
                            if creature.size < 16.0:
                                # Native calls creature_handle_death directly: no damage pipeline, so no
                                # heading-jitter or death-SFX rand draws, and hp stays positive so the
                                # generic chip damage below still applies.
                                step_runtime.world.creatures.handle_death(step_runtime, hit_idx)
                        case ProjectileTemplateId.PULSE_GUN:
                            creature.pos = Vec2(
                                x87_pc24_add(creature.pos.x, x87_pc24_mul(move.x, 3.0)),
                                x87_pc24_add(creature.pos.y, x87_pc24_mul(move.y, 3.0)),
                            )
                            # Native re-scans the pool per query, so later projectiles this tick see
                            # the pushed creature at its new position; resync the spatial hash.
                            creature_spatial.sync_index(hit_idx)
                        case ProjectileTemplateId.PLAGUE_SPREADER:
                            creature.plague_infected = True

                    damage_amount = _projectile_damage_amount_f32(
                        dist, weapon_entry_for_projectile_type_id(type_id).damage_scale,
                    )

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
                        if remaining <= 0.0:
                            creature_apply_damage(step_runtime, int(hit_idx), float(damage_amount), CreatureDamageType.BULLET, impulse)
                            creature_spatial.sync_index(int(hit_idx))
                            if proj.life_timer != 0.25:
                                proj.life_timer = 0.25
                        else:
                            creature_apply_damage(step_runtime, int(hit_idx), float(remaining), CreatureDamageType.BULLET, impulse)
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
