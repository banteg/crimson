from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike

from ...collision_math import within_native_find_radius
from ...creatures.damage import creature_apply_damage
from ...creatures.damage_types import CreatureDamageType
from ...creatures.lifecycle import creature_lifecycle_is_alive, creature_lifecycle_is_collidable
from ...effects import SpriteEffectPool
from ...effects_atlas import EffectId
from ...math_parity import (
    NATIVE_HALF_PI,
    f32,
    x87_fpatan,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_hypot,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ...rng_caller_static import RngCallerStatic
from ..types import (
    SECONDARY_PROJECTILE_POOL_SIZE,
    SecondaryProjectile,
    SecondaryProjectileTypeId,
)
from .collision import creature_find_nearest_alive
from .spatial_hash import CreatureSpatialHash

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState
    from ...sim.state_types import PlayerState
    from ...sim.world_state import WorldStepRuntime


_SECONDARY_PRE_HIT_DECAL_CALLERS = (
    (
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_1,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_1,
    ),
    (
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_2,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_2,
    ),
    (
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_3,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_3,
    ),
)


_DETONATION_IMPULSE_SCALE = f32(0.1)
_TRAIL_DECAY_SCALE = f32(0.01)


def _creature_is_collidable(creature: CreatureState) -> bool:
    if not creature.active:
        return False
    return creature_lifecycle_is_collidable(creature.death_timer)


def _step_detonation(
    entry: SecondaryProjectile,
    step_runtime: WorldStepRuntime,
    *,
    dt: float,
    creature_spatial: CreatureSpatialHash,
    rng: CrandLike,
) -> None:
    runtime_state, creatures = step_runtime.world.state, step_runtime.world.creatures.entries
    fx_queue = step_runtime.fx_queue
    runtime_state.camera_shake_pulses = 4

    entry.detonation_t = x87_pc24_add(entry.detonation_t, x87_pc24_mul(dt, 3.0))
    entry.vel = Vec2(entry.detonation_t, entry.detonation_scale)
    t = float(entry.detonation_t)
    scale = float(entry.detonation_scale)
    if t > 1.0:
        fx_queue.add(
            effect_id=int(EffectId.AURA),
            pos=entry.pos,
            width=float(scale) * 256.0,
            height=float(scale) * 256.0,
            rotation=0.0,
            rgba=RGBA(0.0, 0.0, 0.0, 0.25),
        )
        entry.active = False

    radius = x87_pc24_mul(x87_pc24_mul(scale, t), 80.0)
    damage = x87_pc24_mul(dt, scale)
    damage = x87_pc24_mul(damage, 700.0)
    # Native scans every slot and gates only on `active && health > 0`:
    # shrunk-to-death corpses keep positive health and are still damaged at
    # any lifecycle stage.
    for creature_idx, creature in enumerate(creatures):
        if not creature.active or not creature.hp > 0.0:
            continue
        # projectile_vec2_distance: PC=24 `sqrt(dx*dx + dy*dy)` vs the f32 radius.
        distance = x87_pc24_hypot(
            x87_pc24_sub(creature.pos.x, entry.pos.x),
            x87_pc24_sub(creature.pos.y, entry.pos.y),
        )
        if distance < radius:
            impulse_dir = (creature.pos - entry.pos).normalized()
            impulse = Vec2(
                x87_pc24_mul(impulse_dir.x, _DETONATION_IMPULSE_SCALE),
                x87_pc24_mul(impulse_dir.y, _DETONATION_IMPULSE_SCALE),
            )
            creature_apply_damage(step_runtime, creature_idx, damage, CreatureDamageType.EXPLOSION, impulse)
            creature_spatial.sync_index(int(creature_idx))
            if creature.hp <= 0.0:
                # Native detonation AoE does an extra two random decals and a
                # second `creature_handle_death` call after the killing hit.
                fx_queue.add_random(pos=creature.pos, rng=rng)
                fx_queue.add_random(pos=creature.pos, rng=rng)
                step_runtime.world.creatures.handle_death(step_runtime, creature_idx)


def _move_rocket(
    entry: SecondaryProjectile,
    *,
    dt: float,
    creatures: Sequence[CreatureState],
    runtime_state: GameplayState,
) -> None:
    # Move. Native keeps pos/vel as f32 fields: `pos += f32(dt * vel)`.
    entry.pos = Vec2(
        f32(float(entry.pos.x) + f32(float(dt) * float(entry.vel.x))),
        f32(float(entry.pos.y) + f32(float(dt) * float(entry.vel.y))),
    )

    # Update velocity + countdown. `projectile_vec2_length` rounds per PC=24 op.
    speed_mag = x87_pc24_hypot(entry.vel.x, entry.vel.y)
    match entry.type_id:
        case SecondaryProjectileTypeId.ROCKET | SecondaryProjectileTypeId.ROCKET_MINIGUN:
            rocket = entry.type_id == SecondaryProjectileTypeId.ROCKET
            if speed_mag < (500.0 if rocket else 600.0):
                factor = x87_pc24_add(x87_pc24_mul(dt, 3.0 if rocket else 4.0), 1.0)
                entry.vel = Vec2(
                    f32(factor * float(entry.vel.x)),
                    f32(factor * float(entry.vel.y)),
                )
            entry.life_timer = x87_pc24_sub(entry.life_timer, f32(dt))
        case SecondaryProjectileTypeId.HOMING_ROCKET:
            # Type 2: homing projectile.
            target_id = entry.target_id
            if not (0 <= target_id < len(creatures)) or not creatures[target_id].active:
                entry.target_id = creature_find_nearest_alive(
                    creatures=creatures,
                    origin=entry.pos,
                    preserve_bugs=bool(runtime_state.preserve_bugs),
                )
                target_id = entry.target_id

            if 0 <= target_id < len(creatures):
                target = creatures[target_id]
                # Native steering: angle = atan2(pos - target) kept in
                # extended precision; the stored f32 angle is atan - pi/2.
                # vel_x adds cos((atan - pi/2) - pi/2) from the extended
                # angle; vel_y (and the over-cap subtraction for both
                # components) recompute from the stored f32 angle, so the
                # add-then-subtract is not an exact identity.
                atan_ext = x87_fpatan(
                    x87_pc24_sub(entry.pos.y, target.pos.y),
                    x87_pc24_sub(entry.pos.x, target.pos.x),
                )
                entry.angle = x87_pc24_sub(atan_ext, NATIVE_HALF_PI)
                heading_ext = x87_pc24_sub(
                    x87_pc24_sub(atan_ext, NATIVE_HALF_PI),
                    NATIVE_HALF_PI,
                )
                heading_stored = x87_pc24_sub(entry.angle, NATIVE_HALF_PI)
                entry.vel = Vec2(
                    x87_pc24_add(
                        entry.vel.x,
                        x87_pc24_cos_mul(
                            heading_ext,
                            dt,
                            800.0,
                        ),
                    ),
                    x87_pc24_add(
                        entry.vel.y,
                        x87_pc24_sin_mul(
                            heading_stored,
                            dt,
                            800.0,
                        ),
                    ),
                )
                speed_after = x87_pc24_hypot(entry.vel.x, entry.vel.y)
                if speed_after > 350.0:
                    entry.vel = Vec2(
                        x87_pc24_sub(
                            entry.vel.x,
                            x87_pc24_cos_mul(
                                heading_stored,
                                dt,
                                800.0,
                            ),
                        ),
                        x87_pc24_sub(
                            entry.vel.y,
                            x87_pc24_sin_mul(
                                heading_stored,
                                dt,
                                800.0,
                            ),
                        ),
                    )

            entry.life_timer = x87_pc24_sub(entry.life_timer, x87_pc24_mul(dt, 0.5))


def _tick_rocket_trail(
    entry: SecondaryProjectile,
    *,
    dt: float,
    sprite_effects: SpriteEffectPool,
    rng: CrandLike,
) -> None:
    # Rocket smoke trail (`trail_distance` in crimsonland.exe).
    trail_speed = x87_pc24_add(abs(entry.vel.x), abs(entry.vel.y))
    trail_decay = x87_pc24_mul(trail_speed, dt)
    trail_decay = x87_pc24_mul(trail_decay, _TRAIL_DECAY_SCALE)
    entry.trail_distance = x87_pc24_sub(entry.trail_distance, trail_decay)
    if float(entry.trail_distance) < 0.0:
        direction = Vec2.from_heading(entry.angle)
        spawn_pos = entry.pos - direction * 9.0
        # Native bug: both trail velocity components come from cosine
        # (fcos with no fsin), so the smoke drifts diagonally.
        trail_cos = math.cos(f32(entry.angle) + NATIVE_HALF_PI)
        trail_velocity = Vec2(f32(trail_cos) * 90.0, f32(trail_cos * 90.0))
        sprite_effects.spawn(
            pos=spawn_pos,
            vel=trail_velocity,
            scale=14.0,
            color=RGBA(1.0, 1.0, 1.0, 0.25),
            rng=rng,
        )
        entry.trail_distance = f32(0.06)


def fx_spawn_secondary_projectile(
    state: GameplayState,
    player: PlayerState,
    creatures: Sequence[CreatureState],
    *,
    pos: Vec2,
    angle: float,
    type_id: SecondaryProjectileTypeId,
) -> int:
    """Port of `fx_spawn_secondary_projectile`; `player` is `current_player_index`'s, whose aim seeds the seeker."""

    entries = state.secondary_projectiles.entries
    index = next((i for i, entry in enumerate(entries) if not entry.active), SECONDARY_PROJECTILE_POOL_SIZE - 1)
    state.shots_fired += 1

    entry = entries[index]
    entry.generation += 1
    entry.active = True
    entry.pos = Vec2(f32(pos.x), f32(pos.y))
    entry.life_timer = 2.0
    radians = x87_pc24_sub(f32(angle), NATIVE_HALF_PI)
    entry.vel = Vec2(x87_pc24_cos_mul(radians, 90.0), x87_pc24_sin_mul(radians, 90.0))
    entry.angle = f32(angle)
    entry.trail_distance = 0.0
    entry.type_id = type_id

    if type_id == SecondaryProjectileTypeId.HOMING_ROCKET:
        entry.target_id = creature_find_nearest_alive(
            creatures=creatures,
            origin=player.aim,
            preserve_bugs=bool(state.preserve_bugs),
        )
        # Native stores each trig result as float32 before the seeker's 190x velocity override.
        entry.vel = Vec2(x87_pc24_cos_mul(radians, 1.0, 190.0), x87_pc24_sin_mul(radians, 1.0, 190.0))
    return index


class SecondaryProjectilePool:
    def __init__(self) -> None:
        self._entries = [SecondaryProjectile() for _ in range(SECONDARY_PROJECTILE_POOL_SIZE)]

    @property
    def entries(self) -> list[SecondaryProjectile]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.generation = 0
            entry.active = False

    def iter_active(self) -> list[SecondaryProjectile]:
        return [entry for entry in self._entries if entry.active]

    def step(self, step_runtime: WorldStepRuntime) -> int:
        """Update the secondary projectile pool subset (types 1/2/4 + detonation type 3)."""
        dt = float(step_runtime.dt)
        runtime_state = step_runtime.world.state
        creatures = step_runtime.world.creatures.entries
        fx_queue = step_runtime.fx_queue
        detail_preset = int(step_runtime.world.state.detail_preset)

        if dt <= 0.0:
            return 0
        if not any(entry.active for entry in self._entries):
            return 0

        rng = runtime_state.rng
        freeze_active = float(runtime_state.bonuses.freeze) > 0.0
        effects = runtime_state.effects
        sprite_effects = runtime_state.sprite_effects

        creature_spatial = CreatureSpatialHash(pool=step_runtime.world.creatures, is_collidable=_creature_is_collidable)
        hit_count = 0

        for entry in self._entries:
            if not entry.active:
                continue

            type_id = entry.type_id
            if type_id == SecondaryProjectileTypeId.DETONATION:
                _step_detonation(entry, step_runtime, dt=dt, creature_spatial=creature_spatial, rng=rng)
                continue

            _move_rocket(entry, dt=dt, creatures=creatures, runtime_state=runtime_state)

            _tick_rocket_trail(entry, dt=dt, sprite_effects=sprite_effects, rng=rng)

            # projectile_update uses creature_find_in_radius(..., 8.0, ...)
            hit_idx: int | None = None
            for idx in creature_spatial.candidate_indices(pos=entry.pos, radius=8.0):
                creature = creatures[int(idx)]
                if not _creature_is_collidable(creature):
                    continue
                if within_native_find_radius(
                    origin=entry.pos,
                    target=creature.pos,
                    radius=8.0,
                    target_size=float(creature.size),
                ):
                    hit_idx = idx
                    break
            if hit_idx is not None:
                hit_count += 1
                if creature_lifecycle_is_alive(creatures[int(hit_idx)].death_timer):
                    runtime_state.shots_hit += 1

                if freeze_active:
                    for _ in range(4):
                        shard_angle = x87_pc24_mul(
                            float(rng.rand_tagged(RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_FREEZE_SHARD_ANGLE) % 612),
                            f32(0.01),
                        )
                        effects.spawn_freeze_shard(
                            pos=entry.pos,
                            angle=shard_angle,
                            rng=rng,
                            detail_preset=int(detail_preset),
                        )
                else:
                    for dx_caller, dy_caller in _SECONDARY_PRE_HIT_DECAL_CALLERS:
                        offset = Vec2(
                            float(rng.rand_tagged(dx_caller) % 20 - 10),
                            float(rng.rand_tagged(dy_caller) % 20 - 10),
                        )
                        fx_queue.add_random(
                            pos=creatures[hit_idx].pos + offset,
                            rng=rng,
                        )

                match type_id:
                    case SecondaryProjectileTypeId.ROCKET:
                        damage = x87_pc24_add(x87_pc24_mul(entry.life_timer, 50.0), 500.0)
                        if detail_preset >= 3:
                            effects.spawn_explosion_burst(pos=entry.pos, scale=0.4, rng=rng, detail_preset=detail_preset)
                    case SecondaryProjectileTypeId.HOMING_ROCKET:
                        damage = x87_pc24_add(x87_pc24_mul(entry.life_timer, 20.0), 80.0)
                    case SecondaryProjectileTypeId.ROCKET_MINIGUN:
                        damage = x87_pc24_add(x87_pc24_mul(entry.life_timer, 20.0), 40.0)
                    case _:
                        damage = 150.0

                step_runtime.play_secondary_rocket_hit_audio(entry.pos)

                inv_dt = f32(1.0 / float(dt))
                impulse = Vec2(
                    x87_pc24_mul(inv_dt, entry.vel.x),
                    x87_pc24_mul(inv_dt, entry.vel.y),
                )
                creature_apply_damage(step_runtime, hit_idx, damage, CreatureDamageType.EXPLOSION, impulse)
                creature_spatial.sync_index(int(hit_idx))

                # Each rocket type detonates at its own scale, with freeze shards or scorch decals.
                center = creatures[hit_idx].pos
                match type_id:
                    case SecondaryProjectileTypeId.ROCKET:
                        det_scale, shard_pos, decal_count = 1.0, entry.pos, 20
                        shard_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_FREEZE_SHARD_ANGLE
                        angle_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_ANGLE
                        radius_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_RADIUS
                        radius_mod = 90
                    case SecondaryProjectileTypeId.HOMING_ROCKET:
                        det_scale, shard_pos, decal_count = 0.35, entry.pos, 10
                        shard_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_FREEZE_SHARD_ANGLE
                        angle_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_DECAL_ANGLE
                        radius_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_DECAL_RADIUS
                        radius_mod = 64
                    case SecondaryProjectileTypeId.ROCKET_MINIGUN:
                        det_scale, shard_pos, decal_count = 0.25, center, 3
                        shard_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_FREEZE_SHARD_ANGLE
                        angle_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_DECAL_ANGLE
                        radius_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_DECAL_RADIUS
                        radius_mod = 44
                    case _:
                        det_scale, shard_pos, decal_count = 0.5, entry.pos, 0
                        shard_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_FREEZE_SHARD_ANGLE
                        angle_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_ANGLE
                        radius_caller = RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_RADIUS
                        radius_mod = 1
                entry.type_id = SecondaryProjectileTypeId.DETONATION
                entry.vel = Vec2(0.0, f32(det_scale))
                entry.detonation_t = 0.0
                entry.detonation_scale = f32(det_scale)
                if freeze_active:
                    for _ in range(8):
                        shard_angle = x87_pc24_mul(float(rng.rand_tagged(shard_caller) % 612), f32(0.01))
                        effects.spawn_freeze_shard(pos=shard_pos, angle=shard_angle, rng=rng, detail_preset=detail_preset)
                else:
                    for _ in range(decal_count):
                        # Native: `(float)(crt_rand() % 628) * 0.01f`, then `cos(angle) * radius` added at PC24.
                        angle = x87_pc24_mul(float(rng.rand_tagged(angle_caller) % 628), f32(0.01))
                        radius = float(rng.rand_tagged(radius_caller) % radius_mod)
                        decal_pos = Vec2(
                            x87_pc24_add(x87_pc24_cos_mul(angle, radius), center.x),
                            x87_pc24_add(x87_pc24_sin_mul(angle, radius), center.y),
                        )
                        fx_queue.add_random(pos=decal_pos, rng=rng)

                step = math.tau / 10.0
                for idx in range(10):
                    mag = (
                        float(
                            rng.rand_tagged(RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG)
                            % 800,
                        )
                        * 0.1
                    )
                    ang = float(idx) * step
                    velocity = Vec2.from_angle(ang) * mag
                    sprite_effects.spawn(
                        pos=entry.pos,
                        vel=velocity,
                        scale=14.0,
                        color=RGBA(1.0, 1.0, 1.0, 0.37),
                        rng=rng,
                    )

            # Native's TTL check runs after the hit handling in the same
            # iteration (no early-out): a rocket that hits while its TTL is
            # already spent gets its detonation scale overwritten to 0.5, and
            # exactly-zero TTL detonates this tick (<=, not <).
            if entry.life_timer <= 0.0:
                entry.type_id = SecondaryProjectileTypeId.DETONATION
                entry.vel = Vec2(0.0, 0.5)
                entry.detonation_t = 0.0
                entry.detonation_scale = 0.5
        return hit_count
