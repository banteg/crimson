from __future__ import annotations

import math
from typing import MutableSequence, Sequence

from grim.color import RGBA
from grim.geom import Vec2

from ...effects_atlas import EffectId
from ..types import (
    CreatureDamageApplier,
    Damageable,
    FxQueueLike,
    ProjectileRuntimeState,
    SECONDARY_PROJECTILE_POOL_SIZE,
    SecondaryDetonationKillHandler,
    SecondaryProjectile,
    SecondaryProjectileTypeId,
    _EffectsLike,
    _SpriteEffectsLike,
    _rng_zero,
)
from .collision import _apply_damage_to_creature, _creature_find_nearest_for_secondary, _within_native_find_radius

class SecondaryProjectilePool:
    def __init__(self, *, size: int = SECONDARY_PROJECTILE_POOL_SIZE) -> None:
        self._entries = [SecondaryProjectile() for _ in range(size)]

    @property
    def entries(self) -> list[SecondaryProjectile]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def spawn(
        self,
        *,
        pos: Vec2,
        angle: float,
        type_id: int,
        owner_id: int = -100,
        time_to_live: float = 2.0,
        target_hint: Vec2 | None = None,
        creatures: Sequence[Damageable] | None = None,
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
        entry.angle = float(angle)
        entry.type_id = int(type_id)
        entry.pos = pos
        entry.owner_id = int(owner_id)
        entry.target_id = -1
        entry.target_hint_active = False
        entry.target_hint = Vec2()
        entry.trail_timer = 0.0
        entry.vel = Vec2()
        entry.detonation_t = 0.0
        entry.detonation_scale = 1.0

        if entry.type_id == SecondaryProjectileTypeId.DETONATION:
            # Detonation uses explicit timer/scale fields now.
            entry.detonation_t = 0.0
            entry.detonation_scale = float(time_to_live)
            entry.speed = float(time_to_live)
            return index

        # Effects.md: vel = cos/sin(angle - PI/2) * 90 (190 for type 2).
        base_speed = 90.0
        if entry.type_id == SecondaryProjectileTypeId.HOMING_ROCKET:
            base_speed = 190.0
        entry.vel = Vec2.from_heading(float(angle)) * base_speed
        entry.speed = float(time_to_live)

        if entry.type_id == SecondaryProjectileTypeId.HOMING_ROCKET:
            # Native `fx_spawn_secondary_projectile` seeds seeker target_id at spawn via
            # `creature_find_nearest(&player_aim_x, -1, 0.0)`.
            if creatures is not None:
                origin = target_hint if target_hint is not None else pos
                entry.target_id = _creature_find_nearest_for_secondary(
                    creatures=creatures,
                    origin=origin,
                )
            elif target_hint is not None:
                # Keep legacy fallback for tests/debug views that omit creature snapshots.
                entry.target_hint_active = True
                entry.target_hint = target_hint

        return index

    def iter_active(self) -> list[SecondaryProjectile]:
        return [entry for entry in self._entries if entry.active]

    def update_pulse_gun(
        self,
        dt: float,
        creatures: Sequence[Damageable],
        *,
        apply_creature_damage: CreatureDamageApplier | None = None,
        runtime_state: ProjectileRuntimeState | None = None,
        fx_queue: FxQueueLike | None = None,
        detail_preset: int = 5,
        on_detonation_kill: SecondaryDetonationKillHandler | None = None,
    ) -> None:
        """Update the secondary projectile pool subset (types 1/2/4 + detonation type 3)."""

        if dt <= 0.0:
            return

        def _apply_secondary_damage(
            creature_index: int,
            damage: float,
            *,
            owner_id: int,
            impulse: Vec2 = Vec2(),
        ) -> None:
            _apply_damage_to_creature(
                creatures,
                int(creature_index),
                float(damage),
                damage_type=3,
                impulse=impulse,
                owner_id=int(owner_id),
                apply_creature_damage=apply_creature_damage,
            )

        rand = _rng_zero
        freeze_active = False
        effects: _EffectsLike | None = None
        sprite_effects: _SpriteEffectsLike | None = None
        sfx_queue: MutableSequence[str] | None = None
        if runtime_state is not None:
            rand = runtime_state.rng.rand
            freeze_active = float(runtime_state.bonuses.freeze) > 0.0
            effects = runtime_state.effects
            sprite_effects = runtime_state.sprite_effects
            sfx_queue = runtime_state.sfx_queue

        for entry in self._entries:
            if not entry.active:
                continue

            if entry.type_id == SecondaryProjectileTypeId.DETONATION:
                if runtime_state is not None:
                    runtime_state.camera_shake_pulses = 4

                entry.detonation_t += dt * 3.0
                t = float(entry.detonation_t)
                scale = float(entry.detonation_scale)
                if t > 1.0:
                    if fx_queue is not None:
                        fx_queue.add(
                            effect_id=int(EffectId.AURA),
                            pos=entry.pos,
                            width=float(scale) * 256.0,
                            height=float(scale) * 256.0,
                            rotation=0.0,
                            rgba=RGBA(0.0, 0.0, 0.0, 0.25),
                        )
                    entry.active = False

                radius = scale * t * 80.0
                radius_sq = radius * radius
                damage = dt * scale * 700.0
                for creature_idx, creature in enumerate(creatures):
                    if not creature.active:
                        continue
                    if creature.hp <= 0.0:
                        continue
                    d_sq = Vec2.distance_sq(entry.pos, creature.pos)
                    if d_sq < radius_sq:
                        hp_before = float(creature.hp)
                        impulse_dir = entry.pos.direction_to(creature.pos)
                        impulse = impulse_dir * 0.1
                        _apply_secondary_damage(
                            creature_idx,
                            damage,
                            owner_id=int(entry.owner_id),
                            impulse=impulse,
                        )
                        if on_detonation_kill is not None and hp_before > 0.0 and float(creature.hp) <= 0.0:
                            # Native detonation AoE does an extra two random decals and a
                            # second `creature_handle_death` call after the killing hit.
                            if fx_queue is not None:
                                fx_queue.add_random(pos=creature.pos, rand=rand)
                                fx_queue.add_random(pos=creature.pos, rand=rand)
                            on_detonation_kill(int(creature_idx))
                continue

            if entry.type_id not in (
                SecondaryProjectileTypeId.ROCKET,
                SecondaryProjectileTypeId.HOMING_ROCKET,
                SecondaryProjectileTypeId.ROCKET_MINIGUN,
            ):
                continue

            # Move.
            entry.pos = entry.pos + entry.vel * dt

            # Update velocity + countdown.
            speed_mag = entry.vel.length()
            if entry.type_id == SecondaryProjectileTypeId.ROCKET:
                if speed_mag < 500.0:
                    factor = 1.0 + dt * 3.0
                    entry.vel = entry.vel * factor
                entry.speed -= dt
            elif entry.type_id == SecondaryProjectileTypeId.ROCKET_MINIGUN:
                if speed_mag < 600.0:
                    factor = 1.0 + dt * 4.0
                    entry.vel = entry.vel * factor
                entry.speed -= dt
            else:
                # Type 2: homing projectile.
                target_id = entry.target_id
                if not (0 <= target_id < len(creatures)) or not creatures[target_id].active:
                    search_pos = entry.pos
                    if entry.target_hint_active:
                        entry.target_hint_active = False
                        search_pos = entry.target_hint
                    entry.target_id = _creature_find_nearest_for_secondary(
                        creatures=creatures,
                        origin=search_pos,
                    )
                    target_id = entry.target_id

                if 0 <= target_id < len(creatures):
                    target = creatures[target_id]
                    to_target = target.pos - entry.pos
                    target_dir, dist = to_target.normalized_with_length()
                    if dist > 1e-6:
                        entry.angle = to_target.to_heading()
                        accel = target_dir * (dt * 800.0)
                        next_velocity = entry.vel + accel
                        if next_velocity.length() <= 350.0:
                            entry.vel = next_velocity

                entry.speed -= dt * 0.5

            # Rocket smoke trail (`trail_timer` in crimsonland.exe).
            entry.trail_timer -= (abs(entry.vel.x) + abs(entry.vel.y)) * dt * 0.01
            if entry.trail_timer < 0.0:
                direction = Vec2.from_heading(entry.angle)
                spawn_pos = entry.pos - direction * 9.0
                trail_velocity = Vec2.from_heading(entry.angle + math.pi) * 90.0
                if sprite_effects is not None:
                    sprite_effects.spawn(
                        pos=spawn_pos,
                        vel=trail_velocity,
                        scale=14.0,
                        color=RGBA(1.0, 1.0, 1.0, 0.25),
                    )
                entry.trail_timer = 0.06

            # projectile_update uses creature_find_in_radius(..., 8.0, ...)
            hit_idx: int | None = None
            for idx, creature in enumerate(creatures):
                if not creature.active:
                    continue
                # Native `creature_find_in_radius` also gates on `hitbox_size > 5.0`.
                if float(creature.hitbox_size) <= 5.0:
                    continue
                if _within_native_find_radius(
                    origin=entry.pos,
                    target=creature.pos,
                    radius=8.0,
                    target_size=float(creature.size),
                ):
                    hit_idx = idx
                    break
            if hit_idx is not None:
                if sfx_queue is not None:
                    sfx_queue.append("sfx_explosion_medium")

                hit_type_id = SecondaryProjectileTypeId(int(entry.type_id))

                det_scale = 0.5
                if entry.type_id == SecondaryProjectileTypeId.ROCKET:
                    det_scale = 1.0
                elif entry.type_id == SecondaryProjectileTypeId.HOMING_ROCKET:
                    det_scale = 0.35
                elif entry.type_id == SecondaryProjectileTypeId.ROCKET_MINIGUN:
                    det_scale = 0.25

                if freeze_active:
                    if effects is not None:
                        for _ in range(4):
                            shard_angle = float(int(rand()) % 0x264) * 0.01
                            effects.spawn_freeze_shard(
                                pos=entry.pos,
                                angle=shard_angle,
                                rand=rand,
                                detail_preset=int(detail_preset),
                            )
                elif fx_queue is not None:
                    for _ in range(3):
                        offset = Vec2(
                            float(int(rand()) % 0x14 - 10),
                            float(int(rand()) % 0x14 - 10),
                        )
                        fx_queue.add_random(
                            pos=creatures[hit_idx].pos + offset,
                            rand=rand,
                        )

                if (
                    entry.type_id == SecondaryProjectileTypeId.ROCKET
                    and effects is not None
                    and int(detail_preset) > 2
                ):
                    effects.spawn_explosion_burst(
                        pos=entry.pos,
                        scale=0.4,
                        rand=rand,
                        detail_preset=int(detail_preset),
                    )

                # Native `projectile_update` applies hit visuals before
                # `creature_apply_damage` for secondary projectiles.
                damage = 150.0
                if entry.type_id == SecondaryProjectileTypeId.ROCKET:
                    damage = entry.speed * 50.0 + 500.0
                elif entry.type_id == SecondaryProjectileTypeId.HOMING_ROCKET:
                    damage = entry.speed * 20.0 + 80.0
                elif entry.type_id == SecondaryProjectileTypeId.ROCKET_MINIGUN:
                    damage = entry.speed * 20.0 + 40.0
                _apply_secondary_damage(
                    hit_idx,
                    damage,
                    owner_id=int(entry.owner_id),
                    impulse=entry.vel / float(dt),
                )

                entry.type_id = SecondaryProjectileTypeId.DETONATION
                entry.vel = Vec2()
                entry.detonation_t = 0.0
                entry.detonation_scale = float(det_scale)
                entry.trail_timer = 0.0

                # Extra debris/scorch decals (or freeze shards) on detonation.
                if freeze_active:
                    if effects is not None:
                        shard_pos = entry.pos
                        if hit_type_id == SecondaryProjectileTypeId.ROCKET_MINIGUN:
                            shard_pos = creatures[hit_idx].pos
                        for _ in range(8):
                            shard_angle = float(int(rand()) % 0x264) * 0.01
                            effects.spawn_freeze_shard(
                                pos=shard_pos,
                                angle=shard_angle,
                                rand=rand,
                                detail_preset=int(detail_preset),
                            )
                else:
                    extra_decals = 0
                    extra_radius = 0.0
                    if entry.type_id == SecondaryProjectileTypeId.DETONATION:
                        # NOTE: entry.type_id is already 3 here; use det_scale based on prior type.
                        if det_scale == 1.0:
                            extra_decals = 0x14
                            extra_radius = 90.0
                        elif det_scale == 0.35:
                            extra_decals = 10
                            extra_radius = 64.0
                        elif det_scale == 0.25:
                            extra_decals = 3
                            extra_radius = 44.0
                    if fx_queue is not None and extra_decals > 0:
                        center = creatures[hit_idx].pos
                        for _ in range(int(extra_decals)):
                            angle = float(int(rand()) % 0x274) * 0.01
                            if det_scale == 0.35:
                                radius = float(int(rand()) & 0x3F)
                            else:
                                radius = float(int(rand()) % max(1, int(extra_radius)))
                            fx_queue.add_random(
                                pos=center + Vec2.from_angle(angle) * radius,
                                rand=rand,
                            )

                if sprite_effects is not None:
                    step = math.tau / 10.0
                    for idx in range(10):
                        mag = float(int(rand()) % 800) * 0.1
                        ang = float(idx) * step
                        velocity = Vec2.from_angle(ang) * mag
                        sprite_effects.spawn(
                            pos=entry.pos,
                            vel=velocity,
                            scale=14.0,
                            color=RGBA(1.0, 1.0, 1.0, 0.37),
                        )

                continue

            if entry.speed <= 0.0:
                entry.type_id = SecondaryProjectileTypeId.DETONATION
                entry.vel = Vec2()
                entry.detonation_t = 0.0
                entry.detonation_scale = 0.5
                entry.trail_timer = 0.0
