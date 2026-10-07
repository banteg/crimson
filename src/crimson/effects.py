from __future__ import annotations

import math
from enum import IntEnum
from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.rand import CallerStatic, CrandLike

from .creatures.damage import creature_apply_damage
from .creatures.damage_types import CreatureDamageType
from .creatures.lifecycle import creature_lifecycle_is_collidable
from .creatures.spatial_hash import CreatureSpatialHash
from .effects_atlas import EffectId
from .math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    NATIVE_TAU,
    f32,
    f32_vec2,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_div,
    x87_pc24_mul,
    x87_pc24_mul_chain,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from .rng_caller_static import RngCallerStatic

if TYPE_CHECKING:
    from .sim.world_state import WorldStepRuntime

__all__ = [
    "EFFECT_POOL_SIZE",
    "FX_QUEUE_CAPACITY",
    "FX_QUEUE_MAX_COUNT",
    "FX_QUEUE_ROTATED_CAPACITY",
    "FX_QUEUE_ROTATED_MAX_COUNT",
    "PARTICLE_POOL_SIZE",
    "SPRITE_EFFECT_POOL_SIZE",
    "EffectEntry",
    "EffectPool",
    "EffectTemplate",
    "FxQueue",
    "FxQueueEntry",
    "FxQueueRotated",
    "FxQueueRotatedEntry",
    "Particle",
    "ParticlePool",
    "ParticleStyleId",
    "SpriteEffect",
    "SpriteEffectPool",
]

EFFECT_POOL_SIZE = 0x200
PARTICLE_POOL_SIZE = 0x80
SPRITE_EFFECT_POOL_SIZE = 0x180

FX_QUEUE_CAPACITY = 0x80
FX_QUEUE_MAX_COUNT = 0x7F

FX_QUEUE_ROTATED_CAPACITY = 0x40
FX_QUEUE_ROTATED_MAX_COUNT = 0x3F

_NATIVE_PARTICLE_SPIN_SCALE = f32(0.01)
_NATIVE_SPRITE_ROTATION_SCALE = f32(0.01)


def _native_particle_velocity(angle: float, speed: float) -> Vec2:
    angle_f32 = f32(angle)
    return Vec2(
        x87_pc24_cos_mul(angle_f32, speed),
        x87_pc24_sin_mul(angle_f32, speed),
    )


def _native_particle_rotation(draw: int) -> float:
    return x87_pc24_mul(float(draw % 0x274), _NATIVE_PARTICLE_SPIN_SCALE)


def _native_clamp_unit(value: float) -> float:
    value = f32(value)
    if not value >= 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


class ParticleStyleId(IntEnum):
    FLAMETHROWER = 0
    BLOW_TORCH = 1
    HR_FLAMER = 2
    BUBBLEGUN = 8


class Particle(msgspec.Struct):
    active: bool = False
    in_flight: bool = False
    pos: Vec2 = Vec2()
    vel: Vec2 = Vec2()
    color_r: float = 1.0
    color_g: float = 1.0
    color_b: float = 1.0
    color_a: float = 0.0
    intensity: float = 0.0
    angle: float = 0.0
    rotation: float = 0.0
    style_id: ParticleStyleId = ParticleStyleId.FLAMETHROWER
    target_id: int = -1


class ParticlePool:
    def __init__(self) -> None:
        self._entries = [Particle() for _ in range(PARTICLE_POOL_SIZE)]

    @property
    def entries(self) -> list[Particle]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def _alloc_slot(self, *, caller: CallerStatic, rng: CrandLike) -> int:
        for i, entry in enumerate(self._entries):
            if not entry.active:
                return i
        # Native: `crt_rand() & 0x7f` (pool size is 0x80).
        return rng.rand_tagged(caller) % len(self._entries)

    def spawn_particle(
        self,
        *,
        pos: Vec2,
        angle: float,
        intensity: float = 1.0,
        rng: CrandLike,
    ) -> int:
        """Port of `fx_spawn_particle` (0x00420130)."""

        idx = self._alloc_slot(caller=RngCallerStatic.FX_SPAWN_PARTICLE_ALLOC, rng=rng)
        entry = self._entries[idx]
        angle_f32 = f32(angle)
        entry.active = True
        entry.in_flight = True
        entry.pos = f32_vec2(pos)
        entry.vel = _native_particle_velocity(angle_f32, 90.0)
        entry.color_r = 1.0
        entry.color_g = 1.0
        entry.color_b = 1.0
        entry.color_a = 0.0
        entry.intensity = f32(intensity)
        entry.angle = angle_f32
        entry.rotation = _native_particle_rotation(rng.rand_tagged(RngCallerStatic.FX_SPAWN_PARTICLE_ROTATION))
        entry.style_id = ParticleStyleId.FLAMETHROWER
        entry.target_id = -1
        return idx

    def spawn_particle_slow(
        self,
        *,
        pos: Vec2,
        angle: float,
        rng: CrandLike,
    ) -> int:
        """Port of `fx_spawn_particle_slow` (0x00420240)."""

        idx = self._alloc_slot(caller=RngCallerStatic.FX_SPAWN_PARTICLE_SLOW_ALLOC, rng=rng)
        entry = self._entries[idx]
        angle_f32 = f32(angle)
        entry.active = True
        entry.in_flight = True
        entry.pos = f32_vec2(pos)
        entry.vel = _native_particle_velocity(angle_f32, 30.0)
        entry.color_r = 1.0
        entry.color_g = 1.0
        entry.color_b = 1.0
        entry.color_a = 0.0
        entry.intensity = 1.0
        entry.angle = angle_f32
        entry.rotation = _native_particle_rotation(rng.rand_tagged(RngCallerStatic.FX_SPAWN_PARTICLE_SLOW_ROTATION))
        entry.style_id = ParticleStyleId.BUBBLEGUN
        entry.target_id = -1
        return idx

    def iter_active(self) -> list[Particle]:
        return [entry for entry in self._entries if entry.active]

    def update(self, dt: float, *, step_runtime: WorldStepRuntime) -> list[int]:
        """Advance particles and deactivate expired entries.

        This is a minimal port of the particle loop inside `projectile_update`
        (0x00420b90). It captures the per-style decay/movement rules that drive
        visual lifetimes and the weapon-driven collision damage.

        Returns indices of particles that were deactivated this tick.
        """

        if dt <= 0.0:
            return []
        dt = f32(dt)
        creatures = step_runtime.world.creatures.entries
        fx_queue = step_runtime.fx_queue
        sprite_effects = step_runtime.world.state.sprite_effects
        rng = step_runtime.world.state.rng

        expired: list[int] = []
        creature_spatial: CreatureSpatialHash | None = None

        for idx, entry in enumerate(self._entries):
            if not entry.active:
                continue

            style = int(entry.style_id) & 0xFF

            bubblegun = style == int(ParticleStyleId.BUBBLEGUN)
            decay = f32(0.11 if bubblegun else 0.9)
            entry.intensity = x87_pc24_sub(entry.intensity, x87_pc24_mul(dt, decay))
            entry.rotation = x87_pc24_add(entry.rotation, x87_pc24_mul(dt, 5.0) if bubblegun else dt)
            if not bubblegun or entry.in_flight:
                # The SDK vector chain multiplies dt into velocity first, with
                # PC=24 rounding at each operation before adding the position.
                if bubblegun:
                    factors = (entry.intensity,) if entry.intensity > f32(0.15) else (f32(0.55), entry.intensity)
                else:
                    factors = (2.5, max(entry.intensity, f32(0.15)))
                move_x = x87_pc24_mul_chain(dt, entry.vel.x, *factors)
                move_y = x87_pc24_mul_chain(dt, entry.vel.y, *factors)
                entry.pos = Vec2(
                    x87_pc24_add(entry.pos.x, move_x),
                    x87_pc24_add(entry.pos.y, move_y),
                )

            alive = entry.intensity > (0.0 if style == int(ParticleStyleId.FLAMETHROWER) else f32(0.8))
            if not alive:
                entry.active = False
                expired.append(idx)
                if style == int(ParticleStyleId.BUBBLEGUN) and entry.target_id != -1:
                    target_id = int(entry.target_id)
                    if 0 <= target_id < len(creatures):
                        if creatures[target_id].active:
                            sound_slot = int(
                                rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BUBBLEGUN_EXPIRY_SFX) % 3,
                            )
                            step_runtime.on_bubblegun_expiry_sfx(target_id, sound_slot)
                        # Death history and forced bonuses precede the native active check.
                        step_runtime.world.creatures.handle_death(step_runtime, target_id, keep_corpse=False)
                continue

            if entry.in_flight:
                # Random walk drift (native adjusts angle based on `crt_rand`).
                jitter_caller = RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_ALT
                if style == int(ParticleStyleId.FLAMETHROWER):
                    jitter_caller = RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_FLAMETHROWER
                elif style == int(ParticleStyleId.BUBBLEGUN):
                    jitter_caller = RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_BUBBLEGUN
                turn = rng.rand_tagged(jitter_caller) % 100 - 50
                turn_scale = f32(1.96 if style == int(ParticleStyleId.FLAMETHROWER) else 1.1)
                jitter = x87_pc24_mul_chain(float(turn), f32(0.06), entry.intensity, dt, turn_scale)
                entry.angle = x87_pc24_sub(entry.angle, jitter)
                entry.vel = _native_particle_velocity(entry.angle, 62.0 if bubblegun else 82.0)

            alpha = clamp(entry.intensity, 0.0, 1.0)
            shade = x87_pc24_sub(1.0, x87_pc24_mul(entry.intensity, f32(0.95)))
            entry.color_a = alpha
            entry.color_r = shade
            entry.color_g = shade
            # Native only updates color_r/color_g; color_b stays at its spawn value (1.0).

            if entry.in_flight:
                if creature_spatial is None:
                    creature_spatial = CreatureSpatialHash(
                        pool=step_runtime.world.creatures,
                        is_collidable=lambda c: c.active and creature_lifecycle_is_collidable(c.death_timer),
                    )
                hit_idx = creature_spatial.find_in_radius(
                    pos=entry.pos, radius=max(float(entry.intensity), 0.0) * 8.0,
                )
                if hit_idx != -1:
                    entry.in_flight = False
                    creature = creatures[hit_idx]
                    if style == int(ParticleStyleId.BUBBLEGUN):
                        entry.target_id = int(hit_idx)
                        entry.pos = creature.pos
                        entry.vel = Vec2()
                    else:
                        # Native wraps the stored angle iteratively with the f32
                        # tau literal (6.2831855), keeps the atan2 hit angle in
                        # extended precision for its wrap, and deflects by the
                        # f32 constant 1.2566371.
                        angle = float(entry.angle)
                        while float(NATIVE_TAU) < angle:
                            angle = f32(angle - float(NATIVE_TAU))
                        while angle < 0.0:
                            angle = f32(angle + float(NATIVE_TAU))
                        entry.angle = angle
                        hit_x = x87_pc24_sub(
                            x87_pc24_sub(entry.pos.x, x87_pc24_mul(dt, entry.vel.x)),
                            creature.pos.x,
                        )
                        hit_y = x87_pc24_sub(
                            x87_pc24_sub(entry.pos.y, x87_pc24_mul(dt, entry.vel.y)),
                            creature.pos.y,
                        )
                        hit_angle = math.atan2(hit_y, hit_x)
                        while float(NATIVE_TAU) < hit_angle:
                            hit_angle = x87_pc24_sub(hit_angle, NATIVE_TAU)
                        while hit_angle < 0.0:
                            hit_angle = x87_pc24_add(hit_angle, NATIVE_TAU)
                        deflect_step = f32(1.2566371)
                        if float(entry.angle) <= hit_angle:
                            entry.angle = f32(float(entry.angle) + deflect_step)
                        else:
                            entry.angle = f32(float(entry.angle) - deflect_step)

                        bounce_velocity = _native_particle_velocity(entry.angle, 82.0)
                        speed_scale = x87_pc24_mul(
                            float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BOUNCE_SPEED_SCALE) % 10),
                            f32(0.1),
                        )
                        entry.vel = Vec2(
                            x87_pc24_mul(bounce_velocity.x, speed_scale),
                            x87_pc24_mul(bounce_velocity.y, speed_scale),
                        )

                        damage = max(0.0, x87_pc24_mul(entry.intensity, 10.0))
                        if damage > 0.0:
                            creature_apply_damage(
                                step_runtime, hit_idx, damage, CreatureDamageType.FIRE, Vec2(),
                            )

                        tint = creature.tint
                        tint_r = f32(tint.r)
                        tint_g = f32(tint.g)
                        tint_b = f32(tint.b)
                        tint_sum = x87_pc24_add(x87_pc24_add(tint_g, tint_b), tint_r)
                        if tint_sum > f32(1.6):
                            factor = x87_pc24_sub(1.0, x87_pc24_mul(entry.intensity, f32(0.01)))
                            creature.tint = RGBA(
                                _native_clamp_unit(x87_pc24_mul(factor, tint_r)),
                                _native_clamp_unit(x87_pc24_mul(factor, tint_g)),
                                _native_clamp_unit(x87_pc24_mul(factor, tint_b)),
                                _native_clamp_unit(tint.a),
                            )

                        if idx % 3 == 0:
                            sprite_vel = Vec2(
                                float(
                                    rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_SPRITE_VEL_X) % 60 - 30,
                                ),
                                float(
                                    rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_SPRITE_VEL_Y) % 60 - 30,
                                ),
                            )
                            sprite_effects.spawn(
                                pos=creature.pos,
                                vel=sprite_vel,
                                scale=13.0,
                                color=RGBA(1.0, 1.0, 1.0, 0.7),
                                rng=rng,
                            )

                        fx_queue.add_random(
                            pos=creature.pos,
                            rng=rng,
                        )

                        creature.pos = Vec2(
                            x87_pc24_add(creature.pos.x, x87_pc24_mul(entry.vel.x, dt)),
                            x87_pc24_add(creature.pos.y, x87_pc24_mul(entry.vel.y, dt)),
                        )

        return expired


class SpriteEffect(msgspec.Struct):
    active: bool = False
    color: RGBA = msgspec.field(default_factory=lambda: RGBA(a=0.0))
    rotation: float = 0.0
    pos: Vec2 = Vec2()
    vel: Vec2 = Vec2()
    scale: float = 1.0


class SpriteEffectPool:
    def __init__(self) -> None:
        self._entries = [SpriteEffect() for _ in range(SPRITE_EFFECT_POOL_SIZE)]

    @property
    def entries(self) -> list[SpriteEffect]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def spawn(self, *, pos: Vec2, vel: Vec2, scale: float = 1.0, color: RGBA | None = None, rng: CrandLike) -> int:
        """Port of `fx_spawn_sprite` (0x0041fbb0)."""

        idx = None
        for i, entry in enumerate(self._entries):
            if not entry.active:
                idx = i
                break
        if idx is None:
            idx = rng.rand_tagged(RngCallerStatic.FX_SPAWN_SPRITE_ALLOC) % len(self._entries)

        entry = self._entries[idx]
        entry.active = True
        entry.color = RGBA() if color is None else RGBA(f32(color.r), f32(color.g), f32(color.b), f32(color.a))
        entry.rotation = x87_pc24_mul(
            float(rng.rand_tagged(RngCallerStatic.FX_SPAWN_SPRITE_ROTATION) % 628),
            _NATIVE_SPRITE_ROTATION_SCALE,
        )
        entry.pos = f32_vec2(pos)
        entry.vel = f32_vec2(vel)
        entry.scale = f32(scale)
        return idx

    def iter_active(self) -> list[SpriteEffect]:
        return [entry for entry in self._entries if entry.active]

    def update(self, dt: float) -> list[int]:
        if dt <= 0.0:
            return []

        # Sprite loop of projectile_update (0x0042246a): every field is f32 and
        # each op rounds at PC24, so alpha 0.25f lives 16 ticks at 60 Hz.
        dt = f32(dt)
        rotation_step = x87_pc24_mul(dt, f32(3.0))
        scale_step = x87_pc24_mul(dt, f32(60.0))
        expired: list[int] = []
        for idx, entry in enumerate(self._entries):
            if not entry.active:
                continue
            entry.pos = Vec2(
                x87_pc24_add(entry.pos.x, x87_pc24_mul(dt, entry.vel.x)),
                x87_pc24_add(entry.pos.y, x87_pc24_mul(dt, entry.vel.y)),
            )
            entry.rotation = x87_pc24_add(entry.rotation, rotation_step)
            entry.color = entry.color.with_alpha(x87_pc24_sub(entry.color.a, dt))
            entry.scale = x87_pc24_add(entry.scale, scale_step)
            if entry.color.a <= 0.0:
                entry.active = False
                expired.append(idx)
        return expired


class FxQueueEntry(msgspec.Struct):
    effect_id: int = 0
    rotation: float = 0.0
    pos: Vec2 = Vec2()
    height: float = 0.0
    width: float = 0.0
    color: RGBA = msgspec.field(default_factory=RGBA)


class FxQueue:
    """Per-frame terrain decal queue (`fx_queue` / `fx_queue_add`)."""

    def __init__(self) -> None:
        self._entries = [FxQueueEntry() for _ in range(FX_QUEUE_CAPACITY)]
        self._count = 0
        # Mirrors native `config_violence_disabled` gate in `fx_queue_add_random`.
        # Nonzero suppresses violence-linked random decals.
        self.violence_disabled = 0

    @property
    def entries(self) -> list[FxQueueEntry]:
        return self._entries

    @property
    def count(self) -> int:
        return self._count

    def clear(self) -> None:
        self._count = 0

    def iter_active(self) -> list[FxQueueEntry]:
        return self._entries[: self._count]

    def add(
        self,
        *,
        effect_id: int,
        pos: Vec2,
        width: float,
        height: float,
        rotation: float,
        rgba: RGBA,
    ) -> bool:
        """Port of `fx_queue_add` (0x0041e840)."""

        if self._count >= FX_QUEUE_MAX_COUNT:
            return False

        entry = self._entries[self._count]
        entry.effect_id = int(effect_id)
        entry.rotation = float(rotation)
        entry.pos = pos
        entry.height = float(height)
        entry.width = float(width)
        entry.color = rgba
        self._count += 1
        return True

    def add_random(self, *, pos: Vec2, rng: CrandLike) -> bool:
        """Port of `fx_queue_add_random` (effect ids 3..7 with grayscale tint)."""
        if int(self.violence_disabled) != 0:
            return False
        # Native `fx_queue_add_random` always consumes RNG even when the queue
        # is full, then lets `fx_queue_add` fail silently.
        gray = x87_pc24_add(
            x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY) & 0xF), f32(0.01)),
            f32(0.84),
        )
        w = float(rng.rand_tagged(RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH) % 24 - 12) + 30.0
        rotation = x87_pc24_mul(
            float(rng.rand_tagged(RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION) % 628),
            f32(0.01),
        )
        effect_id = rng.rand_tagged(RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID) % 5 + 3
        return self.add(
            effect_id=effect_id,
            pos=pos,
            width=w,
            height=w,
            rotation=rotation,
            # Native keeps the statically initialized alpha (0x3f47ae14);
            # only the gray channels are re-rolled per call.
            rgba=RGBA(gray, gray, gray, 0.7799999713897705),
        )


class FxQueueRotatedEntry(msgspec.Struct):
    top_left: Vec2 = Vec2()
    color: RGBA = msgspec.field(default_factory=RGBA)
    rotation: float = 0.0
    scale: float = 1.0
    creature_type_id: int = 0


class FxQueueRotated:
    """Rotated corpse queue (`fx_queue_rotated` / `fx_queue_add_rotated`)."""

    def __init__(self) -> None:
        self._entries = [FxQueueRotatedEntry() for _ in range(FX_QUEUE_ROTATED_CAPACITY)]
        self._count = 0
        # Native `cv_terrainBodiesTransparency`: 0 scales corpse alpha by 0.8, otherwise by its reciprocal.
        self.bodies_transparency = 0.0

    @property
    def entries(self) -> list[FxQueueRotatedEntry]:
        return self._entries

    @property
    def count(self) -> int:
        return self._count

    def clear(self) -> None:
        self._count = 0

    def iter_active(self) -> list[FxQueueRotatedEntry]:
        return self._entries[: self._count]

    def add(
        self,
        *,
        top_left: Vec2,
        rgba: RGBA,
        rotation: float,
        scale: float,
        creature_type_id: int,
        terrain_texture_failed: bool = False,
    ) -> bool:
        """Port of `fx_queue_add_rotated` (0x00427840)."""

        if terrain_texture_failed:
            # Native skips the queue write but still reports success.
            return True
        if self._count >= FX_QUEUE_ROTATED_MAX_COUNT:
            return False

        transparency = f32(self.bodies_transparency)
        # Native divides first, then multiplies at gameplay PC=24 precision.
        alpha_scale = x87_pc24_div(1.0, transparency) if transparency != 0.0 else f32(0.8)
        a = x87_pc24_mul(f32(rgba.a), alpha_scale)

        entry = self._entries[self._count]
        entry.top_left = f32_vec2(top_left)
        entry.color = RGBA(f32(rgba.r), f32(rgba.g), f32(rgba.b), a)
        entry.rotation = f32(rotation)
        entry.scale = f32(scale)
        entry.creature_type_id = int(creature_type_id)

        self._count += 1
        return True



class EffectEntry(msgspec.Struct):
    """Native `effect_entry_t`; the defaults are its zeroed static storage."""

    pos: Vec2 = Vec2()
    effect_id: int = 0
    vel: Vec2 = Vec2()
    rotation: float = 0.0
    scale: float = 0.0
    half_width: float = 0.0
    half_height: float = 0.0
    age: float = 0.0
    lifetime: float = 0.0
    flags: int = 0
    color: RGBA = RGBA(0.0, 0.0, 0.0, 0.0)
    rotation_step: float = 0.0
    scale_step: float = 0.0
    # Native `next_free`: the entry index after this one on the free list, -1 for null.
    next_free: int = -1


class EffectTemplate(msgspec.Struct):
    """Native `effect_template`: the fields `effect_spawn` copies into every new entry.

    Spawners overwrite only some fields; the rest keep whatever the previous spawner
    (or `effect_defaults_reset`) left. The slots are float32: `effect_spawn` rounds
    them on the copy.
    """

    vel: Vec2 = Vec2()
    rotation: float = 0.0
    scale: float = 0.0
    half_width: float = 0.0
    half_height: float = 0.0
    age: float = 0.0
    lifetime: float = 0.0
    flags: int = 0
    color: RGBA = RGBA(0.0, 0.0, 0.0, 0.0)
    rotation_step: float = 0.0
    scale_step: float = 0.0


class EffectPool:
    """Effect pool (`effect_spawn`, `effects_update`).

    This pool renders transient particle quads and can optionally enqueue decals
    into `FxQueue` on expiry (flags bit `0x80`).
    """

    def __init__(self) -> None:
        self._entries = [EffectEntry() for _ in range(EFFECT_POOL_SIZE)]
        self.template = EffectTemplate()
        self._free_head = 0
        # Native `effect_spawn_detail_skip_counter`: `effect_defaults_reset` leaves it alone, and native never
        # resets it for the whole process. This one starts with each world so replays need not record it
        # (docs/rewrite/replay-run-start.md).
        self._detail_skip_counter = 0
        self.reset()

    @property
    def entries(self) -> list[EffectEntry]:
        return self._entries

    def reset(self) -> None:
        """Port of `effect_defaults_reset` (`game_core_init`, `gameplay_reset_state`).

        The free list is rebuilt as 0 -> 1 -> ... -> 511. The last entry is never
        initialized or linked onward: its null `next_free` ends the list, so at most
        511 entries are live and a spawn with the last entry at the head is discarded.
        """

        template = self.template
        template.color = RGBA(1.0, 1.0, 1.0, 1.0)
        template.flags = 1
        template.rotation = 0.0
        template.scale = 1.0
        template.age = 0.0
        template.lifetime = 0.5
        template.half_height = 32.0
        template.half_width = 32.0
        template.rotation_step = 1.0
        template.scale_step = 1.0
        template.vel = Vec2()

        for index in range(EFFECT_POOL_SIZE - 1):
            entry = self._entries[index]
            entry.next_free = index + 1
            # `effect_init_entry`.
            entry.flags = 0
            entry.age = 0.0
            entry.rotation = 0.0
            entry.scale = 1.0
            entry.color = RGBA(1.0, 1.0, 1.0, 1.0)
        self._free_head = 0

    def iter_active(self) -> list[EffectEntry]:
        return [entry for entry in self._entries if entry.flags]

    def spawn(self, effect_id: int, pos: Vec2, detail_preset: int) -> None:
        """Port of `effect_spawn` (0x0042e120): pop the free-list head and copy the whole template into it.

        Low detail presets skip every other spawn. With the free list down to its last
        entry the spawn lands in `effect_discard_entry`, which nothing updates or draws.
        """

        if detail_preset <= 2:
            skip = self._detail_skip_counter & 1
            self._detail_skip_counter += 1
            if skip:
                return

        entry = self._entries[self._free_head]
        if entry.next_free == -1:
            return
        self._free_head = entry.next_free

        template = self.template
        entry.vel = f32_vec2(template.vel)
        entry.rotation = f32(template.rotation)
        entry.scale = f32(template.scale)
        entry.half_width = f32(template.half_width)
        entry.half_height = f32(template.half_height)
        entry.age = f32(template.age)
        entry.lifetime = f32(template.lifetime)
        entry.flags = template.flags
        color = template.color
        entry.color = RGBA(f32(color.r), f32(color.g), f32(color.b), f32(color.a))
        entry.rotation_step = f32(template.rotation_step)
        entry.scale_step = f32(template.scale_step)
        entry.pos = f32_vec2(pos)
        entry.effect_id = int(effect_id)

    def free(self, idx: int) -> None:
        """Port of `effect_free`: push the entry onto the free-list head."""

        entry = self._entries[idx]
        entry.next_free = self._free_head
        entry.flags = 0
        self._free_head = idx

    def update(self, dt: float, *, fx_queue: FxQueue | None = None) -> None:
        """Advance active effects and enqueue terrain decals on expiry."""

        dt_f32 = f32(dt)

        for idx, entry in enumerate(self._entries):
            flags = int(entry.flags)
            if not flags:
                continue

            age = f32(f32(entry.age) + dt_f32)
            entry.age = age
            lifetime = f32(entry.lifetime)

            if age < lifetime:
                if age >= 0.0:
                    move_x = f32(dt_f32 * f32(entry.vel.x))
                    move_y = f32(dt_f32 * f32(entry.vel.y))
                    entry.pos = Vec2(
                        f32(f32(entry.pos.x) + move_x),
                        f32(f32(entry.pos.y) + move_y),
                    )
                    if flags & 0x4:
                        rotation_delta = f32(dt_f32 * f32(entry.rotation_step))
                        entry.rotation = f32(f32(entry.rotation) + rotation_delta)
                    if flags & 0x8:
                        scale_delta = f32(dt_f32 * f32(entry.scale_step))
                        entry.scale = f32(f32(entry.scale) + scale_delta)
                    if flags & 0x10:
                        next_alpha = f32(1.0 - f32(age / lifetime))
                        entry.color = entry.color.with_alpha(next_alpha)
                continue

            if fx_queue is not None and (flags & 0x80):
                # On expiry, the native code overrides alpha before queuing.
                alpha = f32(0.35 if (flags & 0x100) else 0.8)
                entry.color = entry.color.with_alpha(alpha)
                fx_queue.add(
                    effect_id=int(entry.effect_id),
                    pos=entry.pos,
                    width=f32(f32(entry.half_width) + f32(entry.half_width)),
                    height=f32(f32(entry.half_height) + f32(entry.half_height)),
                    rotation=f32(entry.rotation),
                    rgba=entry.color,
                )

            self.free(idx)

    def spawn_shell_casing(
        self,
        *,
        pos: Vec2,
        aim_heading: float,
        rng: CrandLike,
        detail_preset: int,
    ) -> None:
        """Port of the weapon-flag-1 casing spawn in `player_update` (effect id 0x12); `scale` is inherited."""

        angle = x87_pc24_add(
            x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_ANGLE) & 0x3F), f32(0.01)),
            aim_heading,
        )
        speed = x87_pc24_add(
            x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_SPEED) & 0x3F), f32(0.022727273)),
            1.0,
        )
        template = self.template
        template.flags = 0x1C5
        template.color = RGBA(1.0, 1.0, 1.0, 0.6)
        template.lifetime = 0.15
        template.age = 0.0
        # Native stores the `cos * speed` drift before scaling it by 100.
        drift = Vec2(x87_pc24_cos_mul(angle, speed), x87_pc24_sin_mul(angle, speed))
        template.rotation = x87_pc24_mul(
            float((rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_ROTATION) & 0x3F) - 0x20), f32(0.1),
        )
        template.half_height = 2.0
        template.half_width = 2.0
        template.vel = Vec2(x87_pc24_mul(drift.x, 100.0), x87_pc24_mul(drift.y, 100.0))
        template.rotation_step = x87_pc24_mul(
            x87_pc24_sub(
                x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_CASING_ROTATION_STEP) % 20), f32(0.1)),
                1.0,
            ),
            14.0,
        )
        template.scale_step = 0.0
        self.spawn(EffectId.CASING, pos, detail_preset)

    def spawn_blood_splatter(
        self,
        *,
        pos: Vec2,
        angle: float,
        age: float,
        rng: CrandLike,
        detail_preset: int,
        violence_disabled: int,
    ) -> None:
        """Port of `effect_spawn_blood_splatter` (0x0042eb10); `scale` is inherited."""

        if int(violence_disabled) != 0:
            return

        template = self.template
        template.lifetime = x87_pc24_sub(0.25, f32(age))
        base = x87_pc24_add(f32(angle), NATIVE_PI)
        # The native helper stores both trig results before multiplying them
        # by each particle's independently sampled speed.
        direction_cos = f32(math.cos(base))
        template.flags = 0xC9
        template.color = RGBA(1.0, 1.0, 1.0, 0.5)
        template.scale_step = 0.0
        template.age = age
        direction_sin = f32(math.sin(base))

        for _ in range(2):
            template.rotation = x87_pc24_add(
                x87_pc24_mul(
                    float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_ROTATION) & 0x3F) - 0x20),
                    f32(0.1),
                ),
                base,
            )
            half = float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_HALF) & 7) + 1)
            template.half_width = half
            template.half_height = half
            speed_x = float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_SPEED_X) & 0x3F) + 100)
            speed_y = float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_SPEED_Y) & 0x3F) + 100)
            template.vel = Vec2(x87_pc24_mul(direction_cos, speed_x), x87_pc24_mul(direction_sin, speed_y))
            template.rotation_step = 0.0
            template.scale_step = x87_pc24_add(
                x87_pc24_mul(
                    float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_SCALE_STEP) & 0x7F), f32(0.03),
                ),
                f32(0.1),
            )
            self.spawn(EffectId.BLOOD_SPLATTER, pos, detail_preset)

    def spawn_burst(
        self,
        *,
        pos: Vec2,
        count: int,
        rng: CrandLike,
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_burst` (0x0042ef60); `scale` and `rotation_step` are inherited."""

        template = self.template
        template.flags = 0x1D
        template.color = RGBA(0.4, 0.5, 1.0, 0.5)
        template.age = 0.0
        template.lifetime = 0.5
        template.half_width = 32.0
        template.half_height = 32.0

        for _ in range(count):
            template.rotation = x87_pc24_mul(
                float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BURST_ROTATION) & 0x7F), f32(0.049087387),
            )
            template.vel = Vec2(
                float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BURST_VEL_X) & 0x7F) - 0x40),
                float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BURST_VEL_Y) & 0x7F) - 0x40),
            )
            template.scale_step = x87_pc24_add(
                x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_BURST_SCALE_STEP) % 100), f32(0.01)),
                f32(0.1),
            )
            self.spawn(EffectId.BURST, pos, detail_preset)

    def spawn_freeze_shard(
        self,
        *,
        pos: Vec2,
        angle: float,
        rng: CrandLike,
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_freeze_shard` (0x0042ec80); `scale` is inherited."""

        template = self.template
        template.flags = 0x1CD
        template.color = RGBA(1.0, 1.0, 1.0, 0.5)
        template.lifetime = x87_pc24_add(
            x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_LIFETIME) & 0xF), f32(0.01)),
            f32(0.2),
        )
        template.age = 0.0
        template.half_width = 8.0
        template.half_height = 8.0

        angle = x87_pc24_add(f32(angle), NATIVE_PI)
        template.rotation = x87_pc24_add(
            x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION) % 100), f32(0.01)),
            angle,
        )
        half = float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_HALF) % 5 + 7)
        template.half_width = half
        template.half_height = half

        template.vel = Vec2(x87_pc24_cos_mul(angle, 114.0), x87_pc24_sin_mul(angle, 114.0))
        template.rotation_step = x87_pc24_mul(
            x87_pc24_sub(
                x87_pc24_mul(
                    float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION_STEP) % 20), f32(0.1),
                ),
                1.0,
            ),
            4.0,
        )
        # Native negates the integer before conversion, preserving positive zero.
        template.scale_step = x87_pc24_mul(
            float(-(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_SCALE_STEP) & 0xF)),
            f32(0.1),
        )

        self.spawn(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_EFFECT_ID) % 3 + 8, pos, detail_preset)

    def spawn_freeze_shatter(
        self,
        *,
        pos: Vec2,
        angle: float,
        rng: CrandLike,
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_freeze_shatter` (0x0042ee00); `scale` is inherited."""

        template = self.template
        template.flags = 0x5D
        template.color = RGBA(1.0, 1.0, 1.0, 0.5)
        template.age = 0.0
        template.lifetime = 1.1
        template.scale_step = 0.0

        for index in range(4):
            # Native `angle + (float)index * 1.57079637f`, and the rest, in single precision.
            template.rotation = x87_pc24_add(angle, x87_pc24_mul(float(index), NATIVE_HALF_PI))
            template.vel = Vec2(
                x87_pc24_cos_mul(template.rotation, 42.0),
                x87_pc24_sin_mul(template.rotation, 42.0),
            )
            half = float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHATTER_HALF) % 10 + 18)
            template.half_width = half
            template.half_height = half
            template.rotation_step = x87_pc24_mul(
                x87_pc24_sub(
                    x87_pc24_mul(
                        float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHATTER_ROTATION_STEP) % 20), f32(0.1),
                    ),
                    1.0,
                ),
                f32(1.9),
            )
            self.spawn(EffectId.FREEZE_SHATTER, pos, detail_preset)

        for _ in range(4):
            self.spawn_freeze_shard(
                pos=pos,
                angle=x87_pc24_mul(
                    float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_FREEZE_SHATTER_SHARD_ANGLE) % 612), f32(0.01),
                ),
                rng=rng,
                detail_preset=detail_preset,
            )

    def spawn_explosion_burst(
        self,
        *,
        pos: Vec2,
        scale: float,
        rng: CrandLike,
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_explosion_burst` (0x0042f6c0).

        The core and the flash inherit `rotation_step`, and every piece inherits `scale`.
        """

        scale = f32(scale)
        template = self.template

        template.flags = 0x19
        template.color = RGBA(0.6, 0.6, 0.6, 1.0)
        template.lifetime = 0.35
        template.age = -0.1
        template.half_width = 32.0
        template.half_height = 32.0
        template.rotation = 0.0
        template.vel = Vec2()
        template.scale_step = x87_pc24_mul(scale, 25.0)
        self.spawn(EffectId.RING, pos, detail_preset)

        template.flags = 0x5D
        template.color = RGBA(0.1, 0.1, 0.1, 1.0)
        template.rotation = 0.0
        template.vel = Vec2()

        if detail_preset > 3:
            shockwave_scale_step = x87_pc24_mul(scale, 5.0)
            for index in range(2):
                template.half_width = 32.0
                template.half_height = 32.0
                time_offset = x87_pc24_mul(float(index), f32(0.2))
                template.age = x87_pc24_sub(time_offset, 0.5)
                template.lifetime = x87_pc24_add(time_offset, f32(0.6))
                template.rotation = x87_pc24_mul(
                    float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_PUFF_ROTATION) % 614), f32(0.02),
                )
                template.rotation_step = 1.4
                template.scale_step = shockwave_scale_step
                self.spawn(EffectId.EXPLOSION_PUFF, pos, detail_preset)

        template.flags = 0x19
        template.color = RGBA(1.0, 1.0, 1.0, 1.0)
        template.age = 0.0
        template.lifetime = 0.3
        template.half_width = 32.0
        template.half_height = 32.0
        template.rotation = 0.0
        template.vel = Vec2()
        template.scale_step = x87_pc24_mul(scale, 45.0)
        self.spawn(EffectId.BURST, pos, detail_preset)

        template.flags = 0x1D
        template.color = RGBA(1.0, 1.0, 1.0, 1.0)
        template.lifetime = 0.7
        template.age = 0.0
        template.half_width = 32.0
        template.half_height = 32.0

        if detail_preset < 2:
            count = 1
        else:
            count = 3 + (detail_preset >= 4)

        for _ in range(count):
            template.rotation = x87_pc24_mul(
                float(rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_ROTATION) % 314), f32(0.02),
            )
            template.vel = Vec2(
                float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_VEL_X) & 0x3F) * 2 - 0x40),
                float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_VEL_Y) & 0x3F) * 2 - 0x40),
            )
            template.scale_step = x87_pc24_mul(
                float((rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_SCALE_STEP) - 3) & 7), scale,
            )
            template.rotation_step = float(
                (rng.rand_tagged(RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_ROTATION_STEP) + 3) & 7,
            )
            self.spawn(EffectId.EXPLOSION_BURST, pos, detail_preset)
