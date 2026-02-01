from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable, Protocol

__all__ = [
    "FX_QUEUE_CAPACITY",
    "FX_QUEUE_MAX_COUNT",
    "FX_QUEUE_ROTATED_CAPACITY",
    "FX_QUEUE_ROTATED_MAX_COUNT",
    "EFFECT_POOL_SIZE",
    "PARTICLE_POOL_SIZE",
    "SPRITE_EFFECT_POOL_SIZE",
    "FxQueue",
    "FxQueueEntry",
    "FxQueueRotated",
    "FxQueueRotatedEntry",
    "EffectEntry",
    "EffectPool",
    "Particle",
    "ParticlePool",
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


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _default_rand() -> int:
    return 0


class _CreatureForParticles(Protocol):
    active: bool
    x: float
    y: float
    hp: float
    size: float
    hitbox_size: float
    tint_r: float
    tint_g: float
    tint_b: float
    tint_a: float


CreatureDamageApplier = Callable[[int, float, int, float, float, int], None]
CreatureKillHandler = Callable[[int, int], None]


@dataclass(slots=True)
class Particle:
    active: bool = False
    render_flag: bool = False
    pos_x: float = 0.0
    pos_y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    scale_x: float = 1.0
    scale_y: float = 1.0
    scale_z: float = 1.0
    age: float = 0.0
    intensity: float = 0.0
    angle: float = 0.0
    spin: float = 0.0
    style_id: int = 0
    target_id: int = -1
    owner_id: int = -100


class ParticlePool:
    def __init__(self, *, size: int = PARTICLE_POOL_SIZE, rand: Callable[[], int] | None = None) -> None:
        self._entries = [Particle() for _ in range(int(size))]
        self._rand = rand or _default_rand

    @property
    def entries(self) -> list[Particle]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def _alloc_slot(self) -> int:
        for i, entry in enumerate(self._entries):
            if not entry.active:
                return i
        if not self._entries:
            raise ValueError("Particle pool has zero entries")
        # Native: `crt_rand() & 0x7f` (pool size is 0x80).
        return int(self._rand()) % len(self._entries)

    def spawn_particle(
        self,
        *,
        pos_x: float,
        pos_y: float,
        angle: float,
        intensity: float = 1.0,
        owner_id: int = -100,
    ) -> int:
        """Port of `fx_spawn_particle` (0x00420130)."""

        idx = self._alloc_slot()
        entry = self._entries[idx]
        entry.active = True
        entry.render_flag = True
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.vel_x = math.cos(angle) * 90.0
        entry.vel_y = math.sin(angle) * 90.0
        entry.scale_x = 1.0
        entry.scale_y = 1.0
        entry.scale_z = 1.0
        entry.age = 0.0
        entry.intensity = float(intensity)
        entry.angle = float(angle)
        entry.spin = float(int(self._rand()) % 0x274) * 0.01
        entry.style_id = 0
        entry.target_id = -1
        entry.owner_id = int(owner_id)
        return idx

    def spawn_particle_slow(
        self,
        *,
        pos_x: float,
        pos_y: float,
        angle: float,
        owner_id: int = -100,
    ) -> int:
        """Port of `fx_spawn_particle_slow` (0x00420240)."""

        idx = self._alloc_slot()
        entry = self._entries[idx]
        entry.active = True
        entry.render_flag = True
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.vel_x = math.cos(angle) * 30.0
        entry.vel_y = math.sin(angle) * 30.0
        entry.scale_x = 1.0
        entry.scale_y = 1.0
        entry.scale_z = 1.0
        entry.age = 0.0
        entry.intensity = 1.0
        entry.angle = float(angle)
        entry.spin = float(int(self._rand()) % 0x274) * 0.01
        entry.style_id = 8
        entry.target_id = -1
        entry.owner_id = int(owner_id)
        return idx

    def iter_active(self) -> list[Particle]:
        return [entry for entry in self._entries if entry.active]

    def update(
        self,
        dt: float,
        *,
        creatures: list[_CreatureForParticles] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
        kill_creature: CreatureKillHandler | None = None,
    ) -> list[int]:
        """Advance particles and deactivate expired entries.

        This is a minimal port of the particle loop inside `projectile_update`
        (0x00420b90). It captures the per-style decay/movement rules that drive
        visual lifetimes and the weapon-driven collision damage.

        Returns indices of particles that were deactivated this tick.
        """

        if dt <= 0.0:
            return []

        def _creature_find_in_radius(*, pos_x: float, pos_y: float, radius: float) -> int:
            if creatures is None:
                return -1
            max_index = min(len(creatures), 0x180)
            pos_x = float(pos_x)
            pos_y = float(pos_y)
            radius = float(radius)

            for creature_idx in range(max_index):
                creature = creatures[creature_idx]
                if not bool(getattr(creature, "active", False)):
                    continue
                if float(getattr(creature, "hp", 0.0)) <= 0.0:
                    continue
                if float(getattr(creature, "hitbox_size", 0.0)) < 5.0:
                    continue

                size = float(getattr(creature, "size", 50.0))
                dist = math.hypot(float(getattr(creature, "x", 0.0)) - pos_x, float(getattr(creature, "y", 0.0)) - pos_y) - radius
                threshold = size * 0.142857149 + 3.0
                if threshold < dist:
                    continue
                return int(creature_idx)

            return -1

        expired: list[int] = []
        rand = self._rand

        for idx, entry in enumerate(self._entries):
            if not entry.active:
                continue

            style = int(entry.style_id) & 0xFF

            if style == 8:
                entry.intensity -= dt * 0.11
                entry.spin += dt * 5.0
                move_scale = entry.intensity
                if move_scale <= 0.15:
                    move_scale *= 0.55
                entry.pos_x += entry.vel_x * dt * move_scale
                entry.pos_y += entry.vel_y * dt * move_scale
            else:
                entry.intensity -= dt * 0.9
                entry.spin += dt
                move_scale = max(entry.intensity, 0.15) * 2.5
                entry.pos_x += entry.vel_x * dt * move_scale
                entry.pos_y += entry.vel_y * dt * move_scale

            if entry.render_flag:
                # Random walk drift (native adjusts angle based on `crt_rand`).
                jitter = float(int(rand()) % 100 - 50) * 0.06 * max(entry.intensity, 0.0) * dt
                if style == 0:
                    jitter *= 1.96
                    speed = 82.0
                elif style == 8:
                    jitter *= 1.1
                    speed = 62.0
                else:
                    jitter *= 1.1
                    speed = 82.0
                entry.angle -= jitter
                entry.vel_x = math.cos(entry.angle) * speed
                entry.vel_y = math.sin(entry.angle) * speed

            alpha = _clamp(entry.intensity, 0.0, 1.0)
            shade = 1.0 - max(entry.intensity, 0.0) * 0.95
            entry.age = alpha
            entry.scale_x = shade
            entry.scale_y = shade
            # Native only updates scale_x/scale_y; scale_z stays at its spawn value (1.0).

            alive = entry.intensity > (0.0 if style == 0 else 0.8)
            if not alive:
                entry.active = False
                expired.append(idx)
                if style == 8 and entry.target_id != -1:
                    target_id = int(entry.target_id)
                    entry.target_id = -1
                    if kill_creature is not None:
                        kill_creature(target_id, int(entry.owner_id))
                    elif creatures is not None and 0 <= target_id < len(creatures):
                        creatures[target_id].hp = -1.0
                        creatures[target_id].active = False
                continue

            if style == 8 and (not entry.render_flag) and entry.target_id != -1 and creatures is not None:
                target_id = int(entry.target_id)
                if 0 <= target_id < len(creatures) and bool(getattr(creatures[target_id], "active", False)):
                    entry.pos_x = float(getattr(creatures[target_id], "x", entry.pos_x))
                    entry.pos_y = float(getattr(creatures[target_id], "y", entry.pos_y))

            if entry.render_flag and creatures is not None:
                hit_idx = _creature_find_in_radius(pos_x=entry.pos_x, pos_y=entry.pos_y, radius=max(entry.intensity, 0.0) * 8.0)
                if hit_idx != -1:
                    entry.render_flag = False
                    creature = creatures[hit_idx]
                    if style == 8:
                        entry.target_id = int(hit_idx)
                        entry.pos_x = float(getattr(creature, "x", entry.pos_x))
                        entry.pos_y = float(getattr(creature, "y", entry.pos_y))
                        entry.vel_x = 0.0
                        entry.vel_y = 0.0
                    else:
                        damage = max(0.0, float(entry.intensity) * 10.0)
                        if damage > 0.0:
                            if apply_creature_damage is not None:
                                apply_creature_damage(int(hit_idx), float(damage), 4, 0.0, 0.0, int(entry.owner_id))
                            else:
                                creature.hp = float(getattr(creature, "hp", 0.0)) - float(damage)

                        tint_sum = float(getattr(creature, "tint_r", 1.0)) + float(getattr(creature, "tint_g", 1.0)) + float(getattr(creature, "tint_b", 1.0))
                        if tint_sum > 1.6:
                            factor = 1.0 - max(entry.intensity, 0.0) * 0.01
                            creature.tint_r = _clamp(float(getattr(creature, "tint_r", 1.0)) * factor, 0.0, 1.0)
                            creature.tint_g = _clamp(float(getattr(creature, "tint_g", 1.0)) * factor, 0.0, 1.0)
                            creature.tint_b = _clamp(float(getattr(creature, "tint_b", 1.0)) * factor, 0.0, 1.0)
                            creature.tint_a = _clamp(float(getattr(creature, "tint_a", 1.0)) * factor, 0.0, 1.0)

        return expired


@dataclass(slots=True)
class SpriteEffect:
    active: bool = False
    color_r: float = 1.0
    color_g: float = 1.0
    color_b: float = 1.0
    color_a: float = 0.0
    rotation: float = 0.0
    pos_x: float = 0.0
    pos_y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    scale: float = 1.0


class SpriteEffectPool:
    def __init__(self, *, size: int = SPRITE_EFFECT_POOL_SIZE, rand: Callable[[], int] | None = None) -> None:
        self._entries = [SpriteEffect() for _ in range(int(size))]
        self._rand = rand or _default_rand

    @property
    def entries(self) -> list[SpriteEffect]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.active = False

    def spawn(self, *, pos_x: float, pos_y: float, vel_x: float, vel_y: float, scale: float = 1.0) -> int:
        """Port of `fx_spawn_sprite` (0x0041fbb0)."""

        idx = None
        for i, entry in enumerate(self._entries):
            if not entry.active:
                idx = i
                break
        if idx is None:
            if not self._entries:
                raise ValueError("Sprite effect pool has zero entries")
            idx = int(self._rand()) % len(self._entries)

        entry = self._entries[idx]
        entry.active = True
        entry.color_r = 1.0
        entry.color_g = 1.0
        entry.color_b = 1.0
        entry.color_a = 1.0
        entry.rotation = float(int(self._rand()) % 0x274) * 0.01
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.vel_x = float(vel_x)
        entry.vel_y = float(vel_y)
        entry.scale = float(scale)
        return idx

    def iter_active(self) -> list[SpriteEffect]:
        return [entry for entry in self._entries if entry.active]

    def update(self, dt: float) -> list[int]:
        if dt <= 0.0:
            return []

        expired: list[int] = []
        for idx, entry in enumerate(self._entries):
            if not entry.active:
                continue
            entry.pos_x += dt * entry.vel_x
            entry.pos_y += dt * entry.vel_y
            entry.rotation += dt * 3.0
            entry.color_a -= dt
            entry.scale += dt * 60.0
            if entry.color_a <= 0.0:
                entry.active = False
                expired.append(idx)
        return expired


@dataclass(slots=True)
class FxQueueEntry:
    effect_id: int = 0
    rotation: float = 0.0
    pos_x: float = 0.0
    pos_y: float = 0.0
    height: float = 0.0
    width: float = 0.0
    color_r: float = 1.0
    color_g: float = 1.0
    color_b: float = 1.0
    color_a: float = 1.0


class FxQueue:
    """Per-frame terrain decal queue (`fx_queue` / `fx_queue_add`)."""

    def __init__(self, *, capacity: int = FX_QUEUE_CAPACITY, max_count: int = FX_QUEUE_MAX_COUNT) -> None:
        capacity = max(0, int(capacity))
        max_count = max(0, min(int(max_count), capacity))
        self._entries = [FxQueueEntry() for _ in range(capacity)]
        self._count = 0
        self._max_count = max_count

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
        pos_x: float,
        pos_y: float,
        width: float,
        height: float,
        rotation: float,
        rgba: tuple[float, float, float, float],
    ) -> bool:
        """Port of `fx_queue_add` (0x0041e840)."""

        if self._count >= self._max_count:
            return False

        entry = self._entries[self._count]
        entry.effect_id = int(effect_id)
        entry.rotation = float(rotation)
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.height = float(height)
        entry.width = float(width)
        entry.color_r = float(rgba[0])
        entry.color_g = float(rgba[1])
        entry.color_b = float(rgba[2])
        entry.color_a = float(rgba[3])
        self._count += 1
        return True

    def add_random(self, *, pos_x: float, pos_y: float, rand: Callable[[], int]) -> bool:
        """Port of `fx_queue_add_random` (effect ids 3..7 with grayscale tint)."""

        if self._count >= self._max_count:
            return False

        gray = float(int(rand()) & 0xF) * 0.01 + 0.84
        w = float(int(rand()) % 0x18 - 0x0C) + 30.0
        rotation = float(int(rand()) % 0x274) * 0.01
        effect_id = int(rand()) % 5 + 3
        return self.add(
            effect_id=effect_id,
            pos_x=pos_x,
            pos_y=pos_y,
            width=w,
            height=w,
            rotation=rotation,
            rgba=(gray, gray, gray, 1.0),
        )


@dataclass(slots=True)
class FxQueueRotatedEntry:
    top_left_x: float = 0.0
    top_left_y: float = 0.0
    color_r: float = 1.0
    color_g: float = 1.0
    color_b: float = 1.0
    color_a: float = 1.0
    rotation: float = 0.0
    scale: float = 1.0
    creature_type_id: int = 0


class FxQueueRotated:
    """Rotated corpse queue (`fx_queue_rotated` / `fx_queue_add_rotated`)."""

    def __init__(self, *, capacity: int = FX_QUEUE_ROTATED_CAPACITY, max_count: int = FX_QUEUE_ROTATED_MAX_COUNT) -> None:
        capacity = max(0, int(capacity))
        max_count = max(0, min(int(max_count), capacity))
        self._entries = [FxQueueRotatedEntry() for _ in range(capacity)]
        self._count = 0
        self._max_count = max_count

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
        top_left_x: float,
        top_left_y: float,
        rgba: tuple[float, float, float, float],
        rotation: float,
        scale: float,
        creature_type_id: int,
        terrain_bodies_transparency: float = 0.0,
        terrain_texture_failed: bool = False,
    ) -> bool:
        """Port of `fx_queue_add_rotated` (0x00427840)."""

        if terrain_texture_failed:
            return False
        if self._count >= self._max_count:
            return False

        r, g, b, a = rgba
        if terrain_bodies_transparency != 0.0:
            a = a / float(terrain_bodies_transparency)
        else:
            a = a * 0.8

        entry = self._entries[self._count]
        entry.top_left_x = float(top_left_x)
        entry.top_left_y = float(top_left_y)
        entry.color_r = float(r)
        entry.color_g = float(g)
        entry.color_b = float(b)
        entry.color_a = float(a)
        entry.rotation = float(rotation)
        entry.scale = float(scale)
        entry.creature_type_id = int(creature_type_id)

        self._count += 1
        return True


@dataclass(slots=True)
class EffectEntry:
    pos_x: float = 0.0
    pos_y: float = 0.0
    effect_id: int = 0
    vel_x: float = 0.0
    vel_y: float = 0.0
    rotation: float = 0.0
    scale: float = 1.0
    half_width: float = 0.0
    half_height: float = 0.0
    age: float = 0.0
    lifetime: float = 0.0
    flags: int = 0
    color_r: float = 1.0
    color_g: float = 1.0
    color_b: float = 1.0
    color_a: float = 1.0
    rotation_step: float = 0.0
    scale_step: float = 0.0


class EffectPool:
    """Effect pool (`effect_spawn`, `effects_update`).

    This pool renders transient particle quads and can optionally enqueue decals
    into `FxQueue` on expiry (flags bit `0x80`).
    """

    def __init__(self, *, size: int = EFFECT_POOL_SIZE) -> None:
        size = max(0, int(size))
        self._entries = [EffectEntry() for _ in range(size)]
        self._free = list(range(size - 1, -1, -1))
        self._detail_toggle = 0
        self._overwrite_cursor = 0

    @property
    def entries(self) -> list[EffectEntry]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.flags = 0
        self._free = list(range(len(self._entries) - 1, -1, -1))
        self._detail_toggle = 0
        self._overwrite_cursor = 0

    def iter_active(self) -> list[EffectEntry]:
        return [entry for entry in self._entries if entry.flags]

    def _alloc_slot(self, *, detail_preset: int) -> int | None:
        # Native: if detail_preset < 3, skip every other spawn attempt.
        if int(detail_preset) < 3:
            skip = self._detail_toggle & 1
            self._detail_toggle += 1
            if skip:
                return None

        if self._free:
            return self._free.pop()

        if not self._entries:
            return None

        idx = self._overwrite_cursor % len(self._entries)
        self._overwrite_cursor = idx + 1
        return idx

    def spawn(
        self,
        *,
        effect_id: int,
        pos_x: float,
        pos_y: float,
        vel_x: float,
        vel_y: float,
        rotation: float,
        scale: float,
        half_width: float,
        half_height: float,
        age: float,
        lifetime: float,
        flags: int,
        color_r: float,
        color_g: float,
        color_b: float,
        color_a: float,
        rotation_step: float,
        scale_step: float,
        detail_preset: int,
    ) -> int | None:
        idx = self._alloc_slot(detail_preset=int(detail_preset))
        if idx is None:
            return None

        entry = self._entries[idx]
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.effect_id = int(effect_id)
        entry.vel_x = float(vel_x)
        entry.vel_y = float(vel_y)
        entry.rotation = float(rotation)
        entry.scale = float(scale)
        entry.half_width = float(half_width)
        entry.half_height = float(half_height)
        entry.age = float(age)
        entry.lifetime = float(lifetime)
        entry.flags = int(flags)
        entry.color_r = float(color_r)
        entry.color_g = float(color_g)
        entry.color_b = float(color_b)
        entry.color_a = float(color_a)
        entry.rotation_step = float(rotation_step)
        entry.scale_step = float(scale_step)
        return idx

    def free(self, idx: int) -> None:
        if not (0 <= idx < len(self._entries)):
            return
        entry = self._entries[idx]
        entry.flags = 0
        self._free.append(idx)

    def update(self, dt: float, *, fx_queue: FxQueue | None = None) -> None:
        """Advance active effects and enqueue terrain decals on expiry."""

        if dt <= 0.0:
            return

        for idx, entry in enumerate(self._entries):
            flags = int(entry.flags)
            if not flags:
                continue

            age = float(entry.age) + float(dt)
            entry.age = age
            lifetime = float(entry.lifetime)

            if age < lifetime:
                if age >= 0.0:
                    entry.pos_x += float(entry.vel_x) * float(dt)
                    entry.pos_y += float(entry.vel_y) * float(dt)
                    if flags & 0x4:
                        entry.rotation += float(entry.rotation_step) * float(dt)
                    if flags & 0x8:
                        entry.scale += float(entry.scale_step) * float(dt)
                    if flags & 0x10:
                        entry.color_a = 1.0 - age / lifetime if lifetime > 1e-9 else 0.0
                continue

            if fx_queue is not None and (flags & 0x80):
                # On expiry, the native code overrides alpha before queuing.
                alpha = 0.35 if (flags & 0x100) else 0.8
                fx_queue.add(
                    effect_id=int(entry.effect_id),
                    pos_x=float(entry.pos_x),
                    pos_y=float(entry.pos_y),
                    width=float(entry.half_width) * 2.0,
                    height=float(entry.half_height) * 2.0,
                    rotation=float(entry.rotation),
                    rgba=(float(entry.color_r), float(entry.color_g), float(entry.color_b), float(alpha)),
                )

            self.free(idx)

    def spawn_blood_splatter(
        self,
        *,
        pos_x: float,
        pos_y: float,
        angle: float,
        age: float,
        rand: Callable[[], int],
        detail_preset: int,
        fx_toggle: int,
    ) -> None:
        """Port of `effect_spawn_blood_splatter` (0x0042eb10)."""

        if int(fx_toggle) != 0:
            return

        lifetime = 0.25 - float(age)
        base = float(angle) + math.pi
        dir_x = math.cos(base)
        dir_y = math.sin(base)

        for _ in range(2):
            r0 = int(rand())
            rotation = float((r0 & 0x3F) - 0x20) * 0.1 + base
            r1 = int(rand())
            half = float((r1 & 7) + 1)
            r2 = int(rand())
            vel_x = float((r2 & 0x3F) + 100) * dir_x
            r3 = int(rand())
            vel_y = float((r3 & 0x3F) + 100) * dir_y
            r4 = int(rand())
            scale_step = float(r4 & 0x7F) * 0.03 + 0.1

            self.spawn(
                effect_id=7,
                pos_x=pos_x,
                pos_y=pos_y,
                vel_x=vel_x,
                vel_y=vel_y,
                rotation=rotation,
                scale=1.0,
                half_width=half,
                half_height=half,
                age=float(age),
                lifetime=lifetime,
                flags=0xC9,
                color_r=1.0,
                color_g=1.0,
                color_b=1.0,
                color_a=0.5,
                rotation_step=0.0,
                scale_step=scale_step,
                detail_preset=int(detail_preset),
            )

    def spawn_burst(
        self,
        *,
        pos_x: float,
        pos_y: float,
        count: int,
        rand: Callable[[], int],
        detail_preset: int,
        lifetime: float = 0.5,
        scale_step: float | None = None,
        color_r: float = 0.4,
        color_g: float = 0.5,
        color_b: float = 1.0,
        color_a: float = 0.5,
    ) -> None:
        """Port of `effect_spawn_burst` (0x0042ef60)."""

        count = max(0, int(count))
        for _ in range(count):
            r0 = int(rand())
            rotation = float(r0 & 0x7F) * 0.049087387
            r1 = int(rand())
            vel_x = float((r1 & 0x7F) - 0x40)
            r2 = int(rand())
            vel_y = float((r2 & 0x7F) - 0x40)
            if scale_step is None:
                r3 = int(rand())
                step = float(r3 % 100) * 0.01 + 0.1
            else:
                step = float(scale_step)

            self.spawn(
                effect_id=0,
                pos_x=pos_x,
                pos_y=pos_y,
                vel_x=vel_x,
                vel_y=vel_y,
                rotation=rotation,
                scale=1.0,
                half_width=32.0,
                half_height=32.0,
                age=0.0,
                lifetime=float(lifetime),
                flags=0x1D,
                color_r=float(color_r),
                color_g=float(color_g),
                color_b=float(color_b),
                color_a=float(color_a),
                rotation_step=0.0,
                scale_step=step,
                detail_preset=int(detail_preset),
            )

    def spawn_ring(
        self,
        *,
        pos_x: float,
        pos_y: float,
        detail_preset: int,
        color_r: float,
        color_g: float,
        color_b: float,
        color_a: float,
        lifetime: float = 0.25,
        scale_step: float = 50.0,
    ) -> None:
        """Ring/halo burst used by bonus pickup effects (`bonus_apply`)."""

        self.spawn(
            effect_id=1,
            pos_x=pos_x,
            pos_y=pos_y,
            vel_x=0.0,
            vel_y=0.0,
            rotation=0.0,
            scale=1.0,
            half_width=32.0,
            half_height=32.0,
            age=0.0,
            lifetime=float(lifetime),
            flags=0x19,
            color_r=float(color_r),
            color_g=float(color_g),
            color_b=float(color_b),
            color_a=float(color_a),
            rotation_step=0.0,
            scale_step=float(scale_step),
            detail_preset=int(detail_preset),
        )

    def spawn_freeze_shard(
        self,
        *,
        pos_x: float,
        pos_y: float,
        angle: float,
        rand: Callable[[], int],
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_freeze_shard` (0x0042ec80)."""

        lifetime = float(int(rand()) & 0xF) * 0.01 + 0.2
        base = float(angle) + math.pi

        rotation = float(int(rand()) % 100) * 0.01 + base
        half = float(int(rand()) % 5 + 7)

        vel_x = math.cos(base) * 114.0
        vel_y = math.sin(base) * 114.0

        rotation_step = (float(int(rand()) % 0x14) * 0.1 - 1.0) * 4.0
        scale_step = -float(int(rand()) & 0xF) * 0.1

        effect_id = int(rand()) % 3 + 8
        self.spawn(
            effect_id=int(effect_id),
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            vel_x=float(vel_x),
            vel_y=float(vel_y),
            rotation=float(rotation),
            scale=1.0,
            half_width=float(half),
            half_height=float(half),
            age=0.0,
            lifetime=float(lifetime),
            flags=0x1CD,
            color_r=1.0,
            color_g=1.0,
            color_b=1.0,
            color_a=0.5,
            rotation_step=float(rotation_step),
            scale_step=float(scale_step),
            detail_preset=int(detail_preset),
        )

    def spawn_freeze_shatter(
        self,
        *,
        pos_x: float,
        pos_y: float,
        angle: float,
        rand: Callable[[], int],
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_freeze_shatter` (0x0042ee00)."""

        lifetime = 1.1
        for idx in range(4):
            rotation = float(idx) * (math.pi / 2.0) + float(angle)
            vel_x = math.cos(rotation) * 42.0
            vel_y = math.sin(rotation) * 42.0
            half = float(int(rand()) % 10 + 0x12)
            rotation_step = (float(int(rand()) % 0x14) * 0.1 - 1.0) * 1.9

            self.spawn(
                effect_id=0x0E,
                pos_x=float(pos_x),
                pos_y=float(pos_y),
                vel_x=float(vel_x),
                vel_y=float(vel_y),
                rotation=float(rotation),
                scale=1.0,
                half_width=float(half),
                half_height=float(half),
                age=0.0,
                lifetime=float(lifetime),
                flags=0x5D,
                color_r=1.0,
                color_g=1.0,
                color_b=1.0,
                color_a=0.5,
                rotation_step=float(rotation_step),
                scale_step=0.0,
                detail_preset=int(detail_preset),
            )

        for _ in range(4):
            shard_angle = float(int(rand()) % 0x264) * 0.01
            self.spawn_freeze_shard(
                pos_x=float(pos_x),
                pos_y=float(pos_y),
                angle=float(shard_angle),
                rand=rand,
                detail_preset=int(detail_preset),
            )

    def spawn_explosion_burst(
        self,
        *,
        pos_x: float,
        pos_y: float,
        scale: float,
        rand: Callable[[], int],
        detail_preset: int,
    ) -> None:
        """Port of `effect_spawn_explosion_burst` (0x0042f6c0)."""

        detail_preset = int(detail_preset)
        scale = float(scale)

        # Shockwave ring.
        self.spawn(
            effect_id=1,
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            vel_x=0.0,
            vel_y=0.0,
            rotation=0.0,
            scale=1.0,
            half_width=32.0,
            half_height=32.0,
            age=-0.1,
            lifetime=0.35,
            flags=0x19,
            color_r=0.6,
            color_g=0.6,
            color_b=0.6,
            color_a=1.0,
            rotation_step=0.0,
            scale_step=scale * 25.0,
            detail_preset=detail_preset,
        )

        # Dark explosion puffs (high detail only).
        if detail_preset > 3:
            for idx in range(2):
                age = float(idx) * 0.2 - 0.5
                lifetime = float(idx) * 0.2 + 0.6
                rotation = float(int(rand()) % 0x266) * 0.02
                self.spawn(
                    effect_id=0x11,
                    pos_x=float(pos_x),
                    pos_y=float(pos_y),
                    vel_x=0.0,
                    vel_y=0.0,
                    rotation=float(rotation),
                    scale=1.0,
                    half_width=32.0,
                    half_height=32.0,
                    age=float(age),
                    lifetime=float(lifetime),
                    flags=0x5D,
                    color_r=0.1,
                    color_g=0.1,
                    color_b=0.1,
                    color_a=1.0,
                    rotation_step=1.4,
                    scale_step=scale * 5.0,
                    detail_preset=detail_preset,
                )

        # Bright flash.
        self.spawn(
            effect_id=0,
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            vel_x=0.0,
            vel_y=0.0,
            rotation=0.0,
            scale=1.0,
            half_width=32.0,
            half_height=32.0,
            age=0.0,
            lifetime=0.3,
            flags=0x19,
            color_r=1.0,
            color_g=1.0,
            color_b=1.0,
            color_a=1.0,
            rotation_step=0.0,
            scale_step=scale * 45.0,
            detail_preset=detail_preset,
        )

        if detail_preset < 2:
            count = 1
        else:
            count = 3 + (1 if detail_preset > 3 else 0)

        # Extra shockwave particles.
        for _ in range(count):
            rotation = float(int(rand()) % 0x13A) * 0.02
            vel_x = float((int(rand()) & 0x3F) * 2 - 0x40)
            vel_y = float((int(rand()) & 0x3F) * 2 - 0x40)
            scale_step = float((int(rand()) - 3) & 7) * scale
            rotation_step = float((int(rand()) + 3) & 7)
            self.spawn(
                effect_id=0x0C,
                pos_x=float(pos_x),
                pos_y=float(pos_y),
                vel_x=float(vel_x),
                vel_y=float(vel_y),
                rotation=float(rotation),
                scale=1.0,
                half_width=32.0,
                half_height=32.0,
                age=0.0,
                lifetime=0.7,
                flags=0x1D,
                color_r=1.0,
                color_g=1.0,
                color_b=1.0,
                color_a=1.0,
                rotation_step=float(rotation_step),
                scale_step=float(scale_step),
                detail_preset=detail_preset,
            )
