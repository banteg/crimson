from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

__all__ = [
    "FX_QUEUE_CAPACITY",
    "FX_QUEUE_MAX_COUNT",
    "FX_QUEUE_ROTATED_CAPACITY",
    "FX_QUEUE_ROTATED_MAX_COUNT",
    "PARTICLE_POOL_SIZE",
    "SPRITE_EFFECT_POOL_SIZE",
    "FxQueue",
    "FxQueueEntry",
    "FxQueueRotated",
    "FxQueueRotatedEntry",
    "Particle",
    "ParticlePool",
    "SpriteEffect",
    "SpriteEffectPool",
]

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

    def spawn_particle(self, *, pos_x: float, pos_y: float, angle: float, intensity: float = 1.0) -> int:
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
        return idx

    def spawn_particle_slow(self, *, pos_x: float, pos_y: float, angle: float) -> int:
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
        return idx

    def iter_active(self) -> list[Particle]:
        return [entry for entry in self._entries if entry.active]

    def update(self, dt: float) -> list[int]:
        """Advance particles and deactivate expired entries.

        This is a minimal port of the particle loop inside `projectile_update`
        (0x00420b90). It captures the per-style decay/movement rules that drive
        visual lifetimes. Gameplay-driven interactions (e.g. creature hits) are
        handled by higher-level systems in the original game and are omitted here.

        Returns indices of particles that were deactivated this tick.
        """

        if dt <= 0.0:
            return []

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

            alive = entry.intensity > (0.0 if style == 0 else 0.8)
            if not alive:
                entry.active = False
                expired.append(idx)

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
