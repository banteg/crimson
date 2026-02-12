from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, MutableSequence, Protocol

from grim.color import RGBA
from grim.geom import Vec2

from ..creatures.spawn import CreatureFlags


class Damageable(Protocol):
    active: bool
    pos: Vec2
    hp: float
    hitbox_size: float
    size: float
    flags: CreatureFlags
    plague_infected: bool


class PlayerDamageable(Protocol):
    pos: Vec2
    health: float
    shield_timer: float
    size: float
    perk_counts: list[int]


class _SizeLike(Protocol):
    size: float


class _RngLike(Protocol):
    def rand(self) -> int: ...


class _BonusesLike(Protocol):
    freeze: float


class _EffectsLike(Protocol):
    def spawn(
        self,
        *,
        effect_id: int,
        pos: Vec2,
        vel: Vec2,
        rotation: float,
        scale: float,
        half_width: float,
        half_height: float,
        age: float,
        lifetime: float,
        flags: int,
        color: RGBA,
        rotation_step: float,
        scale_step: float,
        detail_preset: int,
    ) -> int | None: ...

    def spawn_freeze_shard(self, *, pos: Vec2, angle: float, rand: Callable[[], int], detail_preset: int) -> None: ...

    def spawn_explosion_burst(self, *, pos: Vec2, scale: float, rand: Callable[[], int], detail_preset: int) -> None: ...


class _SpriteEffectsLike(Protocol):
    def spawn(self, *, pos: Vec2, vel: Vec2, scale: float = 1.0, color: RGBA | None = None) -> int: ...


class ProjectileRuntimeState(Protocol):
    bonus_spawn_guard: bool
    camera_shake_pulses: int
    shock_chain_links_left: int
    shock_chain_projectile_id: int

    @property
    def effects(self) -> _EffectsLike: ...

    @property
    def sprite_effects(self) -> _SpriteEffectsLike: ...

    @property
    def rng(self) -> _RngLike: ...

    @property
    def bonuses(self) -> _BonusesLike: ...

    @property
    def sfx_queue(self) -> MutableSequence[str]: ...

    @property
    def shots_hit(self) -> MutableSequence[int]: ...


class FxQueueLike(Protocol):
    def add(
        self,
        *,
        effect_id: int,
        pos: Vec2,
        width: float,
        height: float,
        rotation: float,
        rgba: RGBA,
    ) -> bool: ...

    def add_random(self, *, pos: Vec2, rand: Callable[[], int]) -> bool: ...


MAIN_PROJECTILE_POOL_SIZE = 0x60
SECONDARY_PROJECTILE_POOL_SIZE = 0x40


class ProjectileTypeId(IntEnum):
    # Values are projectile type ids (not weapon ids). Based on the decompile
    # for `player_fire_weapon` and `projectile_update`.
    PISTOL = 0x01
    MEAN_MINIGUN = 0x01
    ASSAULT_RIFLE = 0x02
    SHOTGUN = 0x03
    SAWED_OFF_SHOTGUN = 0x03
    JACKHAMMER = 0x03
    SUBMACHINE_GUN = 0x05
    GAUSS_GUN = 0x06
    GAUSS_SHOTGUN = 0x06
    PLASMA_RIFLE = 0x09
    MULTI_PLASMA = 0x09
    PLASMA_MINIGUN = 0x0B
    PLASMA_SHOTGUN = 0x0B
    PULSE_GUN = 0x13
    ION_RIFLE = 0x15
    ION_MINIGUN = 0x16
    ION_CANNON = 0x17
    SHRINKIFIER = 0x18
    BLADE_GUN = 0x19
    SPIDER_PLASMA = 0x1A
    PLASMA_CANNON = 0x1C
    SPLITTER_GUN = 0x1D
    PLAGUE_SPREADER = 0x29
    RAINBOW_GUN = 0x2B
    FIRE_BULLETS = 0x2D


class SecondaryProjectileTypeId(IntEnum):
    NONE = 0
    ROCKET = 1
    HOMING_ROCKET = 2
    DETONATION = 3
    ROCKET_MINIGUN = 4


_CREATURE_HITBOX_ALIVE = 16.0


def _rng_zero() -> int:
    return 0


CreatureDamageApplier = Callable[[int, float, int, Vec2, int], None]
SecondaryDetonationKillHandler = Callable[[int], None]


@dataclass(frozen=True, slots=True)
class ProjectileHit:
    type_id: int
    origin: Vec2
    hit: Vec2
    target: Vec2


@dataclass(slots=True)
class Projectile:
    active: bool = False
    angle: float = 0.0
    pos: Vec2 = field(default_factory=Vec2)
    origin: Vec2 = field(default_factory=Vec2)
    type_id: int = 0
    life_timer: float = 0.0
    reserved: float = 0.0
    speed_scale: float = 1.0
    damage_pool: float = 1.0
    hit_radius: float = 1.0
    base_damage: float = 0.0
    owner_id: int = 0
    hits_players: bool = False


@dataclass(slots=True)
class SecondaryProjectile:
    active: bool = False
    angle: float = 0.0
    speed: float = 0.0
    pos: Vec2 = field(default_factory=Vec2)
    vel: Vec2 = field(default_factory=Vec2)
    detonation_t: float = 0.0
    detonation_scale: float = 1.0
    type_id: int = 0
    owner_id: int = -100
    trail_timer: float = 0.0
    target_id: int = -1
    # Compatibility fallback for contexts that cannot supply creature snapshots at spawn time.
    target_hint_active: bool = False
    target_hint: Vec2 = field(default_factory=Vec2)


__all__ = [
    "CreatureDamageApplier",
    "Damageable",
    "FxQueueLike",
    "MAIN_PROJECTILE_POOL_SIZE",
    "PlayerDamageable",
    "Projectile",
    "ProjectileHit",
    "ProjectileRuntimeState",
    "ProjectileTypeId",
    "SecondaryDetonationKillHandler",
    "SECONDARY_PROJECTILE_POOL_SIZE",
    "SecondaryProjectile",
    "SecondaryProjectileTypeId",
    "_CREATURE_HITBOX_ALIVE",
    "_EffectsLike",
    "_rng_zero",
    "_SizeLike",
    "_SpriteEffectsLike",
]
