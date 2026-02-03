from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import math
from typing import Callable, Protocol

from grim.math import distance_sq

from .creatures.spawn import CreatureFlags
from .perks import PerkId
from .weapons import weapon_entry_for_projectile_type_id


class Damageable(Protocol):
    x: float
    y: float
    hp: float


class PlayerDamageable(Protocol):
    pos_x: float
    pos_y: float
    health: float
    size: float


class FxQueueLike(Protocol):
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
    ) -> bool: ...

    def add_random(self, *, pos_x: float, pos_y: float, rand: Callable[[], int]) -> bool: ...


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


def _rng_zero() -> int:
    return 0


CreatureDamageApplier = Callable[[int, float, int, float, float, int], None]


@dataclass(slots=True)
class Projectile:
    active: bool = False
    angle: float = 0.0
    pos_x: float = 0.0
    pos_y: float = 0.0
    origin_x: float = 0.0
    origin_y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
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
    pos_x: float = 0.0
    pos_y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    type_id: int = 0
    owner_id: int = -100
    trail_timer: float = 0.0
    target_id: int = -1


def _hit_radius_for(creature: Damageable) -> float:
    """Approximate `creature_find_in_radius`/`creatures_apply_radius_damage` sizing.

    The native code compares `distance - radius < creature.size * 0.14285715 + 3.0`.
    """

    raw = getattr(creature, "size", None)
    if raw is None:
        size = 50.0
    else:
        size = float(raw)
    return max(0.0, size * 0.14285715 + 3.0)


def _apply_damage_to_creature(
    creatures: list[Damageable],
    creature_index: int,
    damage: float,
    *,
    damage_type: int,
    impulse_x: float,
    impulse_y: float,
    owner_id: int,
    apply_creature_damage: CreatureDamageApplier | None = None,
) -> None:
    if damage <= 0.0:
        return
    idx = int(creature_index)
    if not (0 <= idx < len(creatures)):
        return
    if apply_creature_damage is not None:
        apply_creature_damage(
            idx,
            float(damage),
            int(damage_type),
            float(impulse_x),
            float(impulse_y),
            int(owner_id),
        )
    else:
        creatures[idx].hp -= float(damage)


def _spawn_ion_hit_effects(
    effects: object | None,
    sfx_queue: object | None,
    *,
    type_id: int,
    pos_x: float,
    pos_y: float,
    rng: Callable[[], int],
    detail_preset: int,
) -> None:
    if effects is None or not hasattr(effects, "spawn"):
        return

    ring_scale = 0.0
    ring_strength = 0.0
    burst_scale = 0.0
    if type_id == int(ProjectileTypeId.ION_MINIGUN):
        ring_scale = 1.5
        ring_strength = 0.1
        burst_scale = 0.8
    elif type_id == int(ProjectileTypeId.ION_RIFLE):
        ring_scale = 1.2
        ring_strength = 0.4
        burst_scale = 1.2
    elif type_id == int(ProjectileTypeId.ION_CANNON):
        ring_scale = 1.0
        ring_strength = 1.0
        burst_scale = 2.2
        if isinstance(sfx_queue, list):
            sfx_queue.append("sfx_shockwave")
    else:
        return

    detail = int(detail_preset)

    # Port of `FUN_0042f270(pos, ring_scale, ring_strength)`: ring burst (effect_id=1).
    effects.spawn(
        effect_id=1,
        pos_x=float(pos_x),
        pos_y=float(pos_y),
        vel_x=0.0,
        vel_y=0.0,
        rotation=0.0,
        scale=1.0,
        half_width=4.0,
        half_height=4.0,
        age=0.0,
        lifetime=float(ring_strength) * 0.8,
        flags=0x19,
        color_r=0.6,
        color_g=0.6,
        color_b=0.9,
        color_a=1.0,
        rotation_step=0.0,
        scale_step=float(ring_scale) * 45.0,
        detail_preset=detail,
    )

    # Port of `FUN_0042f540(pos, burst_scale)`: burst cloud (effect_id=0).
    burst = float(burst_scale) * 0.8
    lifetime = min(burst * 0.7, 1.1)
    half = burst * 32.0
    count = int(half)
    if detail < 3:
        count //= 2

    for _ in range(max(0, count)):
        rotation = float(int(rng()) & 0x7F) * 0.049087387
        vel_x = float((int(rng()) & 0x7F) - 0x40) * burst * 1.4
        vel_y = float((int(rng()) & 0x7F) - 0x40) * burst * 1.4
        scale_step = (float(int(rng()) % 100) * 0.01 + 0.1) * burst
        effects.spawn(
            effect_id=0,
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            vel_x=vel_x,
            vel_y=vel_y,
            rotation=rotation,
            scale=1.0,
            half_width=half,
            half_height=half,
            age=0.0,
            lifetime=float(lifetime),
            flags=0x1D,
            color_r=0.4,
            color_g=0.5,
            color_b=1.0,
            color_a=0.5,
            rotation_step=0.0,
            scale_step=scale_step,
            detail_preset=detail,
        )


def _spawn_plasma_cannon_hit_effects(
    effects: object | None,
    sfx_queue: object | None,
    *,
    pos_x: float,
    pos_y: float,
    detail_preset: int,
) -> None:
    """Port of `projectile_update` Plasma Cannon hit extras.

    Native does:
    - `sfx_play_panned(sfx_explosion_medium)`
    - `sfx_play_panned(sfx_shockwave)`
    - `FUN_0042f330(pos, 1.5, 1.0)`
    - `FUN_0042f330(pos, 1.0, 1.0)`
    """

    if effects is None or not hasattr(effects, "spawn"):
        return

    if isinstance(sfx_queue, list):
        sfx_queue.append("sfx_explosion_medium")
        sfx_queue.append("sfx_shockwave")

    detail = int(detail_preset)

    def _spawn_ring(*, scale: float) -> None:
        effects.spawn(
            effect_id=1,
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            vel_x=0.0,
            vel_y=0.0,
            rotation=0.0,
            scale=1.0,
            half_width=4.0,
            half_height=4.0,
            age=0.1,
            lifetime=1.0,
            flags=0x19,
            color_r=0.9,
            color_g=0.6,
            color_b=0.3,
            color_a=1.0,
            rotation_step=0.0,
            scale_step=float(scale) * 45.0,
            detail_preset=detail,
        )

    _spawn_ring(scale=1.5)
    _spawn_ring(scale=1.0)


def _spawn_splitter_hit_effects(
    effects: object | None,
    *,
    pos_x: float,
    pos_y: float,
    rng: Callable[[], int],
    detail_preset: int,
) -> None:
    """Port of `FUN_0042f3f0(pos, 26.0, 3)` from the Splitter Gun hit branch."""

    if effects is None or not hasattr(effects, "spawn"):
        return

    detail = int(detail_preset)
    for _ in range(3):
        angle = float(int(rng()) & 0x1FF) * (math.tau / 512.0)
        radius = float(int(rng()) % 26)
        jitter_age = -float(int(rng()) & 0xFF) * 0.0012
        lifetime = 0.1 - jitter_age

        effects.spawn(
            effect_id=0,
            pos_x=float(pos_x) + math.cos(angle) * radius,
            pos_y=float(pos_y) + math.sin(angle) * radius,
            vel_x=0.0,
            vel_y=0.0,
            rotation=0.0,
            scale=1.0,
            half_width=4.0,
            half_height=4.0,
            age=jitter_age,
            lifetime=lifetime,
            flags=0x19,
            color_r=1.0,
            color_g=0.9,
            color_b=0.1,
            color_a=1.0,
            rotation_step=0.0,
            scale_step=55.0,
            detail_preset=detail,
        )


@dataclass(slots=True)
class _ProjectileUpdateCtx:
    pool: ProjectilePool
    creatures: list[Damageable]
    dt: float
    ion_scale: float
    detail_preset: int
    rng: Callable[[], int]
    runtime_state: object | None
    effects: object | None
    sfx_queue: object | None
    apply_creature_damage: CreatureDamageApplier | None


@dataclass(slots=True)
class _ProjectileHitInfo:
    proj_index: int
    proj: Projectile
    hit_idx: int
    move_dx: float
    move_dy: float
    target_x: float
    target_y: float


ProjectileLingerHandler = Callable[[_ProjectileUpdateCtx, Projectile], None]
ProjectilePreHitCreatureHandler = Callable[[_ProjectileUpdateCtx, Projectile, int], None]
ProjectilePostHitCreatureHandler = Callable[[_ProjectileUpdateCtx, _ProjectileHitInfo], None]


@dataclass(frozen=True, slots=True)
class ProjectileBehavior:
    linger: ProjectileLingerHandler
    pre_hit_creature: ProjectilePreHitCreatureHandler | None = None
    post_hit_creature: ProjectilePostHitCreatureHandler | None = None


def _linger_default(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt


def _linger_gauss_gun(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt * 0.1


def _linger_ion_minigun(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt
    damage = ctx.dt * 40.0
    radius = ctx.ion_scale * 60.0
    for creature_idx, creature in enumerate(ctx.creatures):
        if creature.hp <= 0.0:
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=7,
                impulse_x=0.0,
                impulse_y=0.0,
                owner_id=int(proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )


def _linger_ion_rifle(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt
    damage = ctx.dt * 100.0
    radius = ctx.ion_scale * 88.0
    for creature_idx, creature in enumerate(ctx.creatures):
        if creature.hp <= 0.0:
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=7,
                impulse_x=0.0,
                impulse_y=0.0,
                owner_id=int(proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )


def _linger_ion_cannon(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt * 0.7
    damage = ctx.dt * 300.0
    radius = ctx.ion_scale * 128.0
    for creature_idx, creature in enumerate(ctx.creatures):
        if creature.hp <= 0.0:
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=7,
                impulse_x=0.0,
                impulse_y=0.0,
                owner_id=int(proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )


def _pre_hit_splitter(ctx: _ProjectileUpdateCtx, proj: Projectile, hit_idx: int) -> None:
    _spawn_splitter_hit_effects(
        ctx.effects,
        pos_x=float(proj.pos_x),
        pos_y=float(proj.pos_y),
        rng=ctx.rng,
        detail_preset=ctx.detail_preset,
    )
    ctx.pool.spawn(
        pos_x=proj.pos_x,
        pos_y=proj.pos_y,
        angle=proj.angle - 1.0471976,
        type_id=ProjectileTypeId.SPLITTER_GUN,
        owner_id=int(hit_idx),
        base_damage=proj.base_damage,
        hits_players=proj.hits_players,
    )
    ctx.pool.spawn(
        pos_x=proj.pos_x,
        pos_y=proj.pos_y,
        angle=proj.angle + 1.0471976,
        type_id=ProjectileTypeId.SPLITTER_GUN,
        owner_id=int(hit_idx),
        base_damage=proj.base_damage,
        hits_players=proj.hits_players,
    )


def _post_hit_ion_common(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    _spawn_ion_hit_effects(
        ctx.effects,
        ctx.sfx_queue,
        type_id=int(hit.proj.type_id),
        pos_x=float(hit.target_x),
        pos_y=float(hit.target_y),
        rng=ctx.rng,
        detail_preset=ctx.detail_preset,
    )


def _post_hit_ion_rifle(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    if ctx.runtime_state is not None and getattr(ctx.runtime_state, "shock_chain_projectile_id", -1) == hit.proj_index:
        hit.proj.reserved = float(int(hit.hit_idx) + 1)
    _post_hit_ion_common(ctx, hit)


def _post_hit_plasma_cannon(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    size = float(getattr(creature, "size", 50.0) or 50.0)
    ring_radius = size * 0.5 + 1.0

    plasma_entry = weapon_entry_for_projectile_type_id(int(ProjectileTypeId.PLASMA_RIFLE))
    plasma_meta = float(plasma_entry.projectile_meta) if plasma_entry and plasma_entry.projectile_meta is not None else hit.proj.base_damage

    for ring_idx in range(12):
        ring_angle = float(ring_idx) * (math.pi / 6.0)
        ctx.pool.spawn(
            pos_x=hit.proj.pos_x + math.cos(ring_angle) * ring_radius,
            pos_y=hit.proj.pos_y + math.sin(ring_angle) * ring_radius,
            angle=ring_angle,
            type_id=ProjectileTypeId.PLASMA_RIFLE,
            owner_id=-100,
            base_damage=plasma_meta,
        )

    _spawn_plasma_cannon_hit_effects(
        ctx.effects,
        ctx.sfx_queue,
        pos_x=float(hit.proj.pos_x),
        pos_y=float(hit.proj.pos_y),
        detail_preset=ctx.detail_preset,
    )


def _post_hit_shrinkifier(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    if hasattr(creature, "size"):
        new_size = float(getattr(creature, "size", 50.0) or 50.0) * 0.65
        setattr(creature, "size", new_size)
        if new_size < 16.0:
            _apply_damage_to_creature(
                ctx.creatures,
                int(hit.hit_idx),
                float(creature.hp) + 1.0,
                damage_type=1,
                impulse_x=0.0,
                impulse_y=0.0,
                owner_id=int(hit.proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )
    hit.proj.life_timer = 0.25


def _post_hit_pulse_gun(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    creature.x += hit.move_dx * 3.0
    creature.y += hit.move_dy * 3.0


def _post_hit_plague_spreader(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    if hasattr(creature, "plague_infected"):
        setattr(creature, "plague_infected", True)


_DEFAULT_BEHAVIOR = ProjectileBehavior(linger=_linger_default)

# Public: used by tests to ensure handler coverage.
PROJECTILE_BEHAVIOR_BY_TYPE_ID: dict[int, ProjectileBehavior] = {
    int(ProjectileTypeId.PISTOL): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.ASSAULT_RIFLE): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.SHOTGUN): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.SUBMACHINE_GUN): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.GAUSS_GUN): ProjectileBehavior(linger=_linger_gauss_gun),
    int(ProjectileTypeId.PLASMA_RIFLE): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.PLASMA_MINIGUN): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.PULSE_GUN): ProjectileBehavior(linger=_linger_default, post_hit_creature=_post_hit_pulse_gun),
    int(ProjectileTypeId.ION_RIFLE): ProjectileBehavior(linger=_linger_ion_rifle, post_hit_creature=_post_hit_ion_rifle),
    int(ProjectileTypeId.ION_MINIGUN): ProjectileBehavior(linger=_linger_ion_minigun, post_hit_creature=_post_hit_ion_common),
    int(ProjectileTypeId.ION_CANNON): ProjectileBehavior(linger=_linger_ion_cannon, post_hit_creature=_post_hit_ion_common),
    int(ProjectileTypeId.SHRINKIFIER): ProjectileBehavior(linger=_linger_default, post_hit_creature=_post_hit_shrinkifier),
    int(ProjectileTypeId.BLADE_GUN): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.SPIDER_PLASMA): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.PLASMA_CANNON): ProjectileBehavior(linger=_linger_default, post_hit_creature=_post_hit_plasma_cannon),
    int(ProjectileTypeId.SPLITTER_GUN): ProjectileBehavior(linger=_linger_default, pre_hit_creature=_pre_hit_splitter),
    int(ProjectileTypeId.PLAGUE_SPREADER): ProjectileBehavior(linger=_linger_default, post_hit_creature=_post_hit_plague_spreader),
    int(ProjectileTypeId.RAINBOW_GUN): _DEFAULT_BEHAVIOR,
    int(ProjectileTypeId.FIRE_BULLETS): _DEFAULT_BEHAVIOR,
}


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
        pos_x: float,
        pos_y: float,
        angle: float,
        type_id: int,
        owner_id: int,
        base_damage: float = 0.0,
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
        entry.angle = angle
        entry.pos_x = pos_x
        entry.pos_y = pos_y
        entry.origin_x = pos_x
        entry.origin_y = pos_y
        entry.vel_x = math.cos(angle) * 1.5
        entry.vel_y = math.sin(angle) * 1.5
        entry.type_id = int(type_id)
        entry.life_timer = 0.4
        entry.reserved = 0.0
        entry.speed_scale = 1.0
        entry.base_damage = float(base_damage)
        entry.owner_id = int(owner_id)
        entry.hits_players = bool(hits_players)

        if type_id == ProjectileTypeId.ION_MINIGUN:
            entry.hit_radius = 3.0
            entry.damage_pool = 1.0
            return index
        if type_id == ProjectileTypeId.ION_RIFLE:
            entry.hit_radius = 5.0
            entry.damage_pool = 1.0
            return index
        if type_id in (ProjectileTypeId.ION_CANNON, ProjectileTypeId.PLASMA_CANNON):
            entry.hit_radius = 10.0
        else:
            entry.hit_radius = 1.0
            if type_id == ProjectileTypeId.GAUSS_GUN:
                entry.damage_pool = 300.0
                return index
            if type_id == ProjectileTypeId.FIRE_BULLETS:
                entry.damage_pool = 240.0
                return index
            if type_id == ProjectileTypeId.BLADE_GUN:
                entry.damage_pool = 50.0
                return index
        entry.damage_pool = 1.0
        return index

    def iter_active(self) -> list[Projectile]:
        return [entry for entry in self._entries if entry.active]

    def update(
        self,
        dt: float,
        creatures: list[Damageable],
        *,
        world_size: float,
        damage_scale_by_type: dict[int, float] | None = None,
        damage_scale_default: float = 1.0,
        ion_aoe_scale: float = 1.0,
        detail_preset: int = 5,
        rng: Callable[[], int] | None = None,
        runtime_state: object | None = None,
        players: list[PlayerDamageable] | None = None,
        apply_player_damage: Callable[[int, float], None] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
    ) -> list[tuple[int, float, float, float, float, float, float]]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.

        Returns a list of hit tuples: (type_id, origin_x, origin_y, hit_x, hit_y, target_x, target_y).
        """

        if dt <= 0.0:
            return []

        barrel_greaser_active = False
        ion_gun_master_active = False
        ion_scale = float(ion_aoe_scale)
        poison_idx = int(PerkId.POISON_BULLETS)
        if players is not None:
            barrel_idx = int(PerkId.BARREL_GREASER)
            ion_idx = int(PerkId.ION_GUN_MASTER)
            for player in players:
                perk_counts = getattr(player, "perk_counts", None)
                if not isinstance(perk_counts, list):
                    continue

                if 0 <= barrel_idx < len(perk_counts) and int(perk_counts[barrel_idx]) > 0:
                    barrel_greaser_active = True
                if 0 <= ion_idx < len(perk_counts) and int(perk_counts[ion_idx]) > 0:
                    ion_gun_master_active = True
                if barrel_greaser_active and ion_gun_master_active:
                    break

        if ion_scale == 1.0 and ion_gun_master_active:
            ion_scale = 1.2

        def _owner_perk_active(owner_id: int, perk_idx: int) -> bool:
            if players is None:
                return False
            if owner_id == -100:
                player_index = 0
            elif owner_id < 0:
                player_index = -1 - int(owner_id)
            else:
                return False
            if not (0 <= player_index < len(players)):
                return False
            perk_counts = getattr(players[player_index], "perk_counts", None)
            if not isinstance(perk_counts, list):
                return False
            return 0 <= perk_idx < len(perk_counts) and int(perk_counts[perk_idx]) > 0

        if damage_scale_by_type is None:
            damage_scale_by_type = {}

        if rng is None:
            rng = _rng_zero

        effects = None
        sfx_queue = None
        if runtime_state is not None:
            effects = getattr(runtime_state, "effects", None)
            sfx_queue = getattr(runtime_state, "sfx_queue", None)

        hits: list[tuple[int, float, float, float, float, float, float]] = []
        margin = 64.0

        def _damage_scale(type_id: int) -> float:
            value = damage_scale_by_type.get(type_id)
            if value is None:
                return float(damage_scale_default)
            return float(value)

        def _damage_type_for() -> int:
            return 1

        ctx = _ProjectileUpdateCtx(
            pool=self,
            creatures=creatures,
            dt=float(dt),
            ion_scale=float(ion_scale),
            detail_preset=int(detail_preset),
            rng=rng,
            runtime_state=runtime_state,
            effects=effects,
            sfx_queue=sfx_queue,
            apply_creature_damage=apply_creature_damage,
        )

        def _reset_shock_chain_if_owner(index: int) -> None:
            if runtime_state is None:
                return
            if getattr(runtime_state, "shock_chain_projectile_id", -1) != index:
                return
            setattr(runtime_state, "shock_chain_projectile_id", -1)
            setattr(runtime_state, "shock_chain_links_left", 0)

        def _try_spawn_shock_chain_link(index: int, hit_creature: int) -> None:
            if runtime_state is None:
                return
            if getattr(runtime_state, "shock_chain_projectile_id", -1) != index:
                return
            links_left = int(getattr(runtime_state, "shock_chain_links_left", 0) or 0)
            if links_left <= 0:
                return
            if not (0 <= hit_creature < len(creatures)):
                return

            origin = creatures[hit_creature]
            best_idx = -1
            best_dist = 0.0
            max_dist = 100.0
            for creature_id, creature in enumerate(creatures):
                if creature_id == hit_creature:
                    continue
                if creature.hp <= 0.0:
                    continue
                d = distance_sq(origin.x, origin.y, creature.x, creature.y)
                if d > max_dist * max_dist:
                    continue
                if best_idx == -1 or d < best_dist:
                    best_idx = creature_id
                    best_dist = d

            setattr(runtime_state, "shock_chain_links_left", links_left - 1)
            if best_idx == -1:
                return

            target = creatures[best_idx]
            angle = math.atan2(target.y - origin.y, target.x - origin.x) + math.pi / 2.0

            set_guard = hasattr(runtime_state, "bonus_spawn_guard")
            if set_guard:
                setattr(runtime_state, "bonus_spawn_guard", True)
            proj_id = self.spawn(
                pos_x=proj.pos_x,
                pos_y=proj.pos_y,
                angle=angle,
                type_id=int(proj.type_id),
                owner_id=hit_creature,
                base_damage=proj.base_damage,
            )
            if set_guard:
                setattr(runtime_state, "bonus_spawn_guard", False)
            setattr(runtime_state, "shock_chain_projectile_id", proj_id)

        for proj_index, proj in enumerate(self._entries):
            if not proj.active:
                continue
            behavior = PROJECTILE_BEHAVIOR_BY_TYPE_ID.get(int(proj.type_id), _DEFAULT_BEHAVIOR)

            if proj.life_timer <= 0.0:
                _reset_shock_chain_if_owner(proj_index)
                proj.active = False
                continue

            if runtime_state is not None and getattr(runtime_state, "shock_chain_projectile_id", -1) == proj_index:
                pending_hit = int(getattr(proj, "reserved", 0.0) or 0.0)
                if pending_hit > 0:
                    proj.reserved = 0.0
                    _try_spawn_shock_chain_link(proj_index, pending_hit - 1)

            if proj.life_timer < 0.4:
                behavior.linger(ctx, proj)

                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            if (
                proj.pos_x < -margin
                or proj.pos_y < -margin
                or proj.pos_x > world_size + margin
                or proj.pos_y > world_size + margin
            ):
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            steps = int(proj.base_damage)
            if steps <= 0:
                steps = 1
            if barrel_greaser_active and int(proj.owner_id) < 0:
                steps *= 2

            dir_x = math.cos(proj.angle - math.pi / 2.0)
            dir_y = math.sin(proj.angle - math.pi / 2.0)

            acc_x = 0.0
            acc_y = 0.0
            step = 0
            while step < steps:
                acc_x += dir_x * dt * 20.0 * proj.speed_scale * 3.0
                acc_y += dir_y * dt * 20.0 * proj.speed_scale * 3.0

                if math.hypot(acc_x, acc_y) >= 4.0 or steps <= step + 3:
                    move_dx = acc_x
                    move_dy = acc_y
                    proj.pos_x += move_dx
                    proj.pos_y += move_dy
                    acc_x = 0.0
                    acc_y = 0.0

                    hit_idx = None
                    for idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        if idx == proj.owner_id:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = proj.hit_radius + creature_radius
                        if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            hit_idx = idx
                            break

                    if hit_idx is None:
                        if proj.hits_players:
                            hit_player_idx = None
                            owner_id = int(proj.owner_id)
                            owner_player_index = -1 - owner_id if owner_id < 0 and owner_id != -100 else None
                            if players is not None:
                                for idx, player in enumerate(players):
                                    if owner_player_index is not None and idx == owner_player_index:
                                        continue
                                    if float(player.health) <= 0.0:
                                        continue
                                    player_radius = _hit_radius_for(player)
                                    hit_r = proj.hit_radius + player_radius
                                    if (
                                        distance_sq(proj.pos_x, proj.pos_y, player.pos_x, player.pos_y)
                                        <= hit_r * hit_r
                                    ):
                                        hit_player_idx = idx
                                        break

                            if hit_player_idx is None:
                                step += 3
                                continue

                            type_id = proj.type_id
                            hit_x = float(proj.pos_x)
                            hit_y = float(proj.pos_y)
                            player = players[int(hit_player_idx)] if players is not None else None
                            target_x = float(getattr(player, "pos_x", hit_x) if player is not None else hit_x)
                            target_y = float(getattr(player, "pos_y", hit_y) if player is not None else hit_y)
                            hits.append((type_id, proj.origin_x, proj.origin_y, hit_x, hit_y, target_x, target_y))

                            if proj.life_timer != 0.25 and type_id not in (
                                ProjectileTypeId.FIRE_BULLETS,
                                ProjectileTypeId.GAUSS_GUN,
                                ProjectileTypeId.BLADE_GUN,
                            ):
                                proj.life_timer = 0.25
                                jitter = rng() & 3
                                proj.pos_x += dir_x * float(jitter)
                                proj.pos_y += dir_y * float(jitter)

                            dist = math.hypot(proj.origin_x - proj.pos_x, proj.origin_y - proj.pos_y)
                            if dist < 50.0:
                                dist = 50.0

                            damage_scale = _damage_scale(type_id)
                            damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95
                            if damage_amount > 0.0:
                                if apply_player_damage is not None:
                                    apply_player_damage(int(hit_player_idx), float(damage_amount))
                                elif players is not None:
                                    players[int(hit_player_idx)].health -= float(damage_amount)

                            break

                        step += 3
                        continue

                    type_id = proj.type_id
                    creature = creatures[hit_idx]

                    if _owner_perk_active(int(proj.owner_id), poison_idx) and (int(rng()) & 7) == 1:
                        if hasattr(creature, "flags"):
                            creature.flags |= CreatureFlags.SELF_DAMAGE_TICK

                    if behavior.pre_hit_creature is not None:
                        behavior.pre_hit_creature(ctx, proj, int(hit_idx))

                    shots_hit = getattr(runtime_state, "shots_hit", None) if runtime_state is not None else None
                    if isinstance(shots_hit, list):
                        owner_id = int(proj.owner_id)
                        if owner_id < 0 and owner_id != -100:
                            player_index = -1 - owner_id
                            if 0 <= player_index < len(shots_hit):
                                shots_hit[player_index] += 1

                    hit_x = float(proj.pos_x)
                    hit_y = float(proj.pos_y)
                    target_x = float(creature.x)
                    target_y = float(creature.y)
                    hits.append((type_id, proj.origin_x, proj.origin_y, hit_x, hit_y, target_x, target_y))

                    if proj.life_timer != 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        proj.life_timer = 0.25
                        jitter = rng() & 3
                        proj.pos_x += dir_x * float(jitter)
                        proj.pos_y += dir_y * float(jitter)

                    dist = math.hypot(proj.origin_x - proj.pos_x, proj.origin_y - proj.pos_y)
                    if dist < 50.0:
                        dist = 50.0

                    if behavior.post_hit_creature is not None:
                        behavior.post_hit_creature(
                            ctx,
                            _ProjectileHitInfo(
                                proj_index=int(proj_index),
                                proj=proj,
                                hit_idx=int(hit_idx),
                                move_dx=float(move_dx),
                                move_dy=float(move_dy),
                                target_x=float(target_x),
                                target_y=float(target_y),
                            ),
                        )

                    damage_scale = _damage_scale(type_id)
                    damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95

                    if damage_amount > 0.0 and creature.hp > 0.0:
                        remaining = proj.damage_pool - 1.0
                        proj.damage_pool = remaining
                        impulse_x = dir_x * float(proj.speed_scale)
                        impulse_y = dir_y * float(proj.speed_scale)
                        damage_type = _damage_type_for()
                        if remaining <= 0.0:
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(damage_amount),
                                damage_type=damage_type,
                                impulse_x=impulse_x,
                                impulse_y=impulse_y,
                                owner_id=int(proj.owner_id),
                                apply_creature_damage=apply_creature_damage,
                            )
                            if proj.life_timer != 0.25:
                                proj.life_timer = 0.25
                        else:
                            hp_before = float(creature.hp)
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(remaining),
                                damage_type=damage_type,
                                impulse_x=impulse_x,
                                impulse_y=impulse_y,
                                owner_id=int(proj.owner_id),
                                apply_creature_damage=apply_creature_damage,
                            )
                            proj.damage_pool -= hp_before

                    if proj.damage_pool == 1.0 and proj.life_timer != 0.25:
                        proj.damage_pool = 0.0
                        proj.life_timer = 0.25

                    if proj.life_timer == 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        break

                    if proj.damage_pool <= 0.0:
                        break

                step += 3

        return hits

    def update_demo(
        self,
        dt: float,
        creatures: list[Damageable],
        *,
        world_size: float,
        speed_by_type: dict[int, float],
        damage_by_type: dict[int, float],
    ) -> list[tuple[int, float, float, float, float, float, float]]:
        """Update a small projectile subset for the demo view.

        Returns a list of hit tuples: (type_id, origin_x, origin_y, hit_x, hit_y, target_x, target_y).
        """

        if dt <= 0.0:
            return []

        hits: list[tuple[int, float, float, float, float, float, float]] = []
        margin = 64.0

        for proj in self._entries:
            if not proj.active:
                continue

            if proj.life_timer <= 0.0:
                proj.active = False
                continue

            if proj.life_timer < 0.4:
                if proj.type_id == ProjectileTypeId.ION_RIFLE:
                    damage = dt * 100.0
                    radius = 88.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            creature.hp -= damage
                elif proj.type_id == ProjectileTypeId.ION_MINIGUN:
                    damage = dt * 40.0
                    radius = 60.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                            creature.hp -= damage
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            if (
                proj.pos_x < -margin
                or proj.pos_y < -margin
                or proj.pos_x > world_size + margin
                or proj.pos_y > world_size + margin
            ):
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            speed = speed_by_type.get(proj.type_id, 650.0) * proj.speed_scale
            direction_x = math.cos(proj.angle - math.pi / 2.0)
            direction_y = math.sin(proj.angle - math.pi / 2.0)
            proj.pos_x += direction_x * speed * dt
            proj.pos_y += direction_y * speed * dt

            hit_idx = None
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = proj.hit_radius + creature_radius
                if distance_sq(proj.pos_x, proj.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is None:
                continue

            hit_x = float(proj.pos_x)
            hit_y = float(proj.pos_y)
            creature = creatures[hit_idx]
            hits.append((proj.type_id, proj.origin_x, proj.origin_y, hit_x, hit_y, float(creature.x), float(creature.y)))

            creature = creatures[hit_idx]
            creature.hp -= damage_by_type.get(proj.type_id, 10.0)

            proj.life_timer = 0.25

        return hits


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
        pos_x: float,
        pos_y: float,
        angle: float,
        type_id: int,
        owner_id: int = -100,
        time_to_live: float = 2.0,
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
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.owner_id = int(owner_id)
        entry.target_id = -1
        entry.trail_timer = 0.0

        if entry.type_id == 3:
            # Detonation state: `vel_x` becomes the expansion timer and `vel_y` the scale.
            entry.vel_x = 0.0
            entry.vel_y = float(time_to_live)
            entry.speed = float(time_to_live)
            return index

        # Effects.md: vel = cos/sin(angle - PI/2) * 90 (190 for type 2).
        base_speed = 90.0
        if entry.type_id == 2:
            base_speed = 190.0
        vx = math.cos(angle - math.pi / 2.0) * base_speed
        vy = math.sin(angle - math.pi / 2.0) * base_speed
        entry.vel_x = vx
        entry.vel_y = vy
        entry.speed = float(time_to_live)
        return index

    def iter_active(self) -> list[SecondaryProjectile]:
        return [entry for entry in self._entries if entry.active]

    def update_pulse_gun(
        self,
        dt: float,
        creatures: list[Damageable],
        *,
        apply_creature_damage: CreatureDamageApplier | None = None,
        runtime_state: object | None = None,
        fx_queue: FxQueueLike | None = None,
        detail_preset: int = 5,
    ) -> None:
        """Update the secondary projectile pool subset (types 1/2/4 + detonation type 3)."""

        if dt <= 0.0:
            return

        def _apply_damage_to_creature(creature_index: int, damage: float, *, owner_id: int) -> None:
            if damage <= 0.0:
                return
            idx = int(creature_index)
            if not (0 <= idx < len(creatures)):
                return
            if apply_creature_damage is not None:
                apply_creature_damage(idx, float(damage), 3, 0.0, 0.0, int(owner_id))
            else:
                creatures[idx].hp -= float(damage)

        rand = _rng_zero
        freeze_active = False
        effects = None
        sprite_effects = None
        sfx_queue = None
        if runtime_state is not None:
            rng = getattr(runtime_state, "rng", None)
            if rng is not None:
                rand = getattr(rng, "rand", _rng_zero)

            bonuses = getattr(runtime_state, "bonuses", None)
            if bonuses is not None and float(getattr(bonuses, "freeze", 0.0)) > 0.0:
                freeze_active = True

            effects = getattr(runtime_state, "effects", None)
            sprite_effects = getattr(runtime_state, "sprite_effects", None)
            sfx_queue = getattr(runtime_state, "sfx_queue", None)

        for entry in self._entries:
            if not entry.active:
                continue

            if entry.type_id == 3:
                # Detonation: `vel_x` becomes the expansion timer (0..1) and `vel_y` the scale.
                entry.vel_x += dt * 3.0
                t = float(entry.vel_x)
                scale = float(entry.vel_y)
                if t > 1.0:
                    if fx_queue is not None:
                        fx_queue.add(
                            effect_id=0x10,
                            pos_x=float(entry.pos_x),
                            pos_y=float(entry.pos_y),
                            width=float(scale) * 256.0,
                            height=float(scale) * 256.0,
                            rotation=0.0,
                            rgba=(0.0, 0.0, 0.0, 0.25),
                        )
                    entry.active = False

                radius = scale * t * 80.0
                damage = dt * scale * 700.0
                for creature_idx, creature in enumerate(creatures):
                    if creature.hp <= 0.0:
                        continue
                    creature_radius = _hit_radius_for(creature)
                    hit_r = radius + creature_radius
                    if distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                        _apply_damage_to_creature(creature_idx, damage, owner_id=int(entry.owner_id))
                continue

            if entry.type_id not in (1, 2, 4):
                continue

            # Move.
            entry.pos_x += entry.vel_x * dt
            entry.pos_y += entry.vel_y * dt

            # Update velocity + countdown.
            speed_mag = math.hypot(entry.vel_x, entry.vel_y)
            if entry.type_id == 1:
                if speed_mag < 500.0:
                    factor = 1.0 + dt * 3.0
                    entry.vel_x *= factor
                    entry.vel_y *= factor
                entry.speed -= dt
            elif entry.type_id == 4:
                if speed_mag < 600.0:
                    factor = 1.0 + dt * 4.0
                    entry.vel_x *= factor
                    entry.vel_y *= factor
                entry.speed -= dt
            else:
                # Type 2: homing projectile.
                target_id = entry.target_id
                if not (0 <= target_id < len(creatures)) or creatures[target_id].hp <= 0.0:
                    best_idx = -1
                    best_dist = 0.0
                    for idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        d = distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y)
                        if best_idx == -1 or d < best_dist:
                            best_idx = idx
                            best_dist = d
                    entry.target_id = best_idx
                    target_id = best_idx

                if 0 <= target_id < len(creatures):
                    target = creatures[target_id]
                    dx = target.x - entry.pos_x
                    dy = target.y - entry.pos_y
                    dist = math.hypot(dx, dy)
                    if dist > 1e-6:
                        angle = math.atan2(dy, dx) + math.pi / 2.0
                        entry.angle = angle
                        dir_x = math.cos(angle - math.pi / 2.0)
                        dir_y = math.sin(angle - math.pi / 2.0)
                        entry.vel_x += dir_x * dt * 800.0
                        entry.vel_y += dir_y * dt * 800.0
                        if 350.0 < math.hypot(entry.vel_x, entry.vel_y):
                            entry.vel_x -= dir_x * dt * 800.0
                            entry.vel_y -= dir_y * dt * 800.0

                entry.speed -= dt * 0.5

            # Rocket smoke trail (`trail_timer` in crimsonland.exe).
            entry.trail_timer -= (abs(float(entry.vel_x)) + abs(float(entry.vel_y))) * dt * 0.01
            if entry.trail_timer < 0.0:
                dir_x = math.cos(float(entry.angle) - math.pi / 2.0)
                dir_y = math.sin(float(entry.angle) - math.pi / 2.0)
                spawn_x = float(entry.pos_x) - dir_x * 9.0
                spawn_y = float(entry.pos_y) - dir_y * 9.0
                vel_x = math.cos(float(entry.angle) + math.pi / 2.0) * 90.0
                vel_y = math.sin(float(entry.angle) + math.pi / 2.0) * 90.0
                if sprite_effects is not None and hasattr(sprite_effects, "spawn"):
                    sprite_id = sprite_effects.spawn(pos_x=spawn_x, pos_y=spawn_y, vel_x=vel_x, vel_y=vel_y, scale=14.0)
                    try:
                        sprite_effects.entries[int(sprite_id)].color_a = 0.25
                    except Exception:
                        pass
                entry.trail_timer = 0.06

            # projectile_update uses creature_find_in_radius(..., 8.0, ...)
            hit_idx: int | None = None
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = 8.0 + creature_radius
                if distance_sq(entry.pos_x, entry.pos_y, creature.x, creature.y) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is not None:
                if isinstance(sfx_queue, list):
                    sfx_queue.append("sfx_explosion_medium")

                damage = 150.0
                if entry.type_id == 1:
                    damage = entry.speed * 50.0 + 500.0
                elif entry.type_id == 2:
                    damage = entry.speed * 20.0 + 80.0
                elif entry.type_id == 4:
                    damage = entry.speed * 20.0 + 40.0
                _apply_damage_to_creature(hit_idx, damage, owner_id=int(entry.owner_id))

                det_scale = 0.5
                if entry.type_id == 1:
                    det_scale = 1.0
                elif entry.type_id == 2:
                    det_scale = 0.35
                elif entry.type_id == 4:
                    det_scale = 0.25

                if freeze_active:
                    if effects is not None and hasattr(effects, "spawn_freeze_shard"):
                        for _ in range(4):
                            shard_angle = float(int(rand()) % 0x264) * 0.01
                            effects.spawn_freeze_shard(
                                pos_x=float(entry.pos_x),
                                pos_y=float(entry.pos_y),
                                angle=shard_angle,
                                rand=rand,
                                detail_preset=int(detail_preset),
                            )
                elif fx_queue is not None:
                    for _ in range(3):
                        off_x = float(int(rand()) % 0x14 - 10)
                        off_y = float(int(rand()) % 0x14 - 10)
                        fx_queue.add_random(
                            pos_x=float(creatures[hit_idx].x) + off_x,
                            pos_y=float(creatures[hit_idx].y) + off_y,
                            rand=rand,
                        )

                if entry.type_id == 1 and effects is not None and hasattr(effects, "spawn_explosion_burst") and int(detail_preset) > 2:
                    effects.spawn_explosion_burst(
                        pos_x=float(entry.pos_x),
                        pos_y=float(entry.pos_y),
                        scale=0.4,
                        rand=rand,
                        detail_preset=int(detail_preset),
                    )

                entry.type_id = 3
                entry.vel_x = 0.0
                entry.vel_y = float(det_scale)
                entry.trail_timer = 0.0

                # Extra debris and scorch decals on detonation.
                if not freeze_active:
                    extra_decals = 0
                    extra_radius = 0.0
                    if entry.type_id == 3:
                        # NOTE: entry.type_id is already 3 here; use det_scale based on prior type.
                        if det_scale == 1.0:
                            extra_decals = 0x14
                            extra_radius = 90.0
                        elif det_scale == 0.35:
                            extra_decals = 10
                            extra_radius = 63.0
                        elif det_scale == 0.25:
                            extra_decals = 3
                            extra_radius = 44.0
                    if fx_queue is not None and extra_decals > 0:
                        cx = float(creatures[hit_idx].x)
                        cy = float(creatures[hit_idx].y)
                        for _ in range(int(extra_decals)):
                            angle = float(int(rand()) % 0x274) * 0.01
                            radius = float(int(rand()) % max(1, int(extra_radius)))
                            fx_queue.add_random(
                                pos_x=cx + math.cos(angle) * radius,
                                pos_y=cy + math.sin(angle) * radius,
                                rand=rand,
                            )

                    if sprite_effects is not None and hasattr(sprite_effects, "spawn"):
                        step = math.tau / 10.0
                        for idx in range(10):
                            mag = float(int(rand()) % 800) * 0.1
                            ang = float(idx) * step
                            vel_x = math.cos(ang) * mag
                            vel_y = math.sin(ang) * mag
                            sprite_id = sprite_effects.spawn(
                                pos_x=float(entry.pos_x),
                                pos_y=float(entry.pos_y),
                                vel_x=vel_x,
                                vel_y=vel_y,
                                scale=14.0,
                            )
                            try:
                                sprite_effects.entries[int(sprite_id)].color_a = 0.37
                            except Exception:
                                pass

                continue

            if entry.speed <= 0.0:
                entry.type_id = 3
                entry.vel_x = 0.0
                entry.vel_y = 0.5
                entry.trail_timer = 0.0
