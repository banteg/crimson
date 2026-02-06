from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import math
from typing import Callable, Protocol

from grim.color import RGBA
from grim.geom import Vec2

from .creatures.spawn import CreatureFlags
from .effects_atlas import EffectId
from .perks import PerkId
from .weapons import weapon_entry_for_projectile_type_id


class Damageable(Protocol):
    active: bool
    pos: Vec2
    hp: float
    hitbox_size: float
    size: float
    flags: int
    plague_infected: bool


class PlayerDamageable(Protocol):
    pos: Vec2
    health: float
    shield_timer: float
    size: float
    perk_counts: list[int]


class _RngLike(Protocol):
    def rand(self) -> int: ...


class _BonusesLike(Protocol):
    freeze: float


class ProjectileRuntimeState(Protocol):
    bonus_spawn_guard: bool
    effects: object
    sprite_effects: object
    rng: _RngLike
    bonuses: _BonusesLike
    sfx_queue: list[str]
    camera_shake_pulses: int
    shots_hit: list[int]
    shock_chain_links_left: int
    shock_chain_projectile_id: int


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


def _rng_zero() -> int:
    return 0


CreatureDamageApplier = Callable[[int, float, int, Vec2, int], None]


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
    target_hint_active: bool = False
    target_hint: Vec2 = field(default_factory=Vec2)


def _hit_radius_for(creature: Damageable) -> float:
    """Approximate `creature_find_in_radius`/`creatures_apply_radius_damage` sizing.

    The native code compares `distance - radius < creature.size * 0.14285715 + 3.0`.
    """

    size = float(creature.size)
    return max(0.0, size * 0.14285715 + 3.0)


def _apply_damage_to_creature(
    creatures: list[Damageable],
    creature_index: int,
    damage: float,
    *,
    damage_type: int,
    impulse: Vec2,
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
            impulse,
            int(owner_id),
        )
    else:
        creatures[idx].hp -= float(damage)


def _spawn_ion_hit_effects(
    effects: object | None,
    sfx_queue: object | None,
    *,
    type_id: int,
    pos: Vec2,
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
        effect_id=int(EffectId.RING),
        pos=pos,
        vel=Vec2(),
        rotation=0.0,
        scale=1.0,
        half_width=4.0,
        half_height=4.0,
        age=0.0,
        lifetime=float(ring_strength) * 0.8,
        flags=0x19,
        color=RGBA(0.6, 0.6, 0.9, 1.0),
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
        velocity = Vec2(
            float((int(rng()) & 0x7F) - 0x40) * burst * 1.4,
            float((int(rng()) & 0x7F) - 0x40) * burst * 1.4,
        )
        scale_step = (float(int(rng()) % 100) * 0.01 + 0.1) * burst
        effects.spawn(
            effect_id=int(EffectId.BURST),
            pos=pos,
            vel=velocity,
            rotation=rotation,
            scale=1.0,
            half_width=half,
            half_height=half,
            age=0.0,
            lifetime=float(lifetime),
            flags=0x1D,
            color=RGBA(0.4, 0.5, 1.0, 0.5),
            rotation_step=0.0,
            scale_step=scale_step,
            detail_preset=detail,
        )


def _spawn_plasma_cannon_hit_effects(
    effects: object | None,
    sfx_queue: object | None,
    *,
    pos: Vec2,
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
            effect_id=int(EffectId.RING),
            pos=pos,
            vel=Vec2(),
            rotation=0.0,
            scale=1.0,
            half_width=4.0,
            half_height=4.0,
            age=0.1,
            lifetime=1.0,
            flags=0x19,
            color=RGBA(0.9, 0.6, 0.3, 1.0),
            rotation_step=0.0,
            scale_step=float(scale) * 45.0,
            detail_preset=detail,
        )

    _spawn_ring(scale=1.5)
    _spawn_ring(scale=1.0)


def _spawn_splitter_hit_effects(
    effects: object | None,
    *,
    pos: Vec2,
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

        offset = Vec2.from_angle(angle) * radius
        effects.spawn(
            effect_id=int(EffectId.BURST),
            pos=pos + offset,
            vel=Vec2(),
            rotation=0.0,
            scale=1.0,
            half_width=4.0,
            half_height=4.0,
            age=jitter_age,
            lifetime=lifetime,
            flags=0x19,
            color=RGBA(1.0, 0.9, 0.1, 1.0),
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
    runtime_state: ProjectileRuntimeState | None
    effects: object | None
    sfx_queue: object | None
    apply_creature_damage: CreatureDamageApplier | None


@dataclass(slots=True)
class _ProjectileHitInfo:
    proj_index: int
    proj: Projectile
    hit_idx: int
    move: Vec2
    target: Vec2


@dataclass(slots=True)
class _ProjectileHitPerkCtx:
    proj: Projectile
    creature: Damageable
    rng: Callable[[], int]
    owner_perk_active: Callable[[int, int], bool]
    poison_idx: int


_ProjectileHitPerkHook = Callable[[_ProjectileHitPerkCtx], None]


def _projectile_hit_perk_poison_bullets(ctx: _ProjectileHitPerkCtx) -> None:
    if ctx.owner_perk_active(int(ctx.proj.owner_id), int(ctx.poison_idx)) and (int(ctx.rng()) & 7) == 1:
        ctx.creature.flags |= CreatureFlags.SELF_DAMAGE_TICK


_PROJECTILE_HIT_PERK_HOOKS: tuple[_ProjectileHitPerkHook, ...] = (_projectile_hit_perk_poison_bullets,)


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
        if not creature.active:
            continue
        if creature.hitbox_size <= 5.0:
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=7,
                impulse=Vec2(),
                owner_id=int(proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )


def _linger_ion_rifle(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt
    damage = ctx.dt * 100.0
    radius = ctx.ion_scale * 88.0
    for creature_idx, creature in enumerate(ctx.creatures):
        if not creature.active:
            continue
        if creature.hitbox_size <= 5.0:
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=7,
                impulse=Vec2(),
                owner_id=int(proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )


def _linger_ion_cannon(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer -= ctx.dt * 0.7
    damage = ctx.dt * 300.0
    radius = ctx.ion_scale * 128.0
    for creature_idx, creature in enumerate(ctx.creatures):
        if not creature.active:
            continue
        if creature.hitbox_size <= 5.0:
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=7,
                impulse=Vec2(),
                owner_id=int(proj.owner_id),
                apply_creature_damage=ctx.apply_creature_damage,
            )


def _pre_hit_splitter(ctx: _ProjectileUpdateCtx, proj: Projectile, hit_idx: int) -> None:
    _spawn_splitter_hit_effects(
        ctx.effects,
        pos=proj.pos,
        rng=ctx.rng,
        detail_preset=ctx.detail_preset,
    )
    ctx.pool.spawn(
        pos=proj.pos,
        angle=proj.angle - 1.0471976,
        type_id=ProjectileTypeId.SPLITTER_GUN,
        owner_id=int(hit_idx),
        base_damage=proj.base_damage,
        hits_players=proj.hits_players,
    )
    ctx.pool.spawn(
        pos=proj.pos,
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
        pos=hit.proj.pos,
        rng=ctx.rng,
        detail_preset=ctx.detail_preset,
    )


def _post_hit_ion_rifle(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    runtime_state = ctx.runtime_state
    creatures = ctx.creatures
    hit_creature = int(hit.hit_idx)
    if (
        runtime_state is not None
        and runtime_state.shock_chain_projectile_id == hit.proj_index
        and 0 <= hit_creature < len(creatures)
    ):
        links_left = int(runtime_state.shock_chain_links_left)
        if links_left > 0 and creatures:
            runtime_state.shock_chain_links_left = links_left - 1

            origin_pos = hit.proj.pos
            min_dist_sq = 100.0 * 100.0

            best_idx = 0
            best_dist_sq = 1e12
            for creature_id, creature in enumerate(creatures):
                if creature_id == hit_creature:
                    continue
                if not creature.active:
                    continue
                d_sq = Vec2.distance_sq(origin_pos, creature.pos)
                if d_sq <= min_dist_sq:
                    continue
                if d_sq < best_dist_sq:
                    best_dist_sq = d_sq
                    best_idx = creature_id

            origin = creatures[hit_creature]
            target = creatures[best_idx]
            angle = (target.pos - origin.pos).to_heading()

            prev_guard = bool(runtime_state.bonus_spawn_guard)
            runtime_state.bonus_spawn_guard = True
            try:
                proj_id = ctx.pool.spawn(
                    pos=origin_pos,
                    angle=angle,
                    type_id=int(hit.proj.type_id),
                    owner_id=hit_creature,
                    base_damage=hit.proj.base_damage,
                )
            finally:
                runtime_state.bonus_spawn_guard = prev_guard
            runtime_state.shock_chain_projectile_id = proj_id
    _post_hit_ion_common(ctx, hit)


def _post_hit_plasma_cannon(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    size = float(creature.size)
    ring_radius = size * 0.5 + 1.0

    plasma_entry = weapon_entry_for_projectile_type_id(int(ProjectileTypeId.PLASMA_RIFLE))
    plasma_meta = float(plasma_entry.projectile_meta) if plasma_entry and plasma_entry.projectile_meta is not None else hit.proj.base_damage

    runtime_state = ctx.runtime_state
    prev_guard = False
    if runtime_state is not None:
        prev_guard = bool(runtime_state.bonus_spawn_guard)
        runtime_state.bonus_spawn_guard = True
    try:
        for ring_idx in range(12):
            ring_angle = float(ring_idx) * (math.pi / 6.0)
            ring_offset = Vec2.from_angle(ring_angle) * ring_radius
            ctx.pool.spawn(
                pos=hit.proj.pos + ring_offset,
                angle=ring_angle,
                type_id=ProjectileTypeId.PLASMA_RIFLE,
                owner_id=-100,
                base_damage=plasma_meta,
            )
    finally:
        if runtime_state is not None:
            runtime_state.bonus_spawn_guard = prev_guard

    _spawn_plasma_cannon_hit_effects(
        ctx.effects,
        ctx.sfx_queue,
        pos=hit.proj.pos,
        detail_preset=ctx.detail_preset,
    )


def _post_hit_shrinkifier(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    new_size = float(creature.size) * 0.65
    creature.size = new_size
    if new_size < 16.0:
        _apply_damage_to_creature(
            ctx.creatures,
            int(hit.hit_idx),
            float(creature.hp) + 1.0,
            damage_type=1,
            impulse=Vec2(),
            owner_id=int(hit.proj.owner_id),
            apply_creature_damage=ctx.apply_creature_damage,
        )
    hit.proj.life_timer = 0.25


def _post_hit_pulse_gun(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    creature.pos = creature.pos + hit.move * 3.0


def _post_hit_plague_spreader(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    creature.plague_infected = True


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
        pos: Vec2,
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
        entry.pos = pos
        entry.origin = pos
        entry.type_id = int(type_id)
        entry.life_timer = 0.4
        entry.reserved = 0.0
        entry.speed_scale = 1.0
        entry.base_damage = float(base_damage)
        weapon_entry = weapon_entry_for_projectile_type_id(entry.type_id)
        if weapon_entry is not None and weapon_entry.projectile_meta is not None:
            entry.base_damage = float(weapon_entry.projectile_meta)
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
        runtime_state: ProjectileRuntimeState | None = None,
        players: list[PlayerDamageable] | None = None,
        apply_player_damage: Callable[[int, float], None] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
    ) -> list[ProjectileHit]:
        """Update the main projectile pool.

        Modeled after `projectile_update` (0x00420b90) for the subset used by demo/state-9 work.
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
                perk_counts = player.perk_counts

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
            perk_counts = players[player_index].perk_counts
            return 0 <= perk_idx < len(perk_counts) and int(perk_counts[perk_idx]) > 0

        if damage_scale_by_type is None:
            damage_scale_by_type = {}

        if rng is None:
            rng = _rng_zero

        effects = None
        sfx_queue = None
        if runtime_state is not None:
            effects = runtime_state.effects
            sfx_queue = runtime_state.sfx_queue

        hits: list[ProjectileHit] = []
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
            if runtime_state.shock_chain_projectile_id != index:
                return
            runtime_state.shock_chain_projectile_id = -1
            runtime_state.shock_chain_links_left = 0

        for proj_index, proj in enumerate(self._entries):
            if not proj.active:
                continue
            behavior = PROJECTILE_BEHAVIOR_BY_TYPE_ID.get(int(proj.type_id), _DEFAULT_BEHAVIOR)

            if proj.life_timer <= 0.0:
                _reset_shock_chain_if_owner(proj_index)
                proj.active = False
                continue

            if proj.life_timer < 0.4:
                if int(proj.type_id) in (int(ProjectileTypeId.ION_RIFLE), int(ProjectileTypeId.ION_MINIGUN)):
                    _reset_shock_chain_if_owner(proj_index)
                behavior.linger(ctx, proj)

                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > world_size + margin
                or proj.pos.y > world_size + margin
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

            direction = Vec2.from_heading(float(proj.angle))
            acc = Vec2()
            step = 0
            while step < steps:
                acc = acc + direction * (dt * 20.0 * proj.speed_scale * 3.0)

                if acc.length() >= 4.0 or steps <= step + 3:
                    move = acc
                    proj.pos = proj.pos + move
                    acc = Vec2()

                    hit_idx = None
                    ion_hit_test = int(proj.type_id) in (
                        int(ProjectileTypeId.ION_RIFLE),
                        int(ProjectileTypeId.ION_MINIGUN),
                        int(ProjectileTypeId.ION_CANNON),
                    )
                    for idx, creature in enumerate(creatures):
                        if idx == proj.owner_id:
                            continue
                        if ion_hit_test:
                            if not creature.active:
                                continue
                            if creature.hitbox_size <= 5.0:
                                continue
                        elif creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = proj.hit_radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
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
                                        Vec2.distance_sq(proj.pos, player.pos)
                                        <= hit_r * hit_r
                                    ):
                                        hit_player_idx = idx
                                        break

                            if hit_player_idx is None:
                                step += 3
                                continue

                            type_id = proj.type_id
                            assert players is not None
                            player = players[int(hit_player_idx)]
                            hits.append(
                                ProjectileHit(
                                    type_id=int(type_id),
                                    origin=proj.origin,
                                    hit=proj.pos,
                                    target=player.pos,
                                )
                            )

                            proj.life_timer = 0.25
                            if apply_player_damage is not None:
                                apply_player_damage(int(hit_player_idx), 10.0)
                            else:
                                if float(player.shield_timer) <= 0.0:
                                    player.health -= 10.0

                            break

                        step += 3
                        continue

                    type_id = proj.type_id
                    creature = creatures[hit_idx]

                    perk_ctx = _ProjectileHitPerkCtx(
                        proj=proj,
                        creature=creature,
                        rng=rng,
                        owner_perk_active=_owner_perk_active,
                        poison_idx=poison_idx,
                    )
                    for hook in _PROJECTILE_HIT_PERK_HOOKS:
                        hook(perk_ctx)

                    if behavior.pre_hit_creature is not None:
                        behavior.pre_hit_creature(ctx, proj, int(hit_idx))

                    if runtime_state is not None:
                        owner_id = int(proj.owner_id)
                        if owner_id < 0 and owner_id != -100:
                            shots_hit = runtime_state.shots_hit
                            player_index = -1 - owner_id
                            if 0 <= player_index < len(shots_hit):
                                shots_hit[player_index] += 1

                    target = creature.pos
                    hits.append(
                        ProjectileHit(
                            type_id=int(type_id),
                            origin=proj.origin,
                            hit=proj.pos,
                            target=target,
                        )
                    )

                    if proj.life_timer != 0.25 and type_id not in (
                        ProjectileTypeId.FIRE_BULLETS,
                        ProjectileTypeId.GAUSS_GUN,
                        ProjectileTypeId.BLADE_GUN,
                    ):
                        proj.life_timer = 0.25
                        jitter = rng() & 3
                        proj.pos = proj.pos + direction * float(jitter)

                    dist = proj.origin.distance_to(proj.pos)
                    if dist < 50.0:
                        dist = 50.0

                    if behavior.post_hit_creature is not None:
                        behavior.post_hit_creature(
                            ctx,
                            _ProjectileHitInfo(
                                proj_index=int(proj_index),
                                proj=proj,
                                hit_idx=int(hit_idx),
                                move=move,
                                target=target,
                            ),
                        )

                    damage_scale = _damage_scale(type_id)
                    damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95

                    if damage_amount > 0.0 and (creature.hp > 0.0 or ion_hit_test):
                        remaining = proj.damage_pool - 1.0
                        proj.damage_pool = remaining
                        impulse = direction * float(proj.speed_scale)
                        damage_type = _damage_type_for()
                        if remaining <= 0.0:
                            _apply_damage_to_creature(
                                creatures,
                                int(hit_idx),
                                float(damage_amount),
                                damage_type=damage_type,
                                impulse=impulse,
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
                                impulse=impulse,
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
    ) -> list[ProjectileHit]:
        """Update a small projectile subset for the demo view.
        """

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
                if proj.type_id == ProjectileTypeId.ION_RIFLE:
                    damage = dt * 100.0
                    radius = 88.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                            creature.hp -= damage
                elif proj.type_id == ProjectileTypeId.ION_MINIGUN:
                    damage = dt * 40.0
                    radius = 60.0
                    for creature in creatures:
                        if creature.hp <= 0.0:
                            continue
                        creature_radius = _hit_radius_for(creature)
                        hit_r = radius + creature_radius
                        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
                            creature.hp -= damage
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
                continue

            if (
                proj.pos.x < -margin
                or proj.pos.y < -margin
                or proj.pos.x > world_size + margin
                or proj.pos.y > world_size + margin
            ):
                proj.life_timer -= dt
                if proj.life_timer <= 0.0:
                    proj.active = False
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
                    type_id=int(proj.type_id),
                    origin=proj.origin,
                    hit=proj.pos,
                    target=creature.pos,
                )
            )

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
        pos: Vec2,
        angle: float,
        type_id: int,
        owner_id: int = -100,
        time_to_live: float = 2.0,
        target_hint: Vec2 | None = None,
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

        if entry.type_id == SecondaryProjectileTypeId.HOMING_ROCKET and target_hint is not None:
            entry.target_hint_active = True
            entry.target_hint = target_hint

        return index

    def iter_active(self) -> list[SecondaryProjectile]:
        return [entry for entry in self._entries if entry.active]

    def update_pulse_gun(
        self,
        dt: float,
        creatures: list[Damageable],
        *,
        apply_creature_damage: CreatureDamageApplier | None = None,
        runtime_state: ProjectileRuntimeState | None = None,
        fx_queue: FxQueueLike | None = None,
        detail_preset: int = 5,
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
        effects: object | None = None
        sprite_effects: object | None = None
        sfx_queue: list[str] | None = None
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
                    if creature.hp <= 0.0:
                        continue
                    d_sq = Vec2.distance_sq(entry.pos, creature.pos)
                    if d_sq < radius_sq:
                        impulse_dir = entry.pos.direction_to(creature.pos)
                        impulse = impulse_dir * 0.1
                        _apply_secondary_damage(
                            creature_idx,
                            damage,
                            owner_id=int(entry.owner_id),
                            impulse=impulse,
                        )
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
                if not (0 <= target_id < len(creatures)) or creatures[target_id].hp <= 0.0:
                    search_pos = entry.pos
                    if entry.target_hint_active:
                        entry.target_hint_active = False
                        search_pos = entry.target_hint
                    best_idx = -1
                    best_dist = 0.0
                    for idx, creature in enumerate(creatures):
                        if creature.hp <= 0.0:
                            continue
                        d = Vec2.distance_sq(search_pos, creature.pos)
                        if best_idx == -1 or d < best_dist:
                            best_idx = idx
                            best_dist = d
                    entry.target_id = best_idx
                    target_id = best_idx

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
                if sprite_effects is not None and hasattr(sprite_effects, "spawn"):
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
                if creature.hp <= 0.0:
                    continue
                creature_radius = _hit_radius_for(creature)
                hit_r = 8.0 + creature_radius
                if Vec2.distance_sq(entry.pos, creature.pos) <= hit_r * hit_r:
                    hit_idx = idx
                    break
            if hit_idx is not None:
                if sfx_queue is not None:
                    sfx_queue.append("sfx_explosion_medium")

                hit_type_id = SecondaryProjectileTypeId(int(entry.type_id))

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

                det_scale = 0.5
                if entry.type_id == SecondaryProjectileTypeId.ROCKET:
                    det_scale = 1.0
                elif entry.type_id == SecondaryProjectileTypeId.HOMING_ROCKET:
                    det_scale = 0.35
                elif entry.type_id == SecondaryProjectileTypeId.ROCKET_MINIGUN:
                    det_scale = 0.25

                if freeze_active:
                    if effects is not None and hasattr(effects, "spawn_freeze_shard"):
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
                    and hasattr(effects, "spawn_explosion_burst")
                    and int(detail_preset) > 2
                ):
                    effects.spawn_explosion_burst(
                        pos=entry.pos,
                        scale=0.4,
                        rand=rand,
                        detail_preset=int(detail_preset),
                    )

                entry.type_id = SecondaryProjectileTypeId.DETONATION
                entry.vel = Vec2()
                entry.detonation_t = 0.0
                entry.detonation_scale = float(det_scale)
                entry.trail_timer = 0.0

                # Extra debris/scorch decals (or freeze shards) on detonation.
                if freeze_active:
                    if effects is not None and hasattr(effects, "spawn_freeze_shard"):
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

                if sprite_effects is not None and hasattr(sprite_effects, "spawn"):
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
