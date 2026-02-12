from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING, Callable, MutableSequence, Sequence

from grim.geom import Vec2

from ...creatures.spawn import CreatureFlags
from ...weapons import weapon_entry_for_projectile_type_id
from ..effects import (
    _spawn_ion_hit_effects,
    _spawn_plasma_cannon_hit_effects,
    _spawn_shrinkifier_hit_effects,
    _spawn_splitter_hit_effects,
)
from ..types import (
    CreatureDamageApplier,
    Damageable,
    Projectile,
    ProjectileRuntimeState,
    ProjectileTypeId,
    _EffectsLike,
)
from .collision import _apply_damage_to_creature, _hit_radius_for

if TYPE_CHECKING:
    from .projectile_pool import ProjectilePool

@dataclass(slots=True)
class _ProjectileUpdateCtx:
    pool: ProjectilePool
    creatures: Sequence[Damageable]
    dt: float
    ion_scale: float
    detail_preset: int
    rng: Callable[[], int]
    runtime_state: ProjectileRuntimeState | None
    effects: _EffectsLike | None
    sfx_queue: MutableSequence[str] | None
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
    # Native player-hit checks in `projectile_update` key off `owner_id != -100`.
    # Splitter children are spawned with `owner_id = hit creature index`, so they
    # can hit players even when the parent projectile owner was `-100`.
    split_hits_players = int(hit_idx) != -100
    ctx.pool.spawn(
        pos=proj.pos,
        angle=proj.angle - 1.0471976,
        type_id=ProjectileTypeId.SPLITTER_GUN,
        owner_id=int(hit_idx),
        base_damage=proj.base_damage,
        hits_players=split_hits_players,
    )
    ctx.pool.spawn(
        pos=proj.pos,
        angle=proj.angle + 1.0471976,
        type_id=ProjectileTypeId.SPLITTER_GUN,
        owner_id=int(hit_idx),
        base_damage=proj.base_damage,
        hits_players=split_hits_players,
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
    _spawn_shrinkifier_hit_effects(
        ctx.effects,
        pos=hit.proj.pos,
        rng=ctx.rng,
        detail_preset=ctx.detail_preset,
    )

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
