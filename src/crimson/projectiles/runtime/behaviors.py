from __future__ import annotations

import math
from collections.abc import Callable, MutableSequence, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId

from ...creatures.damage_runtime import CreatureDamageRuntime
from ...creatures.damage_types import CreatureDamageType
from ...creatures.lifecycle import creature_lifecycle_is_collidable
from ...creatures.spawn import CreatureFlags
from ...effects import EffectPool
from ...math_parity import f32
from ...owner_ref import OwnerRef
from ...rng_caller_static import RngCallerStatic
from ...weapons import weapon_entry_for_projectile_type_id
from ..effects import (
    _spawn_ion_hit_effects,
    _spawn_plasma_cannon_hit_effects,
    _spawn_shrinkifier_hit_effects,
    _spawn_splitter_hit_effects,
)
from ..types import (
    Projectile,
    ProjectileTemplateId,
)
from .collision import _apply_damage_to_creature, _hit_radius_for

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState
    from ...gameplay import GameplayState
    from .projectile_pool import ProjectilePool


class _ProjectileUpdateCtx(msgspec.Struct):
    pool: ProjectilePool
    creatures: Sequence[CreatureState]
    dt: float
    ion_scale: float
    detail_preset: int
    rng: CrandLike
    runtime_state: GameplayState | None
    effects: EffectPool | None
    sfx_queue: MutableSequence[SfxId] | None
    creature_damage_runtime: CreatureDamageRuntime


class _ProjectileHitInfo(msgspec.Struct):
    proj_index: int
    proj: Projectile
    hit_idx: int
    move: Vec2
    target: Vec2


class _ProjectileHitPerkCtx(msgspec.Struct):
    proj: Projectile
    creature: CreatureState
    rng: CrandLike
    poison_bullets_active: bool


_ProjectileHitPerkHook = Callable[[_ProjectileHitPerkCtx], None]


def _projectile_hit_perk_poison_bullets(ctx: _ProjectileHitPerkCtx) -> None:
    # Native gates on the global perk count, so the rand is drawn for every
    # projectile hit while any player owns the perk - including creature-owned
    # projectiles such as splitter children and shock-chain segments.
    if (
        ctx.poison_bullets_active
        and (ctx.rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE) & 7) == 1
    ):
        ctx.creature.flags |= CreatureFlags.SELF_DAMAGE_TICK


_PROJECTILE_HIT_PERK_HOOKS: tuple[_ProjectileHitPerkHook, ...] = (_projectile_hit_perk_poison_bullets,)


def _life_timer_sub_f32(life_timer: float, amount: float) -> float:
    return float(f32(float(life_timer) - float(amount)))


def _linger_default(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer = _life_timer_sub_f32(float(proj.life_timer), float(ctx.dt))


def _linger_gauss_gun(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer = _life_timer_sub_f32(float(proj.life_timer), float(ctx.dt) * 0.1)


def _linger_ion_aoe(
    ctx: _ProjectileUpdateCtx,
    proj: Projectile,
    *,
    life_decay_scale: float,
    damage_per_second: float,
    base_radius: float,
) -> None:
    proj.life_timer = _life_timer_sub_f32(float(proj.life_timer), float(ctx.dt) * float(life_decay_scale))
    damage = float(ctx.dt) * float(damage_per_second)
    radius = float(ctx.ion_scale) * float(base_radius)
    for creature_idx, creature in enumerate(ctx.creatures):
        if not creature.active:
            continue
        if not creature_lifecycle_is_collidable(creature.lifecycle_stage):
            continue
        creature_radius = _hit_radius_for(creature)
        hit_r = radius + creature_radius
        if Vec2.distance_sq(proj.pos, creature.pos) <= hit_r * hit_r:
            _apply_damage_to_creature(
                ctx.creatures,
                creature_idx,
                damage,
                damage_type=CreatureDamageType.ION,
                impulse=Vec2(),
                owner=proj.owner,
                creature_damage_runtime=ctx.creature_damage_runtime,
            )


def _linger_ion_minigun(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    _linger_ion_aoe(
        ctx,
        proj,
        life_decay_scale=1.0,
        damage_per_second=40.0,
        base_radius=60.0,
    )


def _linger_ion_rifle(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    _linger_ion_aoe(
        ctx,
        proj,
        life_decay_scale=1.0,
        damage_per_second=100.0,
        base_radius=88.0,
    )


def _linger_ion_cannon(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    _linger_ion_aoe(
        ctx,
        proj,
        life_decay_scale=0.7,
        damage_per_second=300.0,
        base_radius=128.0,
    )


def _pre_hit_splitter(ctx: _ProjectileUpdateCtx, proj: Projectile, hit_idx: int) -> None:
    _spawn_splitter_hit_effects(
        ctx.effects,
        pos=proj.pos,
        rng=ctx.rng,
        detail_preset=ctx.detail_preset,
    )
    # Native player-hit checks key off non-player ownership; creature-owned splitters
    # always satisfy this, so they can hit players even when the parent was local-owned.
    split_hits_players = True
    ctx.pool.spawn(
        pos=proj.pos,
        angle=proj.angle - 1.0471976,
        type_id=ProjectileTemplateId.SPLITTER_GUN,
        owner=OwnerRef.from_creature(int(hit_idx)),
        travel_budget=proj.travel_budget,
        hits_players=split_hits_players,
    )
    ctx.pool.spawn(
        pos=proj.pos,
        angle=proj.angle + 1.0471976,
        type_id=ProjectileTemplateId.SPLITTER_GUN,
        owner=OwnerRef.from_creature(int(hit_idx)),
        travel_budget=proj.travel_budget,
        hits_players=split_hits_players,
    )


def _post_hit_ion_common(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    _spawn_ion_hit_effects(
        ctx.effects,
        ctx.sfx_queue,
        type_id=ProjectileTemplateId(hit.proj.type_id),
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

            best_idx = 0 if bool(runtime_state.preserve_bugs) else -1
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

            if best_idx < 0:
                _post_hit_ion_common(ctx, hit)
                return

            origin = creatures[hit_creature]
            target = creatures[best_idx]
            angle = (target.pos - origin.pos).to_heading()

            prev_guard = bool(runtime_state.bonus_spawn_guard)
            runtime_state.bonus_spawn_guard = True
            try:
                proj_id = ctx.pool.spawn(
                    pos=origin_pos,
                    angle=angle,
                    type_id=ProjectileTemplateId(hit.proj.type_id),
                    owner=OwnerRef.from_creature(hit_creature),
                    travel_budget=hit.proj.travel_budget,
                )
            finally:
                runtime_state.bonus_spawn_guard = prev_guard
            runtime_state.shock_chain_projectile_id = proj_id
    _post_hit_ion_common(ctx, hit)


def _post_hit_plasma_cannon(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    size = float(creature.size)
    ring_radius = size * 0.5 + 1.0

    plasma_entry = weapon_entry_for_projectile_type_id(ProjectileTemplateId.PLASMA_RIFLE)
    plasma_meta = float(plasma_entry.travel_budget)

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
                type_id=ProjectileTemplateId.PLASMA_RIFLE,
                owner=OwnerRef.from_local_player(0),
                travel_budget=plasma_meta,
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


def _no_death_sfx() -> tuple[SfxId, ...]:
    return ()


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
        # Native calls creature_handle_death directly: no damage pipeline, so no
        # heading-jitter or death-SFX rand draws, and hp stays positive so the
        # generic chip damage after this hook still applies.
        ctx.creature_damage_runtime.on_creature_lethal(int(hit.hit_idx), _no_death_sfx)
    hit.proj.life_timer = 0.25


def _post_hit_pulse_gun(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    creature.pos = creature.pos + hit.move * 3.0


def _post_hit_plague_spreader(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    creature.plague_infected = True
