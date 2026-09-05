from __future__ import annotations

import math
from collections.abc import Callable, MutableSequence, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ...creatures.damage_runtime import CreatureDamageRuntime
from ...creatures.damage_types import CreatureDamageType
from ...creatures.lifecycle import creature_lifecycle_is_collidable
from ...effects import EffectPool
from ...math_parity import NATIVE_HALF_PI, NATIVE_PI, f32, x87_pc24_mul, x87_pc24_sub
from ...owner_ref import OwnerRef
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
from .collision import (
    _apply_damage_to_creature,
    _within_native_find_radius,
    creature_find_nearest_active,
)

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState
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
    sfx_queue: MutableSequence[SfxRequest] | None
    creature_damage_runtime: CreatureDamageRuntime
    sync_creature_index: Callable[[int], None] | None = None


class _ProjectileHitInfo(msgspec.Struct):
    proj_index: int
    proj: Projectile
    hit_idx: int
    move: Vec2
    target: Vec2


def _life_timer_sub_f32(life_timer: float, amount: float) -> float:
    return x87_pc24_sub(life_timer, amount)


def _linger_default(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    proj.life_timer = _life_timer_sub_f32(float(proj.life_timer), float(ctx.dt))


def _linger_gauss_gun(ctx: _ProjectileUpdateCtx, proj: Projectile) -> None:
    decay = x87_pc24_mul(ctx.dt, f32(0.1))
    proj.life_timer = _life_timer_sub_f32(proj.life_timer, decay)


def _linger_ion_aoe(
    ctx: _ProjectileUpdateCtx,
    proj: Projectile,
    *,
    life_decay_scale: float,
    damage_per_second: float,
    base_radius: float,
) -> None:
    decay = x87_pc24_mul(ctx.dt, f32(life_decay_scale))
    proj.life_timer = _life_timer_sub_f32(proj.life_timer, decay)
    damage = x87_pc24_mul(ctx.dt, f32(damage_per_second))
    radius = x87_pc24_mul(f32(ctx.ion_scale), f32(base_radius))
    for creature_idx, creature in enumerate(ctx.creatures):
        if not creature.active:
            continue
        if not creature_lifecycle_is_collidable(creature.lifecycle_stage):
            continue
        # Native uses the strict sqrt-form predicate from creature_find_in_radius.
        if _within_native_find_radius(
            origin=proj.pos,
            target=creature.pos,
            radius=float(radius),
            target_size=float(creature.size),
        ):
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
            best_idx = creature_find_nearest_active(
                creatures=creatures,
                origin=origin_pos,
                exclude_id=hit_creature,
                min_dist=100.0,
                preserve_bugs=bool(runtime_state.preserve_bugs),
            )

            if best_idx < 0:
                _post_hit_ion_common(ctx, hit)
                return

            origin = creatures[hit_creature]
            target = creatures[best_idx]
            # Native stores `(float)(atan2(dy, dx) - 1.5707964 - 3.1415927)`
            # with a single f32 spill (differs from to_heading() by 2*pi).
            delta = target.pos - origin.pos
            angle = float(f32(math.atan2(float(delta.y), float(delta.x)) - NATIVE_HALF_PI - NATIVE_PI))

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
                runtime_state.bonus_spawn_guard = False
            runtime_state.shock_chain_projectile_id = proj_id
    _post_hit_ion_common(ctx, hit)


def _post_hit_plasma_cannon(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    size = float(creature.size)
    ring_radius = size * 0.5 + 1.0

    plasma_entry = weapon_entry_for_projectile_type_id(ProjectileTemplateId.PLASMA_RIFLE)
    plasma_meta = float(plasma_entry.travel_budget)

    runtime_state = ctx.runtime_state
    if runtime_state is not None:
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
            runtime_state.bonus_spawn_guard = False

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
    # Native re-scans the pool per query, so later projectiles this tick see
    # the pushed creature at its new position; resync the spatial hash.
    if ctx.sync_creature_index is not None:
        ctx.sync_creature_index(int(hit.hit_idx))


def _post_hit_plague_spreader(ctx: _ProjectileUpdateCtx, hit: _ProjectileHitInfo) -> None:
    creature = ctx.creatures[int(hit.hit_idx)]
    creature.plague_infected = True
