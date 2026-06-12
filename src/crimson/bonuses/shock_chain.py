from __future__ import annotations

import math

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ..creatures.lifecycle import creature_lifecycle_is_alive
from ..math_parity import NATIVE_HALF_PI, NATIVE_PI, f32
from ..owner_ref import OwnerRef
from ..projectiles.types import ProjectileTemplateId
from ..weapon_runtime.spawn import owner_ref_for_player, projectile_spawn
from .apply_context import BonusApplyCtx


def apply_shock_chain(ctx: BonusApplyCtx) -> None:
    creatures = ctx.creatures
    if not creatures:
        return

    # Mirrors the `exclude_id == -1` behavior of `creature_find_nearest(origin, -1, 0.0)`:
    # - requires `active != 0`
    # - requires `lifecycle_stage == 16.0` (alive sentinel)
    # - no HP gate
    origin = ctx.origin_pos
    best_idx = 0 if bool(ctx.state.preserve_bugs) else -1
    best_dist_sq = 1e12
    for idx, creature in enumerate(creatures):
        if not creature.active:
            continue
        if not creature_lifecycle_is_alive(creature.lifecycle_stage):
            continue
        d_sq = Vec2.distance_sq(origin, creature.pos)
        if d_sq < best_dist_sq:
            best_dist_sq = d_sq
            best_idx = idx

    if best_idx < 0:
        return

    target = creatures[best_idx]
    # Native stores `(float)(atan2(dy, dx) - 1.5707964 - 3.1415927)` with a
    # single f32 spill; the value differs from to_heading() by 2*pi and feeds
    # the projectile's stored f32 angle and velocity.
    delta = target.pos - origin
    angle = float(f32(math.atan2(float(delta.y), float(delta.x)) - NATIVE_HALF_PI - NATIVE_PI))
    owner = (
        owner_ref_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else OwnerRef.from_local_player(0)
    )

    ctx.state.bonus_spawn_guard = True
    ctx.state.shock_chain_links_left = 0x20
    ctx.state.shock_chain_projectile_id = projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=angle,
        type_id=ProjectileTemplateId.ION_RIFLE,
        owner=owner,
        owner_player_index=ctx.player.index,
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append(SfxId.SHOCK_HIT_01)
