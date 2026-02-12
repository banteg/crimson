from __future__ import annotations

from grim.geom import Vec2

from ..projectiles import ProjectileTypeId
from ..weapon_runtime.spawn import owner_id_for_player, projectile_spawn
from .apply_context import BonusApplyCtx


def apply_shock_chain(ctx: BonusApplyCtx) -> None:
    creatures = ctx.creatures
    if not creatures:
        return

    origin_pos = ctx.origin_pos()
    # Mirrors the `exclude_id == -1` behavior of `creature_find_nearest(origin, -1, 0.0)`:
    # - requires `active != 0`
    # - requires `hitbox_size == 16.0` (alive sentinel)
    # - no HP gate
    # - falls back to index 0 if nothing qualifies
    origin = origin_pos.pos
    best_idx = 0
    best_dist_sq = 1e12
    for idx, creature in enumerate(creatures):
        if not creature.active:
            continue
        if creature.hitbox_size != 16.0:
            continue
        d_sq = Vec2.distance_sq(origin, creature.pos)
        if d_sq < best_dist_sq:
            best_dist_sq = d_sq
            best_idx = idx

    target = creatures[best_idx]
    angle = (target.pos - origin).to_heading()
    owner_id = owner_id_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else -100

    ctx.state.bonus_spawn_guard = True
    ctx.state.shock_chain_links_left = 0x20
    ctx.state.shock_chain_projectile_id = projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=angle,
        type_id=int(ProjectileTypeId.ION_RIFLE),
        owner_id=int(owner_id),
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append("sfx_shock_hit_01")
