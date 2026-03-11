from __future__ import annotations

from collections.abc import Callable

from grim.geom import Vec2
from grim.rand import RandDrawLike

from ...bonuses.fire_bullets import queue_large_hit_decal_streak
from ...effects import FxQueue
from ...projectiles.types import ProjectileHit, ProjectileTemplateId


def queue_projectile_large_streak_decal(
    *,
    hit: ProjectileHit,
    base_angle: float,
    fx_queue: FxQueue,
    rand: RandDrawLike,
    freeze_origin: Vec2 | None = None,
    spawn_freeze_shard: Callable[[Vec2, float], None] | None = None,
) -> bool:
    type_id = hit.type_id
    if type_id not in (ProjectileTemplateId.GAUSS_GUN, ProjectileTemplateId.FIRE_BULLETS):
        return False
    queue_large_hit_decal_streak(
        hit=hit,
        base_angle=float(base_angle),
        fx_queue=fx_queue,
        rand=rand,
        freeze_origin=freeze_origin,
        spawn_freeze_shard=spawn_freeze_shard,
    )
    return True
