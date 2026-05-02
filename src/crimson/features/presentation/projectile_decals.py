from __future__ import annotations

from grim.geom import Vec2
from grim.rand import CrandLike

from ...bonuses.fire_bullets import LargeHitDecalRuntime, queue_large_hit_decal_streak
from ...effects import FxQueue
from ...projectiles.types import ProjectileHit, ProjectileTemplateId


def queue_projectile_large_streak_decal(
    *,
    hit: ProjectileHit,
    base_angle: float,
    fx_queue: FxQueue,
    rng: CrandLike,
    freeze_origin: Vec2 | None = None,
    runtime: LargeHitDecalRuntime | None = None,
) -> bool:
    type_id = hit.type_id
    if type_id not in (ProjectileTemplateId.GAUSS_GUN, ProjectileTemplateId.FIRE_BULLETS):
        return False
    queue_large_hit_decal_streak(
        hit=hit,
        base_angle=float(base_angle),
        fx_queue=fx_queue,
        rng=rng,
        freeze_origin=freeze_origin,
        runtime=runtime,
    )
    return True
