from __future__ import annotations

"""Ordered projectile-decal hooks for presentation planning."""

from dataclasses import dataclass
from typing import Callable

from ...effects import FxQueue
from ...projectiles import ProjectileHit, ProjectileTypeId
from ..bonuses.fire_bullets import queue_large_hit_decal_streak


@dataclass(slots=True)
class ProjectileDecalCtx:
    hit: ProjectileHit
    base_angle: float
    fx_queue: FxQueue
    rand: Callable[[], int]


def _hook_large_streak_projectiles(ctx: ProjectileDecalCtx) -> bool:
    type_id = int(ctx.hit.type_id)
    if type_id not in (int(ProjectileTypeId.GAUSS_GUN), int(ProjectileTypeId.FIRE_BULLETS)):
        return False
    queue_large_hit_decal_streak(
        hit=ctx.hit,
        base_angle=float(ctx.base_angle),
        fx_queue=ctx.fx_queue,
        rand=ctx.rand,
    )
    return True


_PROJECTILE_DECAL_HOOKS = (_hook_large_streak_projectiles,)


def run_projectile_decal_hooks(ctx: ProjectileDecalCtx) -> bool:
    """Run ordered decal hooks and return True when one handles the hit."""
    for hook in _PROJECTILE_DECAL_HOOKS:
        if hook(ctx):
            return True
    return False

