from __future__ import annotations

from .primary_dispatch import draw_projectile_from_registry
from .secondary_dispatch import draw_secondary_projectile_from_registry
from .types import (
    ProjectileDrawCtx,
    ProjectileLike,
    ProjectileRendererLike,
    SecondaryProjectileDrawCtx,
    SecondaryProjectileLike,
)

__all__ = [
    "ProjectileDrawCtx",
    "ProjectileLike",
    "ProjectileRendererLike",
    "SecondaryProjectileDrawCtx",
    "SecondaryProjectileLike",
    "draw_projectile_from_registry",
    "draw_secondary_projectile_from_registry",
]
