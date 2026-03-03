from __future__ import annotations

from grim.geom import Vec2

from ...projectiles.types import Projectile

RAD_TO_DEG = 57.29577951308232


def proj_origin(proj: Projectile, fallback: Vec2) -> Vec2:
    _ = fallback
    return proj.origin


__all__ = ["RAD_TO_DEG", "proj_origin"]
