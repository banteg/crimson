from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2

if TYPE_CHECKING:
    from ...projectiles import Projectile

RAD_TO_DEG = 57.29577951308232


def proj_origin(proj: Projectile, fallback: Vec2) -> Vec2:
    origin = getattr(proj, "origin", None)
    if isinstance(origin, Vec2):
        return origin
    return fallback


__all__ = ["RAD_TO_DEG", "proj_origin"]
