from __future__ import annotations

from grim.geom import Vec2

from .types import ProjectileLike

RAD_TO_DEG = 57.29577951308232


def proj_origin(proj: ProjectileLike, fallback: Vec2) -> Vec2:
    origin = getattr(proj, "origin", None)
    if isinstance(origin, Vec2):
        return origin
    return fallback


__all__ = ["RAD_TO_DEG", "proj_origin"]
