from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

if TYPE_CHECKING:
    from ...projectiles.types import Projectile, SecondaryProjectile
    from ..world.context import WorldRenderCtx


class ProjectileDrawCtx(msgspec.Struct, frozen=True):
    renderer: WorldRenderCtx
    proj: Projectile
    proj_index: int
    texture: rl.Texture | None
    type_id: int
    pos: Vec2
    screen_pos: Vec2
    life: float
    angle: float
    scale: float
    alpha: float


class SecondaryProjectileDrawCtx(msgspec.Struct, frozen=True):
    renderer: WorldRenderCtx
    proj: SecondaryProjectile
    proj_type: int
    screen_pos: Vec2
    angle: float
    scale: float
    alpha: float


__all__ = [
    "ProjectileDrawCtx",
    "SecondaryProjectileDrawCtx",
]
