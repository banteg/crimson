from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pyray as rl

from grim.geom import Vec2

if TYPE_CHECKING:
    from ...projectiles import Projectile, SecondaryProjectile
    from ..world.renderer import WorldRenderer


@dataclass(frozen=True, slots=True)
class ProjectileDrawCtx:
    renderer: WorldRenderer
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


@dataclass(frozen=True, slots=True)
class SecondaryProjectileDrawCtx:
    renderer: WorldRenderer
    proj: SecondaryProjectile
    proj_type: int
    screen_pos: Vec2
    angle: float
    scale: float
    alpha: float


__all__ = ["ProjectileDrawCtx", "SecondaryProjectileDrawCtx"]
