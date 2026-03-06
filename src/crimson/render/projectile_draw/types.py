from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from ..rtx.mode import RtxRenderMode

if TYPE_CHECKING:
    from collections.abc import Sequence

    from grim.config import CrimsonConfig

    from ...creatures.runtime import CreaturePool
    from ...projectiles.types import Projectile, SecondaryProjectile
    from ...sim.state_types import PlayerState


class ProjectileRendererLike(Protocol):
    @property
    def assets(self) -> ProjectileRenderAssetsLike: ...

    @property
    def config(self) -> CrimsonConfig | None: ...

    @property
    def players(self) -> Sequence[PlayerState]: ...

    @property
    def creatures(self) -> CreaturePool: ...

    @property
    def elapsed_ms(self) -> float: ...

    @property
    def rtx_mode(self) -> RtxRenderMode: ...

    def _is_bullet_trail_type(self, type_id: int) -> bool: ...

    def world_to_screen(self, pos: Vec2) -> Vec2: ...

    def _draw_bullet_trail(
        self,
        start: Vec2,
        end: Vec2,
        *,
        type_id: int,
        alpha: int,
        scale: float,
        angle: float,
    ) -> bool: ...

    def _bullet_sprite_size(self, type_id: int, *, scale: float) -> float: ...

    def _draw_atlas_sprite(
        self,
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        pos: Vec2,
        scale: float,
        rotation_rad: float = 0.0,
        tint: rl.Color = rl.WHITE,
    ) -> None: ...


class ProjectileRenderAssetsLike(Protocol):
    @property
    def bullet_trail(self) -> rl.Texture | None: ...

    @property
    def bullet(self) -> rl.Texture | None: ...

    @property
    def particles(self) -> rl.Texture | None: ...

    @property
    def projs(self) -> rl.Texture | None: ...


class ProjectileDrawCtx(msgspec.Struct, frozen=True):
    renderer: ProjectileRendererLike
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
    renderer: ProjectileRendererLike
    proj: SecondaryProjectile
    proj_type: int
    screen_pos: Vec2
    angle: float
    scale: float
    alpha: float


__all__ = [
    "ProjectileDrawCtx",
    "ProjectileRenderAssetsLike",
    "ProjectileRendererLike",
    "SecondaryProjectileDrawCtx",
]
