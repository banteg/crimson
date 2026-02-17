from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import pyray as rl

from grim.geom import Vec2

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ...sim.state_types import PlayerState


class ProjectileLike(Protocol):
    @property
    def origin(self) -> Vec2: ...

    @property
    def speed_scale(self) -> float: ...

    @property
    def base_damage(self) -> float: ...


class SecondaryProjectileLike(Protocol):
    @property
    def detonation_t(self) -> float: ...

    @property
    def detonation_scale(self) -> float: ...


class _CreatureLike(Protocol):
    @property
    def active(self) -> bool: ...

    @property
    def hitbox_size(self) -> float: ...

    @property
    def size(self) -> float: ...

    @property
    def pos(self) -> Vec2: ...


class _CreaturePoolLike(Protocol):
    @property
    def entries(self) -> Sequence[_CreatureLike]: ...


class _FxDetailConfigLike(Protocol):
    def fx_detail(self, *, level: int, default: bool) -> bool: ...


class ProjectileRendererLike(Protocol):
    @property
    def bullet_trail_texture(self) -> rl.Texture | None: ...

    @property
    def bullet_texture(self) -> rl.Texture | None: ...

    @property
    def particles_texture(self) -> rl.Texture | None: ...

    @property
    def projs_texture(self) -> rl.Texture | None: ...

    @property
    def config(self) -> _FxDetailConfigLike | None: ...

    @property
    def players(self) -> Sequence[PlayerState]: ...

    @property
    def creatures(self) -> _CreaturePoolLike: ...

    @property
    def elapsed_ms(self) -> float: ...

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


@dataclass(frozen=True, slots=True)
class ProjectileDrawCtx:
    renderer: ProjectileRendererLike
    proj: ProjectileLike
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
    renderer: ProjectileRendererLike
    proj: SecondaryProjectileLike
    proj_type: int
    screen_pos: Vec2
    angle: float
    scale: float
    alpha: float


__all__ = [
    "ProjectileDrawCtx",
    "ProjectileLike",
    "ProjectileRendererLike",
    "SecondaryProjectileDrawCtx",
    "SecondaryProjectileLike",
]
