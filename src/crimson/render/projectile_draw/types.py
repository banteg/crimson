from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import pyray as rl

from grim.geom import Vec2

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ...sim.state_types import PlayerState


class ProjectileLike(Protocol):
    origin: Vec2
    speed_scale: float
    base_damage: float


class SecondaryProjectileLike(Protocol):
    detonation_t: float
    detonation_scale: float


class _CreatureLike(Protocol):
    active: bool
    hitbox_size: float
    size: float
    pos: Vec2


class _CreaturePoolLike(Protocol):
    entries: Sequence[_CreatureLike]


class _FxDetailConfigLike(Protocol):
    def fx_detail(self, *, level: int, default: bool) -> bool: ...


class ProjectileRendererLike(Protocol):
    bullet_trail_texture: rl.Texture | None
    bullet_texture: rl.Texture | None
    particles_texture: rl.Texture | None
    projs_texture: rl.Texture | None
    config: _FxDetailConfigLike | None
    players: Sequence[PlayerState]
    creatures: _CreaturePoolLike
    elapsed_ms: float

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
