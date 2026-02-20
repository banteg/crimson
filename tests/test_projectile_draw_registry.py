from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

from crimson.projectiles import Projectile, ProjectileTypeId
from crimson.render.projectile_draw import ProjectileDrawCtx, draw_projectile_from_registry
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.render.projectile_draw import ProjectileRendererLike
    from grim.raylib_api import rl


class _TextureLike(Protocol):
    id: int
    width: int
    height: int


class _RendererLike(Protocol):
    bullet_trail_texture: _TextureLike | None
    bullet_texture: _TextureLike | None
    particles_texture: _TextureLike | None
    config: object | None
    players: list[object]

    def _is_bullet_trail_type(self, type_id: int) -> bool: ...


def _as_renderer(renderer: _RendererLike) -> ProjectileRendererLike:
    return cast("ProjectileRendererLike", renderer)


def _as_texture(texture: _TextureLike) -> rl.Texture:
    return cast("rl.Texture", texture)


def _projectile(
    *,
    type_id: int,
    pos: Vec2 | None = None,
    origin: Vec2 | None = None,
    life_timer: float = 1.0,
    angle: float = 0.0,
    speed_scale: float = 1.0,
    base_damage: float = 0.0,
) -> Projectile:
    return Projectile(
        type_id=int(type_id),
        pos=Vec2() if pos is None else pos,
        origin=Vec2() if origin is None else origin,
        life_timer=float(life_timer),
        angle=float(angle),
        speed_scale=float(speed_scale),
        base_damage=float(base_damage),
    )


@dataclass(slots=True)
class _TextureStub:
    width: int = 256
    height: int = 256
    id: int = 1


@dataclass(slots=True)
class _RendererStub:
    bullet_trail_texture: _TextureLike | None = None
    bullet_texture: _TextureLike | None = None
    particles_texture: _TextureLike | None = None
    config: object | None = None
    players: list[object] = field(default_factory=list)

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= int(type_id) < 8 or int(type_id) == int(ProjectileTypeId.SPLITTER_GUN)


def test_draw_registry_returns_false_for_bullet_when_nothing_drawn() -> None:
    renderer = _RendererStub()
    proj = _projectile(type_id=0)
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=0,
        pos=Vec2(),
        screen_pos=Vec2(),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_false_for_plasma_without_particles_texture() -> None:
    renderer = _RendererStub()
    proj = _projectile(type_id=int(ProjectileTypeId.PLASMA_RIFLE))
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=int(ProjectileTypeId.PLASMA_RIFLE),
        pos=Vec2(),
        screen_pos=Vec2(),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_true_for_beam_types_even_when_dist_is_zero() -> None:
    renderer = _RendererStub()
    proj = _projectile(
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        origin=Vec2(10.0, 20.0),
        life_timer=1.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True


def test_draw_registry_returns_false_for_beam_types_without_texture() -> None:
    renderer = _RendererStub()
    proj = _projectile(
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        origin=Vec2(10.0, 20.0),
        life_timer=1.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_true_for_pulse_gun_branch() -> None:
    renderer = _RendererStub()
    proj = _projectile(
        type_id=int(ProjectileTypeId.PULSE_GUN),
        pos=Vec2(10.0, 20.0),
        origin=Vec2(10.0, 20.0),
        life_timer=1.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTypeId.PULSE_GUN),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True


def test_draw_registry_returns_true_for_plague_spreader_branch() -> None:
    renderer = _RendererStub()
    proj = _projectile(
        type_id=int(ProjectileTypeId.PLAGUE_SPREADER),
        pos=Vec2(10.0, 20.0),
        life_timer=0.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTypeId.PLAGUE_SPREADER),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=0.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True
