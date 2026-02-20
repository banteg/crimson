from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from crimson.projectiles import SecondaryProjectile
from crimson.render.projectile_draw import SecondaryProjectileDrawCtx, draw_secondary_projectile_from_registry
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.render.projectile_draw import ProjectileRendererLike


class _TextureLike(Protocol):
    id: int
    width: int
    height: int


class _RendererLike(Protocol):
    projs_texture: _TextureLike | None
    particles_texture: _TextureLike | None
    config: object | None


def _as_renderer(renderer: _RendererLike) -> ProjectileRendererLike:
    return cast("ProjectileRendererLike", renderer)


@dataclass(slots=True)
class _TextureStub:
    width: int = 256
    height: int = 256
    id: int = 1


@dataclass(slots=True)
class _RendererStub:
    projs_texture: _TextureLike | None = None
    particles_texture: _TextureLike | None = None
    config: object | None = None


def test_secondary_draw_registry_returns_false_when_not_handled() -> None:
    renderer = _RendererStub()
    proj = SecondaryProjectile(type_id=1, pos=Vec2(), angle=0.0)
    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=1,
        screen_pos=Vec2(),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is False


def test_secondary_draw_registry_returns_true_for_rocket_like_when_texture_invalid() -> None:
    renderer = _RendererStub()
    renderer.projs_texture = _TextureStub(width=0, height=128)
    proj = SecondaryProjectile(type_id=1, pos=Vec2(), angle=0.0)
    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=1,
        screen_pos=Vec2(),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True


def test_secondary_draw_registry_renders_type4_fallback_circle(monkeypatch, mocker) -> None:
    renderer = _RendererStub()
    proj = SecondaryProjectile(type_id=4, pos=Vec2(), angle=0.0)
    calls: list[tuple[int, int, float]] = []

    def _draw_circle(x: int, y: int, radius: float, _color) -> None:
        calls.append((int(x), int(y), float(radius)))

    mocker.patch("crimson.render.projectile_draw.secondary_rocket.rl.draw_circle", side_effect=_draw_circle)

    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=4,
        screen_pos=Vec2(10.0, 20.0),
        angle=0.0,
        scale=2.0,
        alpha=0.5,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True
    assert calls == [(10, 20, 24.0)]


def test_secondary_draw_registry_renders_detonation_lines_when_no_particles(monkeypatch, mocker) -> None:
    renderer = _RendererStub()
    proj = SecondaryProjectile(
        type_id=3,
        pos=Vec2(),
        angle=0.0,
        detonation_t=0.25,
        detonation_scale=1.0,
    )
    calls: list[float] = []

    def _draw_circle_lines(_x: int, _y: int, radius: float, _color) -> None:
        calls.append(float(radius))

    mocker.patch("crimson.render.projectile_draw.secondary_detonation.rl.draw_circle_lines", side_effect=_draw_circle_lines)

    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=3,
        screen_pos=Vec2(10.0, 20.0),
        angle=0.0,
        scale=2.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True
    # radius = det_scale * t * 80.0, then scaled.
    assert calls == [40.0]
