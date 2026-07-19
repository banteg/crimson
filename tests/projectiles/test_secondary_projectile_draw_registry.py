from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, cast

import crimson.render.projectile_draw.secondary_detonation as secondary_detonation_module
import crimson.render.projectile_draw.secondary_dispatch as secondary_dispatch_module
import crimson.render.projectile_draw.secondary_rocket as secondary_rocket_module
from crimson.projectiles.types import SecondaryProjectile, SecondaryProjectileTypeId
from crimson.render.projectile_draw import SecondaryProjectileDrawCtx, draw_secondary_projectile_from_registry
from grim.assets import TextureId
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.render.world.context import WorldRenderCtx


class _TextureLike(Protocol):
    id: int
    width: int
    height: int


class _ResourcesLike(Protocol):
    def texture(self, texture_id: TextureId) -> _TextureLike | None: ...


class _RendererLike(Protocol):
    frame: object


def _as_renderer(renderer: Any) -> WorldRenderCtx:
    return cast("WorldRenderCtx", renderer)


@dataclass(slots=True)
class _TextureStub:
    width: int = 256
    height: int = 256
    id: int = 1


@dataclass(slots=True)
class _ResourcesStub:
    projs: _TextureLike | None = None
    particles: _TextureLike | None = None

    def texture(self, texture_id: TextureId) -> _TextureLike | None:
        match texture_id:
            case TextureId.PROJS:
                return self.projs
            case TextureId.PARTICLES:
                return self.particles
            case _:
                return None


@dataclass(slots=True)
class _FrameStub:
    resources: _ResourcesStub = field(default_factory=_ResourcesStub)
    config: object | None = None


@dataclass(slots=True)
class _RendererStub:
    frame: _FrameStub = field(default_factory=_FrameStub)


def test_secondary_draw_registry_returns_false_when_not_handled() -> None:
    renderer = _RendererStub()
    proj = SecondaryProjectile(type_id=SecondaryProjectileTypeId.ROCKET, pos=Vec2(), angle=0.0)
    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=SecondaryProjectileTypeId.ROCKET,
        screen_pos=Vec2(),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is False


def test_secondary_draw_registry_returns_true_for_rocket_like_when_texture_invalid() -> None:
    renderer = _RendererStub()
    renderer.frame.resources.projs = _TextureStub(width=0, height=128)
    proj = SecondaryProjectile(type_id=SecondaryProjectileTypeId.ROCKET, pos=Vec2(), angle=0.0)
    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=SecondaryProjectileTypeId.ROCKET,
        screen_pos=Vec2(),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True


def test_secondary_draw_registry_renders_type4_fallback_circle(monkeypatch, mocker) -> None:
    renderer = _RendererStub()
    proj = SecondaryProjectile(type_id=SecondaryProjectileTypeId.ROCKET_MINIGUN, pos=Vec2(), angle=0.0)
    calls: list[tuple[int, int, float]] = []

    def _draw_circle(x: int, y: int, radius: float, _color) -> None:
        calls.append((int(x), int(y), float(radius)))

    mocker.patch.object(secondary_rocket_module.rl, "draw_circle", side_effect=_draw_circle)

    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=SecondaryProjectileTypeId.ROCKET_MINIGUN,
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
        type_id=SecondaryProjectileTypeId.DETONATION,
        pos=Vec2(),
        angle=0.0,
        detonation_t=0.25,
        detonation_scale=1.0,
    )
    calls: list[float] = []

    def _draw_circle_lines(_x: int, _y: int, radius: float, _color) -> None:
        calls.append(float(radius))

    mocker.patch.object(secondary_detonation_module.rl, "draw_circle_lines", side_effect=_draw_circle_lines)

    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=SecondaryProjectileTypeId.DETONATION,
        screen_pos=Vec2(10.0, 20.0),
        angle=0.0,
        scale=2.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True
    # radius = det_scale * t * 80.0, then scaled.
    assert calls == [40.0]


def test_secondary_draw_registry_keeps_shared_bloom_for_detonation(mocker) -> None:
    renderer = _RendererStub()
    proj = SecondaryProjectile(
        type_id=SecondaryProjectileTypeId.DETONATION,
        pos=Vec2(),
        angle=0.0,
        detonation_t=1.0,
        detonation_scale=1.0,
    )
    bloom = mocker.patch.object(secondary_dispatch_module, "draw_secondary_projectile_bloom")
    ctx = SecondaryProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_type=SecondaryProjectileTypeId.DETONATION,
        screen_pos=Vec2(10.0, 20.0),
        angle=0.0,
        scale=1.0,
        alpha=0.75,
    )

    assert draw_secondary_projectile_from_registry(ctx) is True
    bloom.assert_called_once_with(ctx)
