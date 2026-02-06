from __future__ import annotations

from types import SimpleNamespace

from grim.geom import Vec2
from crimson.render.secondary_projectile_draw_registry import SecondaryProjectileDrawCtx, draw_secondary_projectile_from_registry


class _TextureStub:
    def __init__(self, width: int = 256, height: int = 256) -> None:
        self.width = int(width)
        self.height = int(height)
        self.id = 1


class _RendererStub:
    projs_texture = None
    particles_texture = None
    config = None


def test_secondary_draw_registry_returns_false_when_not_handled() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(type_id=1, pos=Vec2(0.0, 0.0), angle=0.0)
    ctx = SecondaryProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_type=1,
        screen_pos=Vec2(0.0, 0.0),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is False


def test_secondary_draw_registry_returns_true_for_rocket_like_when_texture_invalid() -> None:
    renderer = _RendererStub()
    renderer.projs_texture = _TextureStub(width=0, height=128)
    proj = SimpleNamespace(type_id=1, pos=Vec2(0.0, 0.0), angle=0.0)
    ctx = SecondaryProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_type=1,
        screen_pos=Vec2(0.0, 0.0),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True


def test_secondary_draw_registry_renders_type4_fallback_circle(monkeypatch) -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(type_id=4, pos=Vec2(0.0, 0.0), angle=0.0)
    calls: list[tuple[int, int, float]] = []

    def _draw_circle(x: int, y: int, radius: float, _color) -> None:  # noqa: ANN001
        calls.append((int(x), int(y), float(radius)))

    monkeypatch.setattr("crimson.render.secondary_projectile_draw_registry.rl.draw_circle", _draw_circle)

    ctx = SecondaryProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_type=4,
        screen_pos=Vec2(10.0, 20.0),
        angle=0.0,
        scale=2.0,
        alpha=0.5,
    )
    assert draw_secondary_projectile_from_registry(ctx) is True
    assert calls == [(10, 20, 24.0)]


def test_secondary_draw_registry_renders_detonation_lines_when_no_particles(monkeypatch) -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(type_id=3, pos=Vec2(0.0, 0.0), angle=0.0, detonation_t=0.25, detonation_scale=1.0)
    calls: list[float] = []

    def _draw_circle_lines(_x: int, _y: int, radius: float, _color) -> None:  # noqa: ANN001
        calls.append(float(radius))

    monkeypatch.setattr("crimson.render.secondary_projectile_draw_registry.rl.draw_circle_lines", _draw_circle_lines)

    ctx = SecondaryProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
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
