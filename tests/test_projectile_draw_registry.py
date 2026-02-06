from __future__ import annotations

from types import SimpleNamespace

from grim.geom import Vec2
from crimson.projectiles import ProjectileTypeId
from crimson.render.projectile_draw_registry import ProjectileDrawCtx, draw_projectile_from_registry


class _TextureStub:
    def __init__(self, width: int = 256, height: int = 256) -> None:
        self.width = int(width)
        self.height = int(height)
        self.id = 1


class _RendererStub:
    bullet_trail_texture = None
    bullet_texture = None
    particles_texture = None
    config = None
    players: list[object] = []

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= int(type_id) < 8 or int(type_id) == int(ProjectileTypeId.SPLITTER_GUN)


def test_draw_registry_returns_false_for_bullet_when_nothing_drawn() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(type_id=0, pos=Vec2(0.0, 0.0), life_timer=1.0, angle=0.0)
    ctx = ProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=0,
        pos=Vec2(0.0, 0.0),
        sx=0.0,
        sy=0.0,
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_false_for_plasma_without_particles_texture() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(type_id=int(ProjectileTypeId.PLASMA_RIFLE), pos=Vec2(0.0, 0.0), life_timer=1.0, angle=0.0)
    ctx = ProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=int(ProjectileTypeId.PLASMA_RIFLE),
        pos=Vec2(0.0, 0.0),
        sx=0.0,
        sy=0.0,
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_true_for_beam_types_even_when_dist_is_zero() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        origin_x=10.0,
        origin_y=20.0,
        life_timer=1.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_index=0,
        texture=_TextureStub(),
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        sx=10.0,
        sy=20.0,
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True


def test_draw_registry_returns_false_for_beam_types_without_texture() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        origin_x=10.0,
        origin_y=20.0,
        life_timer=1.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        sx=10.0,
        sy=20.0,
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_true_for_pulse_gun_branch() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(
        type_id=int(ProjectileTypeId.PULSE_GUN),
        pos=Vec2(10.0, 20.0),
        origin_x=10.0,
        origin_y=20.0,
        life_timer=1.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_index=0,
        texture=_TextureStub(),
        type_id=int(ProjectileTypeId.PULSE_GUN),
        pos=Vec2(10.0, 20.0),
        sx=10.0,
        sy=20.0,
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True


def test_draw_registry_returns_true_for_plague_spreader_branch() -> None:
    renderer = _RendererStub()
    proj = SimpleNamespace(
        type_id=int(ProjectileTypeId.PLAGUE_SPREADER),
        pos=Vec2(10.0, 20.0),
        life_timer=0.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=renderer,  # type: ignore[arg-type]
        proj=proj,
        proj_index=0,
        texture=_TextureStub(),
        type_id=int(ProjectileTypeId.PLAGUE_SPREADER),
        pos=Vec2(10.0, 20.0),
        sx=10.0,
        sy=20.0,
        life=0.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True
