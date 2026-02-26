from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

from crimson.projectiles import Projectile, ProjectileTypeId
from crimson.render.projectile_draw import ProjectileDrawCtx, draw_projectile_from_registry
from crimson.render.rtx.mode import RtxRenderMode
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
    rtx_mode: RtxRenderMode

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
    travel_budget: float = 0.0,
) -> Projectile:
    return Projectile(
        type_id=int(type_id),
        pos=Vec2() if pos is None else pos,
        origin=Vec2() if origin is None else origin,
        life_timer=float(life_timer),
        angle=float(angle),
        speed_scale=float(speed_scale),
        travel_budget=float(travel_budget),
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
    rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= int(type_id) < 8 or int(type_id) == int(ProjectileTypeId.SPLITTER_GUN)


@dataclass(slots=True)
class _AtlasCall:
    rotation_rad: float


@dataclass(slots=True)
class _BeamRendererStub(_RendererStub):
    atlas_calls: list[_AtlasCall] = field(default_factory=list)

    @staticmethod
    def world_to_screen(pos: Vec2) -> Vec2:
        return pos

    def _draw_atlas_sprite(
        self,
        texture: _TextureLike,
        *,
        grid: int,
        frame: int,
        pos: Vec2,
        scale: float,
        rotation_rad: float = 0.0,
        tint: object | None = None,
    ) -> None:
        del texture, grid, frame, pos, scale, tint
        self.atlas_calls.append(_AtlasCall(rotation_rad=float(rotation_rad)))


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


def test_draw_registry_fire_bullets_streak_unrotated_head_rotated(mocker) -> None:
    import crimson.render.projectile_draw.primary_beam as primary_beam_mod

    mocker.patch.object(primary_beam_mod.rl, "begin_blend_mode")
    mocker.patch.object(primary_beam_mod.rl, "end_blend_mode")

    renderer = _BeamRendererStub()
    angle = 0.8
    proj = _projectile(
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=Vec2(300.0, 140.0),
        origin=Vec2(0.0, 140.0),
        life_timer=1.0,
        angle=angle,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
        pos=proj.pos,
        screen_pos=proj.pos,
        life=1.0,
        angle=angle,
        scale=1.0,
        alpha=1.0,
    )

    assert draw_projectile_from_registry(ctx) is True
    assert len(renderer.atlas_calls) > 1
    streak_rotations = [entry.rotation_rad for entry in renderer.atlas_calls[:-1]]
    head_rotation = renderer.atlas_calls[-1].rotation_rad
    assert all(math.isclose(rotation, 0.0, abs_tol=1e-9) for rotation in streak_rotations)
    assert math.isclose(head_rotation, angle, abs_tol=1e-9)
