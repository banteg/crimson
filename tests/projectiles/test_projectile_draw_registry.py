from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, cast

import crimson.render.projectile_draw.primary_plasma as primary_plasma_mod
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.projectile_draw import ProjectileDrawCtx, draw_projectile_from_registry
from crimson.render.rtx.mode import RtxRenderMode
from grim.assets import TextureId
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.render.world.context import WorldRenderCtx
    from grim.raylib_api import rl


class _TextureLike(Protocol):
    id: int
    width: int
    height: int


def _as_renderer(renderer: Any) -> WorldRenderCtx:
    return cast("WorldRenderCtx", renderer)


def _as_texture(texture: _TextureLike) -> rl.Texture:
    return cast("rl.Texture", texture)


def _projectile(
    *,
    type_id: ProjectileTemplateId | int,
    pos: Vec2 | None = None,
    origin: Vec2 | None = None,
    life_timer: float = 1.0,
    angle: float = 0.0,
    speed_scale: float = 1.0,
    travel_budget: float = 0.0,
) -> Projectile:
    return Projectile(
        type_id=cast("ProjectileTemplateId", int(type_id)),
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
class _ResourcesStub:
    bullet_trail: _TextureLike | None = None
    bullet: _TextureLike | None = None
    particles: _TextureLike | None = None
    projs: _TextureLike | None = None

    def texture(self, texture_id: TextureId) -> _TextureLike | None:
        match texture_id:
            case TextureId.BULLET_TRAIL:
                return self.bullet_trail
            case TextureId.BULLET_I:
                return self.bullet
            case TextureId.PARTICLES:
                return self.particles
            case TextureId.PROJS:
                return self.projs
            case _:
                return None


@dataclass(slots=True)
class _RendererStub:
    frame: object

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= int(type_id) < 8 or int(type_id) == int(ProjectileTemplateId.SPLITTER_GUN)


@dataclass(slots=True)
class _FrameStub:
    resources: _ResourcesStub = field(default_factory=_ResourcesStub)
    config: object | None = None
    players: list[object] = field(default_factory=list)
    rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC
    creatures: object = field(default_factory=lambda: type("_Creatures", (), {"entries": []})())
    elapsed_ms: float = 0.0


def _renderer(
    *,
    resources: _ResourcesStub | None = None,
    config: object | None = None,
    players: list[object] | None = None,
    rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC,
    creatures: object | None = None,
    elapsed_ms: float = 0.0,
) -> _RendererStub:
    return _RendererStub(
        frame=_FrameStub(
            resources=_ResourcesStub() if resources is None else resources,
            config=config,
            players=[] if players is None else players,
            rtx_mode=rtx_mode,
            creatures=type("_Creatures", (), {"entries": []})() if creatures is None else creatures,
            elapsed_ms=elapsed_ms,
        ),
    )


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
    renderer = _renderer()
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
    renderer = _renderer()
    proj = _projectile(type_id=int(ProjectileTemplateId.PLASMA_RIFLE))
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=int(ProjectileTemplateId.PLASMA_RIFLE),
        pos=Vec2(),
        screen_pos=Vec2(),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_renders_native_bullet_core_for_shrinkifier(mocker) -> None:
    calls: list[tuple[int, float, float]] = []

    def _draw_texture_pro(texture, _src, dst, _origin, rotation, _tint) -> None:
        calls.append((int(texture.id), float(dst.width), float(rotation)))

    mocker.patch.object(primary_plasma_mod.rl, "begin_blend_mode")
    mocker.patch.object(primary_plasma_mod.rl, "end_blend_mode")
    mocker.patch.object(primary_plasma_mod.rl, "draw_texture_pro", side_effect=_draw_texture_pro)

    resources = _ResourcesStub(
        particles=_TextureStub(id=1),
        bullet=_TextureStub(id=2),
    )
    renderer = _BeamRendererStub(frame=_FrameStub(resources=resources))
    angle = 0.5
    proj = _projectile(
        type_id=ProjectileTemplateId.SHRINKIFIER,
        pos=Vec2(10.0, 0.0),
        origin=Vec2(),
        life_timer=0.4,
        angle=angle,
        speed_scale=1.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=None,
        type_id=int(ProjectileTemplateId.SHRINKIFIER),
        pos=proj.pos,
        screen_pos=proj.pos,
        life=0.4,
        angle=angle,
        scale=1.0,
        alpha=1.0,
    )

    assert draw_projectile_from_registry(ctx) is True
    texture_id, width, rotation = calls[-1]
    assert texture_id == 2
    assert width == 4.0
    assert math.isclose(rotation, angle * 180.0 / math.pi, abs_tol=1e-9)


def test_draw_registry_returns_true_for_beam_types_even_when_dist_is_zero() -> None:
    renderer = _renderer()
    proj = _projectile(
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
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
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True


def test_draw_registry_returns_false_for_beam_types_without_texture() -> None:
    renderer = _renderer()
    proj = _projectile(
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
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
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is False


def test_draw_registry_returns_true_for_pulse_gun_branch() -> None:
    renderer = _renderer()
    proj = _projectile(
        type_id=int(ProjectileTemplateId.PULSE_GUN),
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
        type_id=int(ProjectileTemplateId.PULSE_GUN),
        pos=Vec2(10.0, 20.0),
        screen_pos=Vec2(10.0, 20.0),
        life=1.0,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )
    assert draw_projectile_from_registry(ctx) is True


def test_draw_registry_returns_true_for_plague_spreader_branch() -> None:
    renderer = _renderer()
    proj = _projectile(
        type_id=int(ProjectileTemplateId.PLAGUE_SPREADER),
        pos=Vec2(10.0, 20.0),
        life_timer=0.0,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTemplateId.PLAGUE_SPREADER),
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

    renderer = _BeamRendererStub(frame=_FrameStub())
    angle = 0.8
    proj = _projectile(
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
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
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
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
