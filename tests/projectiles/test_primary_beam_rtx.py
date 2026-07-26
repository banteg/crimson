from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest

from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.projectile_draw import primary_beam
from crimson.render.projectile_draw.types import ProjectileDrawCtx
from crimson.render.rtx.mode import RtxRenderMode
from grim.assets import TextureId
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.render.world.context import WorldRenderCtx
    from grim.raylib_api import rl


@dataclass(slots=True)
class _TextureStub:
    id: int = 1
    width: int = 256
    height: int = 256


@dataclass(slots=True)
class _CreaturesStub:
    entries: list[object] = field(default_factory=list)


@dataclass(slots=True)
class _CreatureStub:
    active: bool
    lifecycle_stage: float
    pos: Vec2
    size: float


@dataclass(slots=True)
class _ResourcesStub:
    particles: _TextureStub | None = None

    def texture(self, texture_id: TextureId) -> _TextureStub | None:
        if texture_id == TextureId.PARTICLES:
            return self.particles
        return None


@dataclass(slots=True)
class _FrameStub:
    rtx_mode: RtxRenderMode
    players: list[object] = field(default_factory=list)
    resources: _ResourcesStub = field(default_factory=_ResourcesStub)
    creatures: _CreaturesStub = field(default_factory=_CreaturesStub)
    elapsed_ms: float = 0.0
    config: object | None = None


@dataclass(slots=True)
class _RendererStub:
    frame: _FrameStub
    atlas_calls: int = 0

    @staticmethod
    def world_to_screen(pos: Vec2) -> Vec2:
        return pos

    def _draw_atlas_sprite(self, *_args, **_kwargs) -> None:
        self.atlas_calls += 1


def _as_renderer(renderer: _RendererStub) -> WorldRenderCtx:
    return cast("WorldRenderCtx", renderer)


def _as_texture(texture: _TextureStub) -> rl.Texture:
    return cast("rl.Texture", texture)


def _beam_ctx(renderer: _RendererStub, *, life: float = 1.0) -> ProjectileDrawCtx:
    pos = Vec2(32.0, 0.0)
    proj = Projectile(
        type_id=ProjectileTemplateId.FIRE_BULLETS,
        pos=pos,
        origin=Vec2(0.0, 0.0),
        life_timer=float(life),
        angle=0.0,
    )
    return ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTemplateId.FIRE_BULLETS),
        pos=pos,
        screen_pos=pos,
        life=float(life),
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )


def test_rtx_beam_path_uses_virtual_head_when_available(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    body_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_body", return_value=True)
    head_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_head", return_value=True)

    renderer = _RendererStub(frame=_FrameStub(rtx_mode=RtxRenderMode.RTX))
    ctx = _beam_ctx(renderer, life=1.0)

    assert primary_beam.draw_beam_effect(ctx) is True
    body_mock.assert_called_once()
    head_mock.assert_called_once()
    assert bool(head_mock.call_args.kwargs["is_fire"]) is True
    assert renderer.atlas_calls == 0


def test_rtx_beam_path_raises_when_virtual_head_unavailable(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam, "draw_beam_fast_stamped_body", return_value=True)
    head_mock = mocker.patch.object(
        primary_beam,
        "draw_beam_fast_stamped_head",
        side_effect=RuntimeError("rtx head shader unavailable"),
    )

    renderer = _RendererStub(frame=_FrameStub(rtx_mode=RtxRenderMode.RTX))
    ctx = _beam_ctx(renderer, life=1.0)

    with pytest.raises(RuntimeError, match="rtx head shader unavailable"):
        primary_beam.draw_beam_effect(ctx)
    head_mock.assert_called_once()
    assert renderer.atlas_calls == 0


def test_rtx_beam_path_raises_when_virtual_body_unavailable(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    body_mock = mocker.patch.object(
        primary_beam,
        "draw_beam_fast_stamped_body",
        side_effect=RuntimeError("rtx body shader unavailable"),
    )
    head_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_head", return_value=True)

    renderer = _RendererStub(frame=_FrameStub(rtx_mode=RtxRenderMode.RTX))
    ctx = _beam_ctx(renderer, life=1.0)

    with pytest.raises(RuntimeError, match="rtx body shader unavailable"):
        primary_beam.draw_beam_effect(ctx)
    body_mock.assert_called_once()
    head_mock.assert_not_called()
    assert renderer.atlas_calls == 0


def test_classic_beam_path_does_not_call_rtx_virtual_helpers(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    body_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_body", return_value=True)
    head_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_head", return_value=True)

    renderer = _RendererStub(frame=_FrameStub(rtx_mode=RtxRenderMode.CLASSIC))
    ctx = _beam_ctx(renderer, life=1.0)

    assert primary_beam.draw_beam_effect(ctx) is True
    body_mock.assert_not_called()
    head_mock.assert_not_called()
    assert renderer.atlas_calls > 0


def test_classic_ion_chain_strip_width_scales_with_effect_scale(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "rl_set_texture", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "rl_begin", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "rl_end", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "rl_color4ub", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "rl_tex_coord2f", side_effect=lambda *_a, **_k: None)

    vertex_mock = mocker.patch.object(primary_beam.rl, "rl_vertex2f")

    renderer = _RendererStub(
        frame=_FrameStub(
            rtx_mode=RtxRenderMode.CLASSIC,
            creatures=_CreaturesStub(
                entries=[
                    _CreatureStub(active=False, lifecycle_stage=0.0, pos=Vec2(), size=0.0),
                    _CreatureStub(active=True, lifecycle_stage=16.0, pos=Vec2(0.0, 90.0), size=35.0),
                ],
            ),
        ),
    )
    pos = Vec2(0.0, 0.0)
    proj = Projectile(
        type_id=ProjectileTemplateId.ION_RIFLE,
        pos=pos,
        origin=Vec2(64.0, 0.0),
        life_timer=0.2,
        angle=0.0,
    )
    ctx = ProjectileDrawCtx(
        renderer=_as_renderer(renderer),
        proj=proj,
        proj_index=0,
        texture=_as_texture(_TextureStub()),
        type_id=int(ProjectileTemplateId.ION_RIFLE),
        pos=pos,
        screen_pos=pos,
        life=0.2,
        angle=0.0,
        scale=1.0,
        alpha=1.0,
    )

    assert primary_beam.draw_beam_effect(ctx) is True
    vertices = [(float(call.args[0]), float(call.args[1])) for call in vertex_mock.call_args_list]
    assert len(vertices) == 8

    outer_half = abs(vertices[0][0] - vertices[1][0]) * 0.5
    inner_half = abs(vertices[4][0] - vertices[5][0]) * 0.5
    assert outer_half == pytest.approx(14.0 * 2.2, rel=1e-6, abs=1e-6)
    assert inner_half == pytest.approx(10.0 * 2.2, rel=1e-6, abs=1e-6)
