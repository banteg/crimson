from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import crimson.render.projectile_draw.primary_beam as primary_beam
from crimson.projectiles import Projectile, ProjectileTypeId
from crimson.render.projectile_draw.types import ProjectileDrawCtx
from crimson.render.rtx.mode import RtxRenderMode
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.render.projectile_draw import ProjectileRendererLike
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
class _RendererStub:
    rtx_mode: RtxRenderMode
    players: list[object] = field(default_factory=list)
    particles_texture: _TextureStub | None = None
    creatures: _CreaturesStub = field(default_factory=_CreaturesStub)
    atlas_calls: int = 0

    @staticmethod
    def world_to_screen(pos: Vec2) -> Vec2:
        return pos

    def _draw_atlas_sprite(self, *_args, **_kwargs) -> None:
        self.atlas_calls += 1


def _as_renderer(renderer: _RendererStub) -> ProjectileRendererLike:
    return cast("ProjectileRendererLike", renderer)


def _as_texture(texture: _TextureStub) -> rl.Texture:
    return cast("rl.Texture", texture)


def _beam_ctx(renderer: _RendererStub, *, life: float = 1.0) -> ProjectileDrawCtx:
    pos = Vec2(32.0, 0.0)
    proj = Projectile(
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
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
        type_id=int(ProjectileTypeId.FIRE_BULLETS),
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

    renderer = _RendererStub(rtx_mode=RtxRenderMode.RTX)
    ctx = _beam_ctx(renderer, life=1.0)

    assert primary_beam.draw_beam_effect(ctx) is True
    body_mock.assert_called_once()
    head_mock.assert_called_once()
    assert bool(head_mock.call_args.kwargs["is_fire"]) is True
    assert renderer.atlas_calls == 0


def test_rtx_beam_path_falls_back_to_texture_head_when_virtual_head_unavailable(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam, "draw_beam_fast_stamped_body", return_value=True)
    head_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_head", return_value=False)

    renderer = _RendererStub(rtx_mode=RtxRenderMode.RTX)
    ctx = _beam_ctx(renderer, life=1.0)

    assert primary_beam.draw_beam_effect(ctx) is True
    head_mock.assert_called_once()
    assert renderer.atlas_calls == 1


def test_classic_beam_path_does_not_call_rtx_virtual_helpers(mocker) -> None:
    mocker.patch.object(primary_beam.rl, "begin_blend_mode", side_effect=lambda *_a, **_k: None)
    mocker.patch.object(primary_beam.rl, "end_blend_mode", side_effect=lambda *_a, **_k: None)
    body_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_body", return_value=True)
    head_mock = mocker.patch.object(primary_beam, "draw_beam_fast_stamped_head", return_value=True)

    renderer = _RendererStub(rtx_mode=RtxRenderMode.CLASSIC)
    ctx = _beam_ctx(renderer, life=1.0)

    assert primary_beam.draw_beam_effect(ctx) is True
    body_mock.assert_not_called()
    head_mock.assert_not_called()
    assert renderer.atlas_calls > 0
