from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

import grim.terrain_render as terrain_render
from crimson.render.world import WorldRenderer
from crimson.render.world import context as world_context
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from tests.helpers import assert_float_close

if TYPE_CHECKING:
    from grim.raylib_api import rl


class _TextureLike(Protocol):
    id: int
    width: int
    height: int


class _RenderTextureLike(Protocol):
    id: int
    texture: _TextureLike


class _ConfigLike(Protocol):
    screen_width: int
    screen_height: int


class _WorldLike(Protocol):
    world_size: float
    config: _ConfigLike | None


@dataclass(slots=True)
class _TextureStub(_TextureLike):
    id: int = 1
    width: int = 16
    height: int = 16


@dataclass(slots=True)
class _RenderTextureStub(_RenderTextureLike):
    id: int = 1
    texture: _TextureStub = field(default_factory=lambda: _TextureStub(id=2, width=1024, height=1024))


@dataclass(slots=True)
class _WorldConfigStub(_ConfigLike):
    screen_width: int
    screen_height: int


@dataclass(slots=True)
class _WorldStub(_WorldLike):
    world_size: float = 1024.0
    config: _WorldConfigStub | None = None


def _as_texture(texture: _TextureLike) -> rl.Texture:
    return cast("rl.Texture", texture)


def _as_render_texture(render_target: _RenderTextureLike) -> rl.RenderTexture:
    return cast("rl.RenderTexture", render_target)


def _as_world(world: _WorldLike) -> object:
    return cast("object", world)


def test_ground_clamp_is_stable_when_screen_matches_world_width() -> None:
    texture = _TextureStub()
    ground = GroundRenderer(texture=_as_texture(texture), width=1024, height=1024)
    clamped = ground._clamp_camera(Vec2(-0.25, -5.0), 1024.0, 768.0)
    assert clamped.x == 0.0


def test_world_clamp_is_stable_when_screen_matches_world_width() -> None:
    world = _WorldStub(world_size=1024.0)
    renderer = WorldRenderer(_as_world(world))
    clamped = renderer._clamp_camera(Vec2(-0.25, -5.0), Vec2(1024.0, 768.0))
    assert clamped.x == 0.0


def test_world_camera_screen_size_fits_widescreen_uniformly() -> None:
    world = _WorldStub(
        world_size=1024.0,
        config=_WorldConfigStub(screen_width=1280, screen_height=720),
    )
    renderer = WorldRenderer(_as_world(world))
    size = renderer._camera_screen_size()
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_world_camera_screen_size_prefers_runtime_dimensions_over_stale_config(mocker) -> None:
    world = _WorldStub(
        world_size=1024.0,
        config=_WorldConfigStub(screen_width=1024, screen_height=768),
    )
    renderer = WorldRenderer(_as_world(world))
    mocker.patch.object(world_context.rl, "get_screen_width", return_value=1280)
    mocker.patch.object(world_context.rl, "get_screen_height", return_value=720)
    size = renderer._camera_screen_size()
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_world_camera_screen_size_uses_frame_snapshot_when_provided(mocker) -> None:
    world = _WorldStub(
        world_size=1024.0,
        config=_WorldConfigStub(screen_width=1024, screen_height=768),
    )
    renderer = WorldRenderer(_as_world(world))
    mocker.patch.object(world_context.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(world_context.rl, "get_screen_height", return_value=768)
    size = renderer._camera_screen_size(runtime_w=1280.0, runtime_h=720.0)
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_ground_draw_uses_explicit_output_dimensions(mocker) -> None:
    texture = _TextureStub()
    ground = GroundRenderer(texture=_as_texture(texture), width=1024, height=1024)
    ground.render_target = _as_render_texture(_RenderTextureStub())
    ground._render_target_ready = True

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    mocker.patch.object(terrain_render.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(terrain_render.rl, "get_screen_height", return_value=768)
    mocker.patch.object(terrain_render, "_blend_custom", side_effect=_noop_blend)
    draw_texture_pro = mocker.patch.object(
        terrain_render.rl,
        "draw_texture_pro",
        autospec=True,
    )

    ground.draw(
        Vec2(-1.0, -1.0),
        screen_w=1024.0,
        screen_h=576.0,
        out_w=1280.0,
        out_h=720.0,
    )

    calls = [(float(call.args[2].width), float(call.args[2].height)) for call in draw_texture_pro.call_args_list]
    assert calls == [(1280.0, 720.0)]


def test_ground_draw_prefers_runtime_dimensions_over_stale_cached_size(mocker) -> None:
    texture = _TextureStub()
    ground = GroundRenderer(
        texture=_as_texture(texture),
        width=1024,
        height=1024,
        screen_width=1024.0,
        screen_height=768.0,
    )
    ground.render_target = _as_render_texture(_RenderTextureStub())
    ground._render_target_ready = True

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    mocker.patch.object(terrain_render.rl, "get_screen_width", return_value=1280)
    mocker.patch.object(terrain_render.rl, "get_screen_height", return_value=720)
    mocker.patch.object(terrain_render, "_blend_custom", side_effect=_noop_blend)
    mocker.patch.object(terrain_render.rl, "draw_texture_pro", side_effect=lambda *_args, **_kwargs: None)
    fit_view_window = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_fit_view_window",
        autospec=True,
        return_value=(1024.0, 576.0),
    )

    ground.draw(Vec2(-1.0, -1.0))

    fit_inputs = [(float(call.args[1]), float(call.args[2])) for call in fit_view_window.call_args_list]
    assert fit_inputs == [(1280.0, 720.0)]
