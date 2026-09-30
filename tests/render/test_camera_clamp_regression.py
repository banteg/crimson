from __future__ import annotations

from pathlib import Path

import pytest

from crimson.render.world import viewport
from grim import canvas
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.helpers import assert_float_close
from tests.support.world_runtime import WorldRuntimeHost


def _config(width: int, height: int) -> CrimsonConfig:
    config = default_crimson_cfg()
    config.display.width = width
    config.display.height = height
    return config


def test_ground_clamp_is_stable_when_screen_matches_world_width() -> None:
    texture = rl.Texture()
    ground = GroundRenderer(texture=texture, overlay=texture, overlay_detail=texture)
    clamped = ground._clamp_camera(Vec2(-0.25, -5.0), 1024.0, 768.0)
    assert clamped.x == 0.0


def test_world_clamp_is_stable_when_screen_matches_world_width() -> None:
    clamped = viewport.clamp_camera(camera=Vec2(-0.25, -5.0), screen_size=Vec2(1024.0, 768.0))
    assert clamped.x == 0.0


def test_world_camera_screen_size_fits_widescreen_uniformly() -> None:
    size = viewport.camera_screen_size(config=_config(1280, 720), runtime_w=0.0, runtime_h=0.0)
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_world_camera_screen_size_prefers_runtime_dimensions_over_stale_config(assets_dir: Path, mocker) -> None:
    world = WorldRuntimeHost(assets_dir=assets_dir, config=_config(1024, 768))
    mocker.patch.object(canvas, "width", return_value=1280)
    mocker.patch.object(canvas, "height", return_value=720)
    size = world.view_transform().screen_size
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_world_camera_screen_size_uses_frame_snapshot_when_provided() -> None:
    size = viewport.camera_screen_size(config=_config(1024, 768), runtime_w=1280.0, runtime_h=720.0)
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_runtime_update_camera_uses_viewport_math_without_renderer_helpers(assets_dir: Path, mocker) -> None:
    runtime = WorldRuntimeHost(assets_dir=assets_dir, config=_config(1024, 768))
    player = runtime.world.players[0]
    player.health = 100.0
    player.pos = Vec2(512.0, 512.0)
    mocker.patch.object(canvas, "width", return_value=1280)
    mocker.patch.object(canvas, "height", return_value=720)

    runtime.update_camera()

    assert_float_close(runtime.camera.x, 0.0)
    assert_float_close(runtime.camera.y, -224.0)


def test_view_transform_is_stable_and_runtime_conversion_uses_current_camera(assets_dir: Path, mocker) -> None:
    world = WorldRuntimeHost(assets_dir=assets_dir)
    world.camera = Vec2(-32.0, -48.0)
    width = mocker.patch.object(canvas, "width", return_value=1280)
    height = mocker.patch.object(canvas, "height", return_value=720)
    view = world.view_transform()
    assert view.screen_size == Vec2(1024, 576)
    assert view.camera == Vec2(0, -48)
    assert view.view_scale == Vec2(1.25, 1.25)
    screen = world.world_to_screen(Vec2(100, 200))
    assert screen == Vec2(125, 190)
    assert world.screen_to_world(screen) == Vec2(100, 200)

    # A prepared draw retains its transform; input conversion sees resize and
    # camera changes immediately, without a renderer synchronization call.
    width.return_value = 800
    height.return_value = 600
    world.camera = Vec2(-100, -80)
    assert view.world_to_screen(Vec2(100, 200)) == screen
    assert world.world_to_screen(Vec2(100, 200)) == Vec2(0, 120)
    assert world.screen_to_world(Vec2(0, 120)) == Vec2(100, 200)


def test_runtime_build_render_frame_requires_bound_resources(assets_dir: Path) -> None:
    world = WorldRuntimeHost(assets_dir=assets_dir)

    with pytest.raises(AssertionError, match="runtime resources must be loaded before use"):
        world.build_render_frame()
