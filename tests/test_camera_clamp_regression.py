from __future__ import annotations

from types import SimpleNamespace

from crimson.render.world import WorldRenderer
import pytest
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer


def test_ground_clamp_is_stable_when_screen_matches_world_width() -> None:
    texture = SimpleNamespace(id=1, width=16, height=16)
    ground = GroundRenderer(texture=texture, width=1024, height=1024)
    clamped = ground._clamp_camera(Vec2(-0.25, -5.0), 1024.0, 768.0)
    assert clamped.x == 0.0


def test_world_clamp_is_stable_when_screen_matches_world_width() -> None:
    world = SimpleNamespace(world_size=1024.0)
    renderer = WorldRenderer(world)
    clamped = renderer._clamp_camera(Vec2(-0.25, -5.0), Vec2(1024.0, 768.0))
    assert clamped.x == 0.0


def test_world_camera_screen_size_fits_widescreen_uniformly() -> None:
    world = SimpleNamespace(
        world_size=1024.0,
        config=SimpleNamespace(screen_width=1280, screen_height=720),
    )
    renderer = WorldRenderer(world)
    size = renderer._camera_screen_size()
    assert size.x == pytest.approx(1024.0)
    assert size.y == pytest.approx(576.0)
