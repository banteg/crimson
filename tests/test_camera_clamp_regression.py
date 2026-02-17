from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

import grim.terrain_render as terrain_render
from crimson.render.world import WorldRenderer
from crimson.render.world import context as world_context
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


def test_world_camera_screen_size_prefers_runtime_dimensions_over_stale_config(monkeypatch) -> None:
    world = SimpleNamespace(
        world_size=1024.0,
        config=SimpleNamespace(screen_width=1024, screen_height=768),
    )
    renderer = WorldRenderer(world)
    monkeypatch.setattr(world_context.rl, "get_screen_width", lambda: 1280)
    monkeypatch.setattr(world_context.rl, "get_screen_height", lambda: 720)
    size = renderer._camera_screen_size()
    assert size.x == pytest.approx(1024.0)
    assert size.y == pytest.approx(576.0)


def test_world_camera_screen_size_uses_frame_snapshot_when_provided(monkeypatch) -> None:
    world = SimpleNamespace(
        world_size=1024.0,
        config=SimpleNamespace(screen_width=1024, screen_height=768),
    )
    renderer = WorldRenderer(world)
    monkeypatch.setattr(world_context.rl, "get_screen_width", lambda: 1024)
    monkeypatch.setattr(world_context.rl, "get_screen_height", lambda: 768)
    size = renderer._camera_screen_size(runtime_w=1280.0, runtime_h=720.0)
    assert size.x == pytest.approx(1024.0)
    assert size.y == pytest.approx(576.0)


def test_ground_draw_uses_explicit_output_dimensions(monkeypatch) -> None:
    texture = SimpleNamespace(id=1, width=16, height=16)
    ground = GroundRenderer(texture=texture, width=1024, height=1024)
    ground.render_target = SimpleNamespace(
        id=1,
        texture=SimpleNamespace(id=2, width=1024, height=1024),
    )
    ground._render_target_ready = True

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    calls: list[tuple[float, float]] = []
    monkeypatch.setattr(terrain_render.rl, "get_screen_width", lambda: 1024)
    monkeypatch.setattr(terrain_render.rl, "get_screen_height", lambda: 768)
    monkeypatch.setattr(terrain_render, "_blend_custom", _noop_blend)
    monkeypatch.setattr(
        terrain_render.rl,
        "draw_texture_pro",
        lambda _texture, _src, dst, _origin, _rotation, _tint: calls.append((float(dst.width), float(dst.height))),
    )

    ground.draw(
        Vec2(-1.0, -1.0),
        screen_w=1024.0,
        screen_h=576.0,
        out_w=1280.0,
        out_h=720.0,
    )

    assert calls == [(1280.0, 720.0)]


def test_ground_draw_prefers_runtime_dimensions_over_stale_cached_size(monkeypatch) -> None:
    texture = SimpleNamespace(id=1, width=16, height=16)
    ground = GroundRenderer(
        texture=texture,
        width=1024,
        height=1024,
        screen_width=1024.0,
        screen_height=768.0,
    )
    ground.render_target = SimpleNamespace(
        id=1,
        texture=SimpleNamespace(id=2, width=1024, height=1024),
    )
    ground._render_target_ready = True

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    fit_inputs: list[tuple[float, float]] = []

    monkeypatch.setattr(terrain_render.rl, "get_screen_width", lambda: 1280)
    monkeypatch.setattr(terrain_render.rl, "get_screen_height", lambda: 720)
    monkeypatch.setattr(terrain_render, "_blend_custom", _noop_blend)
    monkeypatch.setattr(
        terrain_render.rl,
        "draw_texture_pro",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        terrain_render.GroundRenderer,
        "_fit_view_window",
        lambda _self, screen_w, screen_h: (
            fit_inputs.append((float(screen_w), float(screen_h))) or (1024.0, 576.0)
        ),
    )

    ground.draw(Vec2(-1.0, -1.0))

    assert fit_inputs == [(1280.0, 720.0)]
