from __future__ import annotations

from types import SimpleNamespace

import grim.terrain_render as terrain_render
import pytest
from grim.terrain_render import GroundRenderer

pytestmark = pytest.mark.terrain


def _renderer() -> GroundRenderer:
    texture = SimpleNamespace(id=1, width=16, height=16)
    return GroundRenderer(
        texture=texture,
        width=1024,
        height=1024,
        texture_scale=1.0,
        screen_width=1024.0,
        screen_height=768.0,
    )


def test_render_target_size_stays_native_without_hidpi(monkeypatch) -> None:
    monkeypatch.setattr(terrain_render.rl, "get_screen_width", lambda: 1024)
    monkeypatch.setattr(terrain_render.rl, "get_screen_height", lambda: 768)
    monkeypatch.setattr(terrain_render.rl, "get_render_width", lambda: 1024)
    monkeypatch.setattr(terrain_render.rl, "get_render_height", lambda: 768)
    assert _renderer()._render_target_size_for(1.0) == (1024, 1024)


def test_render_target_size_doubles_with_double_render_resolution(monkeypatch) -> None:
    monkeypatch.setattr(terrain_render.rl, "get_screen_width", lambda: 1024)
    monkeypatch.setattr(terrain_render.rl, "get_screen_height", lambda: 768)
    monkeypatch.setattr(terrain_render.rl, "get_render_width", lambda: 2048)
    monkeypatch.setattr(terrain_render.rl, "get_render_height", lambda: 1536)
    assert _renderer()._render_target_size_for(1.0) == (2048, 2048)


def test_effective_texture_scale_halves_with_double_render_resolution(monkeypatch) -> None:
    monkeypatch.setattr(terrain_render.rl, "get_screen_width", lambda: 1024)
    monkeypatch.setattr(terrain_render.rl, "get_screen_height", lambda: 768)
    monkeypatch.setattr(terrain_render.rl, "get_render_width", lambda: 2048)
    monkeypatch.setattr(terrain_render.rl, "get_render_height", lambda: 1536)
    assert _renderer()._normalized_texture_scale() == 0.5
