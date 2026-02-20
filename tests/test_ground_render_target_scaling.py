from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

import grim.terrain_render as terrain_render
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.helpers import assert_float_close

pytestmark = pytest.mark.terrain


def _renderer() -> GroundRenderer:
    texture = cast("rl.Texture", SimpleNamespace(id=1, width=16, height=16))
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


def test_view_window_fits_widescreen_without_nonuniform_stretch() -> None:
    view_w, view_h = _renderer()._fit_view_window(1280.0, 720.0)
    assert_float_close(view_w, 1024.0)
    assert_float_close(view_h, 576.0)


def test_view_window_keeps_native_size_for_supported_legacy_resolution() -> None:
    view_w, view_h = _renderer()._fit_view_window(1024.0, 768.0)
    assert_float_close(view_w, 1024.0)
    assert_float_close(view_h, 768.0)
