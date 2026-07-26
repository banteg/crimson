from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from grim import terrain_render
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.helpers import assert_float_close

pytestmark = pytest.mark.terrain


def _renderer() -> GroundRenderer:
    texture = cast("rl.Texture", SimpleNamespace(id=1, width=16, height=16))
    return GroundRenderer(
        texture=texture,
        overlay=texture,
        overlay_detail=texture,
        width=1024,
        height=1024,
        texture_scale=1.0,
    )


@pytest.mark.parametrize(
    ("render_width", "render_height", "expected_size"),
    [
        (1024, 768, (1024, 1024)),
        (2048, 1536, (2048, 2048)),
    ],
    ids=["native-without-hidpi", "double-render-resolution"],
)
def test_render_target_size_scales_with_render_resolution(
    mocker,
    render_width: int,
    render_height: int,
    expected_size: tuple[int, int],
) -> None:
    mocker.patch.object(terrain_render.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(terrain_render.rl, "get_screen_height", return_value=768)
    mocker.patch.object(terrain_render.rl, "get_render_width", return_value=render_width)
    mocker.patch.object(terrain_render.rl, "get_render_height", return_value=render_height)
    assert _renderer()._render_target_size_for(1.0) == expected_size


def test_effective_texture_scale_halves_with_double_render_resolution(mocker) -> None:
    mocker.patch.object(terrain_render.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(terrain_render.rl, "get_screen_height", return_value=768)
    mocker.patch.object(terrain_render.rl, "get_render_width", return_value=2048)
    mocker.patch.object(terrain_render.rl, "get_render_height", return_value=1536)
    assert _renderer()._normalized_texture_scale() == 0.5


@pytest.mark.parametrize(
    ("screen_width", "screen_height", "expected_width", "expected_height"),
    [
        (1280.0, 720.0, 1024.0, 576.0),
        (1024.0, 768.0, 1024.0, 768.0),
    ],
    ids=["widescreen-fit", "legacy-native-size"],
)
def test_view_window_fit(
    screen_width: float,
    screen_height: float,
    expected_width: float,
    expected_height: float,
) -> None:
    view_w, view_h = _renderer()._fit_view_window(screen_width, screen_height)
    assert_float_close(view_w, expected_width)
    assert_float_close(view_h, expected_height)
