from __future__ import annotations

import pytest

from grim import terrain_render
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.helpers import assert_float_close

pytestmark = pytest.mark.terrain


def _renderer() -> GroundRenderer:
    texture = rl.Texture()
    return GroundRenderer(
        texture=texture,
        overlay=texture,
        overlay_detail=texture,
        width=1024,
        height=1024,
        texture_scale=1.0,
    )


@pytest.mark.parametrize(
    ("dpi_scale", "expected_size"),
    [
        (1.0, (1024, 1024)),
        (1.5, (1024, 1024)),
        (2.0, (2048, 2048)),
    ],
    ids=["native-without-hidpi", "fractional-dpi", "double-dpi"],
)
def test_render_target_size_scales_with_window_dpi(
    mocker,
    dpi_scale: float,
    expected_size: tuple[int, int],
) -> None:
    mocker.patch.object(terrain_render.rl, "get_window_scale_dpi", return_value=rl.Vector2(dpi_scale, dpi_scale))
    assert _renderer()._render_target_size_for(1.0) == expected_size


@pytest.mark.parametrize(
    ("target_width", "dpi_scale", "texture_scale", "expected_scale"),
    [
        (1024, 1.0, 1.0, 1.0),
        (2048, 2.0, 1.0, 0.5),
        (1024, 2.0, 1.0, 1.0),
        (2048, 1.0, 1.0, 0.5),
        (1024, 1.0, 2.0, 1.0),
        (1365, 2.0, 1.5, 1024 / 1365),
    ],
)
def test_effective_texture_scale_uses_allocated_target(
    mocker, target_width: int, dpi_scale: float, texture_scale: float, expected_scale: float,
) -> None:
    mocker.patch.object(terrain_render.rl, "get_window_scale_dpi", return_value=rl.Vector2(dpi_scale, dpi_scale))
    ground = _renderer()
    ground.texture_scale = texture_scale
    ground.render_target = rl.RenderTexture()
    ground.render_target.texture.width = target_width
    assert_float_close(ground._normalized_texture_scale(), expected_scale)


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
