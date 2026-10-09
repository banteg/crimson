from __future__ import annotations

import pytest

from grim import terrain_render
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

pytestmark = pytest.mark.terrain


def _renderer() -> GroundRenderer:
    texture = rl.Texture()
    return GroundRenderer(
        texture=texture,
        overlay=texture,
        overlay_detail=texture,
        width=1024,
        height=1024,
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
