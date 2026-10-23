from __future__ import annotations

import struct

import pytest

from grim.edr import load_float_render_texture
from grim.raylib_api import rl


@pytest.mark.parametrize(
    ("pixel_format", "layout"),
    [
        (rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R16G16B16A16, "<4e"),
        (rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32, "<4f"),
    ],
)
def test_float_target_accumulates_past_one(raylib_context, pixel_format, layout) -> None:
    target = load_float_render_texture(8, 8, pixel_format=pixel_format)
    try:
        rl.begin_texture_mode(target)
        rl.clear_background(rl.BLACK)
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        for _ in range(3):
            rl.draw_rectangle(0, 0, 8, 8, rl.Color(255, 255, 255, 255))
        rl.end_blend_mode()
        rl.end_texture_mode()
        image = rl.load_image_from_texture(target.texture)
        try:
            red, green, blue, _alpha = struct.unpack(layout, rl.ffi.buffer(image.data, struct.calcsize(layout)))
        finally:
            rl.unload_image(image)
    finally:
        rl.unload_render_texture(target)
    assert (red, green, blue) == pytest.approx((3.0, 3.0, 3.0), abs=0.01)
