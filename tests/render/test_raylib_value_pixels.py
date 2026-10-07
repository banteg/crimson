from __future__ import annotations

from raylib import ffi

from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2


def test_fast_value_constructors_preserve_rotated_sprite_pixels(raylib_context) -> None:
    image = rl.gen_image_checked(16, 16, 4, 4, rl.Color(255, 77, 0, 255), rl.Color(51, 127, 255, 90))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    target = rl.load_render_texture(64, 48)

    def render(*, fast: bool) -> bytes:
        color = rl_color if fast else rl.Color
        rectangle = rl_rectangle if fast else rl.Rectangle
        vector = rl_vector2 if fast else rl.Vector2
        rl.begin_texture_mode(target)
        rl.clear_background(color(10, 20, 30, 255))
        for index in range(4):
            rl.draw_texture_pro(
                texture,
                rectangle(0.0, 0.0, 16.0, 16.0),
                rectangle(12.25 + index * 8.5, 15.75 + index * 3.25, 20.1, 22.3),
                vector(10.05, 11.15),
                -23.5 + index * 15.25,
                color(255, 204, 127, 90 + index * 40),
            )
        rl.end_texture_mode()
        pixels = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(pixels, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
            return bytes(ffi.buffer(pixels.data, pixels.width * pixels.height * 4))
        finally:
            rl.unload_image(pixels)

    try:
        actual = render(fast=True)
        assert len(actual) == 64 * 48 * 4
        assert len(set(actual)) > 4  # Sprites were drawn, rather than only the clear color.
        assert actual == render(fast=False)
    finally:
        rl.unload_render_texture(target)
        rl.unload_texture(texture)
