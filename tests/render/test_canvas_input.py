from __future__ import annotations

import pytest

from grim import canvas
from grim.raylib_api import rl


@pytest.mark.parametrize("canvas_size", [(128, 96), (64, 48), (64, 96), (128, 48)])
def test_canvas_restores_mouse_mapping_after_resize(raylib_context, canvas_size) -> None:
    surface = canvas.Canvas(*canvas_size)
    window = rl.glfw_get_current_context()
    size = rl.ffi.new("int[2]")
    rl.glfw_get_window_size(window, size + 0, size + 1)
    on_cursor = rl.glfw_set_cursor_pos_callback(window, rl.ffi.NULL)
    try:
        for stale_scale in (2.0 / 3.0, 0.5):
            # raylib can overwrite the scale during either fullscreen transition,
            # including after the canvas already fitted the new window size.
            rl.set_mouse_scale(stale_scale, stale_scale)
            surface.fit()
            frame = canvas.frame_rect()
            for x, y in ((0.0, 0.0), (0.5, 0.5), (1.0, 1.0)):
                # Inject the same window coordinates GLFW supplies to raylib.
                on_cursor(
                    window,
                    (frame.x + x * frame.width) * size[0] / rl.get_screen_width(),
                    (frame.y + y * frame.height) * size[1] / rl.get_screen_height(),
                )
                pos = canvas.mouse_position()
                assert (pos.x, pos.y) == pytest.approx((x * canvas_size[0], y * canvas_size[1]))
    finally:
        rl.glfw_set_cursor_pos_callback(window, on_cursor)
        rl.set_mouse_scale(1.0, 1.0)
        surface.close()
