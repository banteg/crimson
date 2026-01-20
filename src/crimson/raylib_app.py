from __future__ import annotations

import pyray as rl


def run_window(
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland Reimpl",
    fps: int = 60,
) -> None:
    """Open a minimal Raylib window for the reference implementation."""
    rl.init_window(width, height, title)
    rl.set_target_fps(fps)
    try:
        while not rl.window_should_close():
            rl.begin_drawing()
            rl.clear_background(rl.BLACK)
            rl.end_drawing()
    finally:
        rl.close_window()
