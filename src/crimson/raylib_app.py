from __future__ import annotations

import pyray as rl

from .views.types import View


def run_view(
    view: View,
    *,
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
) -> None:
    """Run a Raylib window with a pluggable debug view."""
    rl.init_window(width, height, title)
    rl.set_target_fps(fps)
    open_fn = getattr(view, "open", None)
    if callable(open_fn):
        open_fn()
    while not rl.window_should_close():
        dt = rl.get_frame_time()
        view.update(dt)
        rl.begin_drawing()
        view.draw()
        rl.end_drawing()
    close_fn = getattr(view, "close", None)
    if callable(close_fn):
        close_fn()
    rl.close_window()


def run_window(
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
) -> None:
    """Open a minimal Raylib window for the reference implementation."""
    from .views.empty import EmptyView

    run_view(EmptyView(), width=width, height=height, title=title, fps=fps)
