from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import msgspec

from grim.raylib_api import rl

from .render_pipeline import RaylibDrawScope, RenderPipeline, WindowSink
from .view import View

SCREENSHOT_DIR = Path("screenshots")
SCREENSHOT_KEY = rl.KeyboardKey.KEY_F12


def _false_hook() -> bool:
    return False


class RunViewHooks(msgspec.Struct, frozen=True):
    should_close: Callable[[], bool] = _false_hook
    consume_screenshot_request: Callable[[], bool] = _false_hook


def _next_screenshot_index(directory: Path) -> int:
    if not directory.exists():
        return 1
    max_index = 0
    for entry in directory.glob("*.png"):
        stem = entry.stem
        if stem.isdigit():
            max_index = max(max_index, int(stem))
    return max_index + 1


def run_view(
    view: View,
    *,
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
    config_flags: int = 0,
    exit_key: int | None = None,
    hooks: RunViewHooks | None = None,
) -> None:
    """Run a Raylib window with a pluggable debug view."""
    if config_flags:
        rl.set_config_flags(config_flags)
    rl.init_window(width, height, title)
    if exit_key is not None:
        rl.set_exit_key(exit_key)
    rl.set_target_fps(fps)
    run_hooks = hooks if hooks is not None else RunViewHooks()
    render_pipeline = RenderPipeline(
        sink=WindowSink(),
        draw_scope=RaylibDrawScope(raylib=rl),
    )
    try:
        view.open()
        screenshot_dir = SCREENSHOT_DIR if SCREENSHOT_DIR.is_absolute() else Path.cwd() / SCREENSHOT_DIR
        screenshot_index = _next_screenshot_index(screenshot_dir)
        while not rl.window_should_close():
            dt = rl.get_frame_time()
            view.update(dt)
            take_screenshot = rl.is_key_pressed(SCREENSHOT_KEY)
            if run_hooks.consume_screenshot_request():
                take_screenshot = True
            render_pipeline.draw(
                draw_frame=view.draw,
                width=rl.get_render_width(),
                height=rl.get_render_height(),
            )
            render_pipeline.present()
            if run_hooks.should_close():
                break
            if take_screenshot:
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                filename = f"{screenshot_index:05d}.png"
                rl.take_screenshot(filename)
                src = Path.cwd() / filename
                if src.exists():
                    shutil.move(str(src), str(screenshot_dir / filename))
                screenshot_index += 1
    finally:
        try:
            view.close()
        finally:
            render_pipeline.close()
            rl.close_window()


def run_window(
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
) -> None:
    """Open a minimal Raylib window for the reference implementation."""

    class _EmptyView:
        def open(self) -> None:
            return None

        def update(self, dt: float) -> None:
            return None

        def draw(self) -> None:
            rl.clear_background(rl.BLACK)

        def close(self) -> None:
            return None

    run_view(_EmptyView(), width=width, height=height, title=title, fps=fps)
