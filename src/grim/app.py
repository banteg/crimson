from __future__ import annotations

import shutil
from pathlib import Path
from typing import Protocol, runtime_checkable

from grim.raylib_api import rl

from .view import View

SCREENSHOT_DIR = Path("screenshots")
SCREENSHOT_KEY = rl.KeyboardKey.KEY_F12


@runtime_checkable
class _HasLifecycle(Protocol):
    def open(self) -> None: ...
    def close(self) -> None: ...


@runtime_checkable
class _HasShouldClose(Protocol):
    def should_close(self) -> bool: ...


@runtime_checkable
class _HasCloseRequested(Protocol):
    close_requested: bool


@runtime_checkable
class _HasConsumeScreenshotRequest(Protocol):
    def consume_screenshot_request(self) -> bool: ...


def _next_screenshot_index(directory: Path) -> int:
    if not directory.exists():
        return 1
    max_index = 0
    for entry in directory.glob("*.png"):
        stem = entry.stem
        if stem.isdigit():
            max_index = max(max_index, int(stem))
    return max_index + 1


def _view_should_close(view: View) -> bool:
    if isinstance(view, _HasShouldClose):
        return view.should_close()
    if isinstance(view, _HasCloseRequested):
        return view.close_requested
    return False


def run_view(
    view: View,
    *,
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
    config_flags: int = 0,
    exit_key: int | None = None,
) -> None:
    """Run a Raylib window with a pluggable debug view."""
    if config_flags:
        rl.set_config_flags(config_flags)
    rl.init_window(width, height, title)
    if exit_key is not None:
        rl.set_exit_key(exit_key)
    rl.set_target_fps(fps)
    if isinstance(view, _HasLifecycle):
        view.open()
    screenshot_dir = SCREENSHOT_DIR if SCREENSHOT_DIR.is_absolute() else Path.cwd() / SCREENSHOT_DIR
    screenshot_index = _next_screenshot_index(screenshot_dir)
    while not rl.window_should_close():
        dt = rl.get_frame_time()
        view.update(dt)
        take_screenshot = rl.is_key_pressed(SCREENSHOT_KEY)
        if isinstance(view, _HasConsumeScreenshotRequest) and view.consume_screenshot_request():
            take_screenshot = True
        rl.begin_drawing()
        view.draw()
        rl.end_drawing()
        if _view_should_close(view):
            break
        if take_screenshot:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{screenshot_index:05d}.png"
            rl.take_screenshot(filename)
            src = Path.cwd() / filename
            if src.exists():
                shutil.move(str(src), str(screenshot_dir / filename))
            screenshot_index += 1
    if isinstance(view, _HasLifecycle):
        view.close()
    rl.close_window()


def run_window(
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
) -> None:
    """Open a minimal Raylib window for the reference implementation."""

    class _EmptyView:
        def update(self, dt: float) -> None:
            return None

        def draw(self) -> None:
            rl.clear_background(rl.BLACK)

    run_view(_EmptyView(), width=width, height=height, title=title, fps=fps)
