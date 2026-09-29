from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import msgspec

from grim.raylib_api import rl

from .canvas import Canvas
from .render_pipeline import RaylibDrawScope, RenderPipeline, WindowSink
from .view import View

SCREENSHOT_DIR = Path("screenshots")
SCREENSHOT_KEY = rl.KeyboardKey.KEY_F12
ALT_KEYS = (rl.KeyboardKey.KEY_LEFT_ALT, rl.KeyboardKey.KEY_RIGHT_ALT)


def _not_requested() -> bool:
    return False


def _ignore_window_change(_state: bool) -> None:
    return None


class RunViewHooks(msgspec.Struct, frozen=True):
    should_close: Callable[[], bool] = _not_requested
    consume_screenshot_request: Callable[[], bool] = _not_requested
    fullscreen_changed: Callable[[bool], None] = _ignore_window_change
    focus_changed: Callable[[bool], None] = _ignore_window_change


def _fullscreen_toggle_pressed() -> bool:
    return rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and any(rl.is_key_down(key) for key in ALT_KEYS)


def _next_screenshot_name(directory: Path, index: int) -> tuple[str, int]:
    """`game_frame_update`'s F12 probe: the first `shot_%03d.bmp` not yet in `directory`, and the index after it."""
    while (directory / f"shot_{index:03d}.bmp").exists():
        index += 1
    return f"shot_{index:03d}.bmp", index + 1


def run_view(
    view: View,
    *,
    width: int = 1280,
    height: int = 720,
    title: str = "Crimsonland",
    fps: int = 60,
    window_state: int = 0,
    exit_key: int | None = None,
    hooks: RunViewHooks | None = None,
    screenshot_dir: Path = SCREENSHOT_DIR,
) -> None:
    """Run a Raylib window with a pluggable debug view drawn on a `width` x `height` canvas."""
    rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_HIGHDPI)
    rl.init_window(width, height, title)
    if window_state:
        # Borderless windowed only applies to an open window, so it can't go through set_config_flags.
        rl.set_window_state(window_state)
    canvas = Canvas(width, height)
    canvas.fit()
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
        screenshot_dir = screenshot_dir if screenshot_dir.is_absolute() else Path.cwd() / screenshot_dir
        screenshot_index = 0
        focused = True
        while not rl.window_should_close():
            dt = rl.get_frame_time()
            # Native grim freezes timing while the window is inactive and the game skips the first frame back.
            was_focused, focused = focused, rl.is_window_focused()
            if focused != was_focused:
                run_hooks.focus_changed(focused)
            toggle_fullscreen = _fullscreen_toggle_pressed()
            if toggle_fullscreen:
                rl.toggle_borderless_windowed()
                run_hooks.fullscreen_changed(rl.is_window_state(rl.ConfigFlags.FLAG_BORDERLESS_WINDOWED_MODE))
            canvas.fit()
            # Skip the update that would also see this frame's Enter press.
            if not toggle_fullscreen and focused and was_focused:
                view.update(dt)
            take_screenshot = rl.is_key_pressed(SCREENSHOT_KEY)
            if run_hooks.consume_screenshot_request():
                take_screenshot = True
            render_pipeline.draw(
                draw_frame=lambda: canvas.draw(view.draw),
                width=rl.get_render_width(),
                height=rl.get_render_height(),
            )
            render_pipeline.present()
            if run_hooks.should_close():
                break
            if take_screenshot:
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                filename, screenshot_index = _next_screenshot_name(screenshot_dir, screenshot_index)
                # raylib writes screenshots into the working directory.
                rl.take_screenshot(filename)
                src = Path.cwd() / filename
                if src.exists() and src != screenshot_dir / filename:
                    shutil.move(str(src), str(screenshot_dir / filename))
    finally:
        try:
            view.close()
        finally:
            canvas.close()
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

        def update(self, dt: float) -> None:  # noqa: ARG002 - View protocol signature
            return None

        def draw(self) -> None:
            rl.clear_background(rl.BLACK)

        def close(self) -> None:
            return None

    run_view(_EmptyView(), width=width, height=height, title=title, fps=fps)
