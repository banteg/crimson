from __future__ import annotations

from collections.abc import Callable

import msgspec

from .blend import opaque_blend
from .raylib_api import rl
from .texture_mode import texture_mode

# The game lays out for one resolution (crimson.cfg width/height). When the window is
# another size (borderless fullscreen), the frame is drawn at that canvas size and
# scaled to fit with black bars, so game code reads the screen size and mouse
# position from here rather than from raylib.


class _Letterbox(msgspec.Struct, frozen=True):
    width: int
    height: int
    x: float
    y: float
    scale: float


_letterbox: _Letterbox | None = None


def width() -> int:
    return rl.get_screen_width() if _letterbox is None else _letterbox.width


def height() -> int:
    return rl.get_screen_height() if _letterbox is None else _letterbox.height


def frame_rect() -> rl.Rectangle:
    """Where the game frame lands in the window, in window points: the letterboxed area or the whole window."""
    box = _letterbox
    if box is None:
        return rl.Rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
    return rl.Rectangle(box.x, box.y, box.width * box.scale, box.height * box.scale)


def mouse_position() -> rl.Vector2:
    pos = rl.get_mouse_position()
    box = _letterbox
    if box is None:
        return pos
    return rl.Vector2((pos.x - box.x) / box.scale, (pos.y - box.y) / box.scale)


def mouse_delta() -> rl.Vector2:
    delta = rl.get_mouse_delta()
    box = _letterbox
    if box is None:
        return delta
    return rl.Vector2(delta.x / box.scale, delta.y / box.scale)


class Canvas:
    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height
        self._target: rl.RenderTexture | None = None

    def fit(self) -> None:
        """Letterbox the canvas into the window; a window of canvas size is drawn to directly."""
        global _letterbox
        window_w = rl.get_screen_width()
        window_h = rl.get_screen_height()
        if (window_w, window_h) == (self.width, self.height):
            _letterbox = None
            return
        scale = min(window_w / self.width, window_h / self.height)
        _letterbox = _Letterbox(
            width=self.width,
            height=self.height,
            x=(window_w - self.width * scale) * 0.5,
            y=(window_h - self.height * scale) * 0.5,
            scale=scale,
        )

    def draw(self, draw_frame: Callable[[], None]) -> None:
        box = _letterbox
        if box is None:
            draw_frame()
            return
        dst = frame_rect()
        # Render at the letterboxed size in physical pixels so the frame is drawn, not upscaled.
        dpi = rl.get_window_scale_dpi()
        target = self._ensure_target(round(dst.width * dpi.x), round(dst.height * dpi.y))
        target_w = target.texture.width
        target_h = target.texture.height
        with texture_mode(target, scale_x=target_w / box.width, scale_y=target_h / box.height):
            rl.clear_background(rl.BLACK)
            draw_frame()
        rl.clear_background(rl.BLACK)
        with opaque_blend():
            rl.draw_texture_pro(
                target.texture,
                rl.Rectangle(0.0, 0.0, float(target_w), -float(target_h)),
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )

    def _ensure_target(self, target_w: int, target_h: int) -> rl.RenderTexture:
        target = self._target
        if target is not None and (target.texture.width, target.texture.height) == (target_w, target_h):
            return target
        if target is not None:
            rl.unload_render_texture(target)
        target = rl.load_render_texture(target_w, target_h)
        rl.set_texture_filter(target.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        self._target = target
        return target

    def close(self) -> None:
        global _letterbox
        _letterbox = None
        if self._target is not None:
            rl.unload_render_texture(self._target)
            self._target = None
