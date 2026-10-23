from __future__ import annotations

from collections.abc import Callable

import msgspec

from .blend import opaque_blend
from .edr import HDR_PIXEL_FORMAT, edr_active, edr_available, load_float_render_texture
from .raylib_api import rl, rl_rectangle, rl_vector2
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


class _Pointer(msgspec.Struct):
    """A cursor the game steers itself (a pad's stick), which the game reads instead of the window's until let go,
    and its left button."""

    pos: rl.Vector2 | None = None
    down: bool = False
    pressed: bool = False


_pointer = _Pointer()


def width() -> int:
    return rl.get_screen_width() if _letterbox is None else _letterbox.width


def height() -> int:
    return rl.get_screen_height() if _letterbox is None else _letterbox.height


def frame_rect() -> rl.Rectangle:
    """Where the game frame lands in the window, in window points: the letterboxed area or the whole window."""
    box = _letterbox
    if box is None:
        return rl_rectangle(0.0, 0.0, float(rl.get_screen_width()), float(rl.get_screen_height()))
    return rl_rectangle(box.x, box.y, box.width * box.scale, box.height * box.scale)


def mouse_position() -> rl.Vector2:
    if _pointer.pos is not None:
        return _pointer.pos
    pos = rl.get_mouse_position()
    box = _letterbox
    if box is None:
        return pos
    return rl_vector2((pos.x - box.x) / box.scale, (pos.y - box.y) / box.scale)


def mouse_delta() -> rl.Vector2:
    delta = rl.get_mouse_delta()
    box = _letterbox
    if box is None:
        return delta
    return rl_vector2(delta.x / box.scale, delta.y / box.scale)


def steer_mouse(pos: rl.Vector2 | None) -> None:
    """Hold the game's cursor at `pos`, in canvas points, or with None hand it back to the window's."""
    _pointer.pos = pos


def press_mouse(down: bool) -> None:
    """Hold the game's own left button down, once a frame; its press is the frame it goes down."""
    _pointer.pressed = down and not _pointer.down
    _pointer.down = down


def mouse_pressed() -> bool:
    """The left button pressed this frame, the window's or the game's own."""
    return rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT) or _pointer.pressed


def mouse_down() -> bool:
    """The left button held, the window's or the game's own."""
    return rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT) or _pointer.down


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
        # GLFW cursor coordinates use window units. raylib's resize callbacks can
        # leave an extra inverse-DPI mouse scale on Wayland, even after fullscreen
        # ends. Derive the mapping from the actual sizes before letterboxing.
        size = rl.ffi.new("int[2]")
        rl.glfw_get_window_size(rl.glfw_get_current_context(), size + 0, size + 1)
        rl.set_mouse_scale(window_w / size[0], window_h / size[1])
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
        # A reserved float window must still composite classic through RGBA8,
        # preserving its per-draw saturation and quantization before presentation.
        if box is None and (edr_active() or not edr_available()):
            draw_frame()
            return
        dst = frame_rect()
        # Render at the letterboxed size in physical pixels so the frame is drawn, not upscaled.
        dpi = rl.get_window_scale_dpi()
        target = self._ensure_target(round(dst.width * dpi.x), round(dst.height * dpi.y))
        target_w = target.texture.width
        target_h = target.texture.height
        with texture_mode(target, scale_x=target_w / self.width, scale_y=target_h / self.height):
            rl.clear_background(rl.BLACK)
            draw_frame()
        rl.clear_background(rl.BLACK)
        with opaque_blend():
            rl.draw_texture_pro(
                target.texture,
                rl_rectangle(0.0, 0.0, float(target_w), -float(target_h)),
                dst,
                rl_vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )

    def _ensure_target(self, target_w: int, target_h: int) -> rl.RenderTexture:
        use_float = edr_active()
        expected_format = int(HDR_PIXEL_FORMAT) if use_float else int(rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
        target = self._target
        if (
            target is not None
            and (target.texture.width, target.texture.height) == (target_w, target_h)
            and int(target.texture.format) == expected_format
        ):
            return target
        previous = target
        if use_float:
            target = load_float_render_texture(target_w, target_h)
        else:
            target = rl.load_render_texture(target_w, target_h)
            rl.set_texture_filter(target.texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        if previous is not None:
            rl.unload_render_texture(previous)
        self._target = target
        return target

    def close(self) -> None:
        global _letterbox
        _letterbox = None
        if self._target is not None:
            rl.unload_render_texture(self._target)
            self._target = None
