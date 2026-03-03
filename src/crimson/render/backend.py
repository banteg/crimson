from __future__ import annotations

from collections.abc import Callable

from grim.raylib_api import rl

RenderDraw = Callable[[], None]


class RaylibBackend:
    """Raylib draw adapter with optional begin/end-drawing ownership."""

    def __init__(self, *, begin_end_drawing: bool = False) -> None:
        self._begin_end_drawing = bool(begin_end_drawing)
        self._opened = False
        self._width = 0
        self._height = 0

    @property
    def opened(self) -> bool:
        return bool(self._opened)

    @property
    def viewport(self) -> tuple[int, int]:
        return int(self._width), int(self._height)

    def open(self) -> None:
        self._opened = True

    def resize(self, *, width: int, height: int) -> None:
        self._width = max(0, int(width))
        self._height = max(0, int(height))

    def draw_frame(self, draw_frame: RenderDraw) -> None:
        if not bool(self._begin_end_drawing):
            draw_frame()
            return
        rl.begin_drawing()
        try:
            draw_frame()
        finally:
            rl.end_drawing()

    def close(self) -> None:
        self._opened = False
