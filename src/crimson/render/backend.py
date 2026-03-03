from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

RenderDraw = Callable[[], None]


class RenderBackend(Protocol):
    def open(self) -> None: ...

    def resize(self, *, width: int, height: int) -> None: ...

    def draw_frame(self, draw_frame: RenderDraw) -> None: ...

    def close(self) -> None: ...


class RaylibBackend:
    """Thin adapter seam over the current raylib-backed draw path."""

    def __init__(self, *, draw_frame: RenderDraw | None = None) -> None:
        self._draw_frame = draw_frame
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

    def draw_frame(self, draw_frame: RenderDraw | None = None) -> None:
        callback = self._draw_frame if draw_frame is None else draw_frame
        if callback is None:
            return
        callback()

    def close(self) -> None:
        self._opened = False
