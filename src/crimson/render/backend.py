from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .frame import RenderFrame
else:  # pragma: no cover
    RenderFrame = object


class RenderBackend(Protocol):
    def open(self) -> None: ...

    def resize(self, *, width: int, height: int) -> None: ...

    def draw_frame(self, frame: "RenderFrame") -> None: ...

    def close(self) -> None: ...


class RaylibBackend:
    """Thin adapter seam over the current raylib-backed draw path."""

    def __init__(self, *, draw_frame: Callable[["RenderFrame"], None] | None = None) -> None:
        self._draw_frame = draw_frame
        self._opened = False
        self._width = 0
        self._height = 0

    def open(self) -> None:
        self._opened = True

    def resize(self, *, width: int, height: int) -> None:
        self._width = max(0, int(width))
        self._height = max(0, int(height))

    def draw_frame(self, frame: "RenderFrame") -> None:
        if self._draw_frame is not None:
            self._draw_frame(frame)

    def close(self) -> None:
        self._opened = False
