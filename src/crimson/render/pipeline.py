from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .sink import RenderSink

RenderDraw = Callable[[], None]


class RenderPipeline:
    """Shared draw/present orchestration for live and replay contexts."""

    def __init__(self, *, backend: Any, sink: RenderSink) -> None:
        self._backend = backend
        self._sink = sink
        self._opened = False
        self._width = -1
        self._height = -1

    def open(self, *, width: int, height: int) -> None:
        if self._opened:
            return
        normalized_w = max(0, int(width))
        normalized_h = max(0, int(height))
        self._backend.open()
        try:
            self._backend.resize(width=normalized_w, height=normalized_h)
            self._sink.open()
        except Exception:
            self._backend.close()
            raise
        self._opened = True
        self._width = normalized_w
        self._height = normalized_h

    def _ensure_open(self, *, width: int, height: int) -> None:
        if self._opened:
            return
        self.open(width=int(width), height=int(height))

    def _resize_if_needed(self, *, width: int, height: int) -> None:
        normalized_w = max(0, int(width))
        normalized_h = max(0, int(height))
        if normalized_w == self._width and normalized_h == self._height:
            return
        self._backend.resize(width=normalized_w, height=normalized_h)
        self._width = normalized_w
        self._height = normalized_h

    def draw(self, *, draw_frame: RenderDraw, width: int, height: int) -> None:
        self._ensure_open(width=int(width), height=int(height))
        self._resize_if_needed(width=int(width), height=int(height))
        self._backend.draw_frame(draw_frame)

    def present(self) -> None:
        if not self._opened:
            return
        self._sink.present()

    def render(self, *, draw_frame: RenderDraw, width: int, height: int) -> None:
        self.draw(draw_frame=draw_frame, width=int(width), height=int(height))
        self.present()

    def flush(self) -> None:
        if not self._opened:
            return
        self._sink.flush()

    def close(self) -> None:
        if not self._opened:
            return
        try:
            self._sink.close()
        finally:
            self._backend.close()
            self._opened = False
