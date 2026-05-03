from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

RenderDraw = Callable[[], None]
RenderPresent = Callable[[], None]


class RenderSink(Protocol):
    def open(self) -> None: ...

    def present(self) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class WindowSink:
    """Default interactive sink; present/flush delegate to the frame loop."""

    def __init__(
        self,
        *,
        present_frame: RenderPresent | None = None,
    ) -> None:
        self._present_frame = present_frame
        self._opened = False

    def open(self) -> None:
        self._opened = True

    def present(self) -> None:
        if self._present_frame is None:
            return
        self._present_frame()

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._opened = False


class RenderDrawScope:
    def draw(self, draw_frame: RenderDraw) -> None:
        draw_frame()


class RaylibDrawScope(RenderDrawScope):
    def __init__(self, *, raylib: Any) -> None:
        self._rl = raylib

    def draw(self, draw_frame: RenderDraw) -> None:
        self._rl.begin_drawing()
        try:
            draw_frame()
        finally:
            self._rl.end_drawing()


class RenderPipeline:
    """Shared draw/present orchestration for live and replay contexts."""

    def __init__(
        self,
        *,
        sink: RenderSink,
        on_resize: Callable[[int, int], None] | None = None,
        draw_scope: RenderDrawScope | None = None,
    ) -> None:
        self._sink = sink
        self._on_resize = on_resize
        self._draw_scope = draw_scope if draw_scope is not None else RenderDrawScope()
        self._opened = False
        self._width = -1
        self._height = -1

    def open(self, *, width: int, height: int) -> None:
        if self._opened:
            return
        normalized_w = max(0, int(width))
        normalized_h = max(0, int(height))
        try:
            if self._on_resize is not None:
                self._on_resize(normalized_w, normalized_h)
            self._sink.open()
        except Exception:
            try:
                self._sink.close()
            except Exception:
                pass
            self._opened = False
            self._width = -1
            self._height = -1
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
        if self._on_resize is not None:
            self._on_resize(normalized_w, normalized_h)
        self._width = normalized_w
        self._height = normalized_h

    def draw(self, *, draw_frame: RenderDraw, width: int, height: int) -> None:
        self._ensure_open(width=int(width), height=int(height))
        self._resize_if_needed(width=int(width), height=int(height))
        self._draw_scope.draw(draw_frame)

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
            self._opened = False
            self._width = -1
            self._height = -1
