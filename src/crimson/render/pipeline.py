from __future__ import annotations

from collections.abc import Callable

from .sink import RenderSink
from .types import RenderDraw


class RenderPipeline:
    """Shared draw/present orchestration for live and replay contexts."""

    def __init__(
        self,
        *,
        sink: RenderSink,
        on_resize: Callable[[int, int], None] | None = None,
        begin_end_drawing: bool = False,
        begin_draw: Callable[[], None] | None = None,
        end_draw: Callable[[], None] | None = None,
    ) -> None:
        if bool(begin_end_drawing) and (begin_draw is None or end_draw is None):
            raise ValueError("begin_draw and end_draw are required when begin_end_drawing=True")
        self._sink = sink
        self._on_resize = on_resize
        self._begin_end_drawing = bool(begin_end_drawing)
        self._begin_draw = begin_draw
        self._end_draw = end_draw
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
            self._opened = False
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
        if self._begin_end_drawing:
            begin_draw = self._begin_draw
            end_draw = self._end_draw
            if begin_draw is None or end_draw is None:
                raise RuntimeError("render pipeline missing begin/end draw callbacks")
            begin_draw()
            try:
                draw_frame()
            finally:
                end_draw()
            return
        draw_frame()

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
        self._sink.close()
        self._opened = False
