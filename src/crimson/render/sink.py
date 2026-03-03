from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from grim.render_pipeline import RenderPresent, RenderSink, WindowSink

__all__ = ["RenderPresent", "RenderSink", "WindowSink", "NullSink", "VideoSink"]


class NullSink:
    """Headless sink used for determinism-only verification paths."""

    def open(self) -> None:
        pass

    def present(self) -> None:
        pass

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class VideoSink:
    """Video-export sink. Fail-fast by policy: presentation errors abort rendering."""

    def __init__(
        self,
        *,
        output_path: Path,
        open_transport: Callable[[], None] | None = None,
        present_frame: RenderPresent | None = None,
        flush_transport: Callable[[], None] | None = None,
        close_transport: Callable[[], None] | None = None,
    ) -> None:
        self.output_path = Path(output_path)
        self._open_transport = open_transport
        self._present_frame = present_frame
        self._flush_transport = flush_transport
        self._close_transport = close_transport
        self._opened = False
        self._flushed = False

    def open(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        if self._open_transport is not None:
            self._open_transport()
        self._opened = True
        self._flushed = False

    def present(self) -> None:
        if self._present_frame is not None:
            self._present_frame()

    def flush(self) -> None:
        if not self._opened or self._flushed:
            return
        if self._flush_transport is not None:
            self._flush_transport()
        self._flushed = True

    def close(self) -> None:
        if not self._opened:
            return
        if self._close_transport is not None:
            self._close_transport()
        self._opened = False
