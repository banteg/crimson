from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

RenderPresent = Callable[[], None]
RenderErrorLogger = Callable[[str], None]


class RenderSink(Protocol):
    fail_fast: bool

    def open(self) -> None: ...

    def present(self) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class WindowSink:
    """Default interactive sink; present/flush delegate to the frame loop."""

    fail_fast = False

    def __init__(
        self,
        *,
        present_frame: RenderPresent | None = None,
        log_error: RenderErrorLogger | None = None,
    ) -> None:
        self._present_frame = present_frame
        self._log_error = log_error
        self._opened = False

    def open(self) -> None:
        self._opened = True

    def present(self) -> None:
        if self._present_frame is None:
            return
        try:
            self._present_frame()
        except Exception as exc:  # pragma: no cover - defensive logging policy seam
            if self._log_error is not None:
                self._log_error(f"window sink present failed: {exc}")

    def flush(self) -> None:
        return

    def close(self) -> None:
        self._opened = False


class NullSink:
    """Headless sink used for determinism-only verification paths."""

    fail_fast = False

    def open(self) -> None:
        return

    def present(self) -> None:
        return

    def flush(self) -> None:
        return

    def close(self) -> None:
        return


class VideoSink:
    """Video-export sink. Fail-fast by policy: presentation errors abort rendering."""

    fail_fast = True

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
