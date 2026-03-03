from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol


class RenderSink(Protocol):
    def open(self) -> None: ...

    def present(self) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class WindowSink:
    """Default interactive sink; present/flush delegate to the frame loop."""

    def open(self) -> None:
        return

    def present(self) -> None:
        return

    def flush(self) -> None:
        return

    def close(self) -> None:
        return


class NullSink:
    """Headless sink used for determinism-only verification paths."""

    def open(self) -> None:
        return

    def present(self) -> None:
        return

    def flush(self) -> None:
        return

    def close(self) -> None:
        return


class VideoSink:
    """Video-export sink placeholder; concrete ffmpeg transport lands in later slices."""

    def __init__(self, *, output_path: Path, present_frame: Callable[[], None] | None = None) -> None:
        self.output_path = Path(output_path)
        self._present_frame = present_frame
        self._opened = False

    def open(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._opened = True

    def present(self) -> None:
        if self._present_frame is not None:
            self._present_frame()

    def flush(self) -> None:
        return

    def close(self) -> None:
        self._opened = False
