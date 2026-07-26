from __future__ import annotations

from pathlib import Path

from grim.render_pipeline import RenderPresent, RenderSink, WindowSink

__all__ = ["NullSink", "RenderPresent", "RenderSink", "VideoSink", "VideoTransport", "WindowSink"]


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


class VideoTransport:
    def open(self) -> None:
        return None

    def present_frame(self) -> None:
        return None

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class VideoSink:
    """Video-export sink. Fail-fast by policy: presentation errors abort rendering."""

    def __init__(
        self,
        *,
        output_path: Path,
        transport: VideoTransport | None = None,
    ) -> None:
        self.output_path = Path(output_path)
        self._transport = transport if transport is not None else VideoTransport()
        self._opened = False
        self._flushed = False

    def open(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._transport.open()
        self._opened = True
        self._flushed = False

    def present(self) -> None:
        self._transport.present_frame()

    def flush(self) -> None:
        if not self._opened or self._flushed:
            return
        self._transport.flush()
        self._flushed = True

    def close(self) -> None:
        if not self._opened:
            return
        self._transport.close()
        self._opened = False
