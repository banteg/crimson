from __future__ import annotations

from pathlib import Path

import pytest

from crimson.render.pipeline import RenderPipeline
from crimson.render.sink import NullSink, VideoSink, WindowSink


def test_render_pipeline_lifecycle_and_resize_behavior() -> None:
    events: list[str] = []

    class _Backend:
        def open(self) -> None:
            events.append("backend.open")

        def resize(self, *, width: int, height: int) -> None:
            events.append(f"backend.resize:{int(width)}x{int(height)}")

        def draw_frame(self, draw_frame) -> None:
            events.append("backend.draw")
            draw_frame()

        def close(self) -> None:
            events.append("backend.close")

    class _Sink:
        fail_fast = False

        def open(self) -> None:
            events.append("sink.open")

        def present(self) -> None:
            events.append("sink.present")

        def flush(self) -> None:
            events.append("sink.flush")

        def close(self) -> None:
            events.append("sink.close")

    pipeline = RenderPipeline(backend=_Backend(), sink=_Sink())
    pipeline.render(draw_frame=lambda: events.append("draw.frame.1"), width=640, height=480)
    pipeline.render(draw_frame=lambda: events.append("draw.frame.2"), width=640, height=480)
    pipeline.render(draw_frame=lambda: events.append("draw.frame.3"), width=800, height=600)
    pipeline.flush()
    pipeline.close()

    assert events == [
        "backend.open",
        "backend.resize:640x480",
        "sink.open",
        "backend.draw",
        "draw.frame.1",
        "sink.present",
        "backend.draw",
        "draw.frame.2",
        "sink.present",
        "backend.resize:800x600",
        "backend.draw",
        "draw.frame.3",
        "sink.present",
        "sink.flush",
        "sink.close",
        "backend.close",
    ]


def test_window_sink_logs_and_continues_on_present_error() -> None:
    logs: list[str] = []

    def _raise_present() -> None:
        raise RuntimeError("boom")

    sink = WindowSink(present_frame=_raise_present, log_error=logs.append)
    sink.open()
    sink.present()
    sink.flush()
    sink.close()

    assert len(logs) == 1
    assert "window sink present failed" in logs[0]


def test_video_sink_transport_and_fail_fast_behavior(tmp_path: Path) -> None:
    events: list[str] = []

    sink = VideoSink(
        output_path=tmp_path / "nested" / "out.mp4",
        open_transport=lambda: events.append("open"),
        present_frame=lambda: events.append("present"),
        flush_transport=lambda: events.append("flush"),
        close_transport=lambda: events.append("close"),
    )
    sink.open()
    sink.present()
    sink.flush()
    sink.close()

    assert events == ["open", "present", "flush", "close"]

    def _raise_present() -> None:
        raise RuntimeError("present failed")

    sink = VideoSink(
        output_path=tmp_path / "out.mp4",
        present_frame=_raise_present,
    )
    sink.open()
    with pytest.raises(RuntimeError, match="present failed"):
        sink.present()
    sink.close()


def test_null_sink_is_noop() -> None:
    sink = NullSink()
    sink.open()
    sink.present()
    sink.flush()
    sink.close()
