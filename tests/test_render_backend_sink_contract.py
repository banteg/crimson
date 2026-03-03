from __future__ import annotations

from pathlib import Path

import pytest

from crimson.render.pipeline import RenderPipeline
from crimson.render.sink import NullSink, VideoSink, WindowSink


def test_render_pipeline_lifecycle_and_resize_behavior() -> None:
    events: list[str] = []

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

    pipeline = RenderPipeline(
        sink=_Sink(),
        on_resize=lambda width, height: events.append(f"resize:{int(width)}x{int(height)}"),
        begin_end_drawing=True,
        begin_draw=lambda: events.append("draw.begin"),
        end_draw=lambda: events.append("draw.end"),
    )
    pipeline.render(draw_frame=lambda: events.append("draw.frame.1"), width=640, height=480)
    pipeline.render(draw_frame=lambda: events.append("draw.frame.2"), width=640, height=480)
    pipeline.render(draw_frame=lambda: events.append("draw.frame.3"), width=800, height=600)
    pipeline.flush()
    pipeline.close()

    assert events == [
        "resize:640x480",
        "sink.open",
        "draw.begin",
        "draw.frame.1",
        "draw.end",
        "sink.present",
        "draw.begin",
        "draw.frame.2",
        "draw.end",
        "sink.present",
        "resize:800x600",
        "draw.begin",
        "draw.frame.3",
        "draw.end",
        "sink.present",
        "sink.flush",
        "sink.close",
    ]


def test_render_pipeline_closes_sink_when_open_fails() -> None:
    events: list[str] = []

    class _FailingSink:
        def open(self) -> None:
            events.append("sink.open")
            raise RuntimeError("open failed")

        def present(self) -> None:
            events.append("sink.present")

        def flush(self) -> None:
            events.append("sink.flush")

        def close(self) -> None:
            events.append("sink.close")

    pipeline = RenderPipeline(sink=_FailingSink())
    with pytest.raises(RuntimeError, match="open failed"):
        pipeline.render(draw_frame=lambda: None, width=640, height=480)

    assert events == ["sink.open", "sink.close"]


def test_window_sink_raises_on_present_error() -> None:
    def _raise_present() -> None:
        raise RuntimeError("boom")

    sink = WindowSink(present_frame=_raise_present)
    sink.open()
    with pytest.raises(RuntimeError, match="boom"):
        sink.present()
    sink.flush()
    sink.close()


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
