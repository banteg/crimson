from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from crimson.render.pipeline import RaylibDrawScope, RenderDrawScope, RenderPipeline
from crimson.render.sink import NullSink, VideoSink, VideoTransport, WindowSink


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

    class _EventDrawScope(RenderDrawScope):
        def draw(self, draw_frame: Callable[[], None]) -> None:
            events.append("draw.begin")
            try:
                draw_frame()
            finally:
                events.append("draw.end")

    pipeline = RenderPipeline(
        sink=_Sink(),
        on_resize=lambda width, height: events.append(f"resize:{int(width)}x{int(height)}"),
        draw_scope=_EventDrawScope(),
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


def test_raylib_draw_scope_balances_begin_end_on_draw_error() -> None:
    events: list[str] = []

    class _RaylibRuntime:
        def begin_drawing(self) -> None:
            events.append("begin")

        def end_drawing(self) -> None:
            events.append("end")

    def _raise_draw() -> None:
        events.append("draw")
        raise RuntimeError("draw failed")

    scope = RaylibDrawScope(raylib=_RaylibRuntime())

    with pytest.raises(RuntimeError, match="draw failed"):
        scope.draw(_raise_draw)

    assert events == ["begin", "draw", "end"]


def test_render_pipeline_resets_open_state_when_close_fails() -> None:
    events: list[str] = []

    class _Sink:
        def __init__(self) -> None:
            self.raise_on_close = False

        def open(self) -> None:
            events.append("sink.open")

        def present(self) -> None:
            events.append("sink.present")

        def flush(self) -> None:
            events.append("sink.flush")

        def close(self) -> None:
            events.append("sink.close")
            if self.raise_on_close:
                raise RuntimeError("close failed")

    sink = _Sink()
    pipeline = RenderPipeline(sink=sink)
    pipeline.render(draw_frame=lambda: events.append("draw.1"), width=640, height=480)

    sink.raise_on_close = True
    with pytest.raises(RuntimeError, match="close failed"):
        pipeline.close()

    sink.raise_on_close = False
    pipeline.render(draw_frame=lambda: events.append("draw.2"), width=640, height=480)
    pipeline.close()

    assert events.count("sink.open") == 2


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

    class _EventVideoTransport(VideoTransport):
        def open(self) -> None:
            events.append("open")

        def present_frame(self) -> None:
            events.append("present")

        def flush(self) -> None:
            events.append("flush")

        def close(self) -> None:
            events.append("close")

    sink = VideoSink(
        output_path=tmp_path / "nested" / "out.mp4",
        transport=_EventVideoTransport(),
    )
    sink.open()
    sink.present()
    sink.flush()
    sink.close()

    assert events == ["open", "present", "flush", "close"]

    class _FailingVideoTransport(VideoTransport):
        def present_frame(self) -> None:
            raise RuntimeError("present failed")

    sink = VideoSink(
        output_path=tmp_path / "out.mp4",
        transport=_FailingVideoTransport(),
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
