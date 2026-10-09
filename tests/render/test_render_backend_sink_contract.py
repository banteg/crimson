from __future__ import annotations

from collections.abc import Callable

import pytest

from crimson.render.pipeline import RaylibDrawScope, RenderDrawScope, RenderPipeline


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
