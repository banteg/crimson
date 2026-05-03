from __future__ import annotations

from typing import Any, ClassVar

import grim.app as grim_app


class _FakeRl:
    def __init__(self) -> None:
        self.window_should_close_calls = 0
        self.begin_calls = 0
        self.end_calls = 0
        self.close_calls = 0
        self.init_args: tuple[int, int, str] | None = None
        self.target_fps: int | None = None

    def set_config_flags(self, _: int) -> None:
        return None

    def init_window(self, width: int, height: int, title: str) -> None:
        self.init_args = (width, height, title)

    def set_exit_key(self, _: int) -> None:
        return None

    def set_target_fps(self, fps: int) -> None:
        self.target_fps = fps

    def window_should_close(self) -> bool:
        self.window_should_close_calls += 1
        return self.window_should_close_calls > 1

    def get_frame_time(self) -> float:
        return 1.0 / 60.0

    def is_key_pressed(self, _: int) -> bool:
        return False

    def get_render_width(self) -> int:
        return 800

    def get_render_height(self) -> int:
        return 450

    def begin_drawing(self) -> None:
        self.begin_calls += 1

    def end_drawing(self) -> None:
        self.end_calls += 1

    def take_screenshot(self, _: str) -> None:
        return None

    def close_window(self) -> None:
        self.close_calls += 1


class _ViewSpy:
    def __init__(self) -> None:
        self.open_calls = 0
        self.update_dts: list[float] = []
        self.draw_calls = 0
        self.close_calls = 0

    def open(self) -> None:
        self.open_calls += 1

    def update(self, dt: float) -> None:
        self.update_dts.append(dt)

    def draw(self) -> None:
        self.draw_calls += 1

    def close(self) -> None:
        self.close_calls += 1


class _PipelineSpy:
    instances: ClassVar[list[_PipelineSpy]] = []

    def __init__(
        self,
        *,
        sink: Any,
        on_resize: Any = None,
        draw_scope: Any = None,
    ) -> None:
        self.sink = sink
        self.on_resize = on_resize
        self.draw_scope = draw_scope
        self.draw_calls: list[tuple[int, int]] = []
        self.present_calls = 0
        self.close_calls = 0
        _PipelineSpy.instances.append(self)

    def draw(self, *, draw_frame: Any, width: int, height: int) -> None:
        self.draw_calls.append((width, height))
        draw_frame()

    def present(self) -> None:
        self.present_calls += 1

    def close(self) -> None:
        self.close_calls += 1


def test_run_view_uses_render_pipeline(monkeypatch) -> None:
    fake_rl = _FakeRl()
    view = _ViewSpy()
    sink_sentinel = object()
    draw_scope_sentinel = object()

    monkeypatch.setattr(grim_app, "rl", fake_rl)
    monkeypatch.setattr(grim_app, "WindowSink", lambda: sink_sentinel)
    monkeypatch.setattr(grim_app, "RaylibDrawScope", lambda *, raylib: draw_scope_sentinel)
    _PipelineSpy.instances.clear()
    monkeypatch.setattr(grim_app, "RenderPipeline", _PipelineSpy)

    grim_app.run_view(view, width=800, height=450, title="Render Test", fps=60)

    assert len(_PipelineSpy.instances) == 1
    pipeline = _PipelineSpy.instances[0]
    assert pipeline.sink is sink_sentinel
    assert pipeline.draw_scope is draw_scope_sentinel
    assert pipeline.draw_calls == [(800, 450)]
    assert pipeline.present_calls == 1
    assert pipeline.close_calls == 1
    assert view.open_calls == 1
    assert len(view.update_dts) == 1
    assert view.draw_calls == 1
    assert view.close_calls == 1
    assert fake_rl.close_calls == 1
