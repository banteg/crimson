from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any, Self

import msgspec

from ...render.world import profile_hooks


class RenderTelemetryFrameSnapshot(msgspec.Struct, frozen=True):
    frame_index: int
    tick_index_before_update: int
    tick_index_after_update: int
    update_ms: float
    draw_ms: float
    frame_ms: float
    draw_calls_total: int
    draw_calls_by_api: dict[str, int]
    draw_calls_by_pass: dict[str, int]
    pass_ms: dict[str, float]


class _SessionSink:
    def __init__(self, session: RenderTelemetrySession) -> None:
        self._session = session

    def on_pass_duration(self, pass_name: str, duration_ms: float) -> None:
        self._session.record_pass_duration(pass_name, duration_ms)


class RenderTelemetrySession:
    _INTERCEPT_APIS: tuple[tuple[str, str], ...] = (
        ("draw_texture_pro", "draw_texture_pro"),
        ("draw_circle", "draw_circle"),
        ("draw_circle_lines", "draw_circle_lines"),
        ("draw_circle_sector", "draw_circle_sector"),
        ("draw_ring", "draw_ring"),
        ("draw_rectangle", "draw_rectangle"),
        ("draw_rectangle_lines", "draw_rectangle_lines"),
        ("draw_text", "draw_text"),
        ("rl_begin", "rl_begin"),
        ("begin_blend_mode", "begin_blend_mode"),
        ("end_blend_mode", "end_blend_mode"),
    )

    def __init__(self) -> None:
        self._active = False
        self._originals: dict[str, Callable[..., Any]] = {}
        self._frames: list[RenderTelemetryFrameSnapshot] = []
        self._current_frame_index: int | None = None
        self._current_tick_before_update: int | None = None
        self._draw_calls_total = 0
        self._draw_calls_by_api: defaultdict[str, int] = defaultdict(int)
        self._draw_calls_by_pass: defaultdict[str, int] = defaultdict(int)
        self._pass_ms: defaultdict[str, float] = defaultdict(float)
        self._sink = _SessionSink(self)
        self._prev_sink: profile_hooks.RenderProfileSink | None = None

    @property
    def frames(self) -> tuple[RenderTelemetryFrameSnapshot, ...]:
        return tuple(self._frames)

    def start(self) -> None:
        if self._active:
            return

        from grim.raylib_api import rl

        self._active = True
        profile_hooks.clear_pass_stack()
        self._prev_sink = profile_hooks.set_active_sink(self._sink)
        for fn_name, api_name in self._INTERCEPT_APIS:
            original = getattr(rl, fn_name, None)
            if original is None or not callable(original):
                continue
            self._originals[fn_name] = original

            def _wrapped(*args: Any, _orig: Callable[..., Any] = original, _api_name: str = api_name, **kwargs: Any) -> Any:
                self.record_draw_call(_api_name)
                return _orig(*args, **kwargs)

            setattr(rl, fn_name, _wrapped)

    def stop(self) -> None:
        if not self._active:
            return

        from grim.raylib_api import rl

        self._active = False
        for fn_name, original in self._originals.items():
            setattr(rl, fn_name, original)
        self._originals.clear()
        profile_hooks.clear_pass_stack()
        profile_hooks.set_active_sink(self._prev_sink)
        self._prev_sink = None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    def begin_frame(self, *, frame_index: int, tick_index_before_update: int) -> None:
        if not self._active:
            return
        self._current_frame_index = int(frame_index)
        self._current_tick_before_update = int(tick_index_before_update)
        self._draw_calls_total = 0
        self._draw_calls_by_api.clear()
        self._draw_calls_by_pass.clear()
        self._pass_ms.clear()

    def end_frame(
        self,
        *,
        tick_index_after_update: int,
        update_ms: float,
        draw_ms: float,
        frame_ms: float,
    ) -> None:
        if self._current_frame_index is None or self._current_tick_before_update is None:
            return
        snapshot = RenderTelemetryFrameSnapshot(
            frame_index=int(self._current_frame_index),
            tick_index_before_update=int(self._current_tick_before_update),
            tick_index_after_update=int(tick_index_after_update),
            update_ms=float(update_ms),
            draw_ms=float(draw_ms),
            frame_ms=float(frame_ms),
            draw_calls_total=int(self._draw_calls_total),
            draw_calls_by_api={str(key): int(value) for key, value in sorted(self._draw_calls_by_api.items())},
            draw_calls_by_pass={str(key): int(value) for key, value in sorted(self._draw_calls_by_pass.items())},
            pass_ms={str(key): float(value) for key, value in sorted(self._pass_ms.items())},
        )
        self._frames.append(snapshot)
        self._current_frame_index = None
        self._current_tick_before_update = None

    def record_draw_call(self, api_name: str) -> None:
        if self._current_frame_index is None:
            return
        api = str(api_name)
        self._draw_calls_total += 1
        self._draw_calls_by_api[api] += 1
        pass_name = profile_hooks.current_pass_name() or "_unscoped"
        self._draw_calls_by_pass[str(pass_name)] += 1

    def record_pass_duration(self, pass_name: str, duration_ms: float) -> None:
        if self._current_frame_index is None:
            return
        self._pass_ms[str(pass_name)] += float(duration_ms)


__all__ = ["RenderTelemetryFrameSnapshot", "RenderTelemetrySession"]
