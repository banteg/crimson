from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol


class RenderProfileSink(Protocol):
    def on_pass_duration(self, pass_name: str, duration_ms: float) -> None: ...


_ACTIVE_SINK: RenderProfileSink | None = None
_PASS_STACK: list[tuple[str, int]] = []


def set_active_sink(sink: RenderProfileSink | None) -> RenderProfileSink | None:
    global _ACTIVE_SINK
    prev = _ACTIVE_SINK
    _ACTIVE_SINK = sink
    return prev


def clear_pass_stack() -> None:
    _PASS_STACK.clear()


def current_pass_name() -> str | None:
    if not _PASS_STACK:
        return None
    return str(_PASS_STACK[-1][0])


def begin_pass(name: str) -> None:
    _PASS_STACK.append((str(name), int(time.perf_counter_ns())))


def end_pass(name: str) -> None:
    _ = name
    if not _PASS_STACK:
        return
    pass_name, start_ns = _PASS_STACK.pop()
    duration_ns = max(0, int(time.perf_counter_ns()) - int(start_ns))
    sink = _ACTIVE_SINK
    if sink is None:
        return
    sink.on_pass_duration(str(pass_name), float(duration_ns) / 1_000_000.0)


@contextmanager
def profile_pass(name: str) -> Iterator[None]:
    begin_pass(name)
    try:
        yield
    finally:
        end_pass(name)


__all__ = [
    "RenderProfileSink",
    "begin_pass",
    "clear_pass_stack",
    "current_pass_name",
    "end_pass",
    "profile_pass",
    "set_active_sink",
]
