from __future__ import annotations

import os
from collections.abc import Callable
from typing import Protocol, runtime_checkable

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011

RngTraceSink = Callable[[int, int, int], None]


@runtime_checkable
class CrandLike(Protocol):
    """Protocol for RNGs that follow the native CRT rand/srand/state contract."""

    @property
    def state(self) -> int: ...

    def srand(self, seed: int) -> None: ...

    def rand(self) -> int: ...


class CrtRand:
    """MSVCRT-compatible `rand()` LCG used by the original game.

    Matches:
      seed = seed * 214013 + 2531011
      return (seed >> 16) & 0x7fff
    """

    __slots__ = ("_state", "_trace_sink")

    def __init__(self, seed: int | None = None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(4), "little")
        self._state = seed & 0xFFFFFFFF
        self._trace_sink: RngTraceSink | None = None

    @property
    def state(self) -> int:
        return self._state

    def srand(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    @property
    def trace_sink(self) -> RngTraceSink | None:
        return self._trace_sink

    def set_trace_sink(self, sink: RngTraceSink | None) -> None:
        self._trace_sink = sink

    def rand(self) -> int:
        state_before = self._state
        self._state = (self._state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        value = (self._state >> 16) & 0x7FFF
        trace_sink = self._trace_sink
        if trace_sink is not None:
            trace_sink(int(state_before), int(self._state), int(value))
        return value


class Crand(CrtRand):
    """MSVCRT-compatible `rand()` LCG."""
