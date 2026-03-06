from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from typing import Protocol, TypeVar, runtime_checkable

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011

RngTraceSink = Callable[[int, int, int], None]
_T = TypeVar("_T")


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

    def getrandbits(self, k: int) -> int:
        k = int(k)
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        value = 0
        bit_offset = 0
        while bit_offset < k:
            value |= int(self.rand()) << bit_offset
            bit_offset += 15
        return value & ((1 << k) - 1)

    def _randbelow(self, stop: int) -> int:
        stop = int(stop)
        if stop <= 0:
            raise ValueError("empty range for randrange()")
        if stop <= 0x8000:
            return int(self.rand()) % stop
        return int(self.getrandbits(int(stop).bit_length())) % stop

    def randrange(self, start: int, stop: int | None = None, step: int = 1) -> int:
        step = int(step)
        if step == 0:
            raise ValueError("zero step for randrange()")
        if stop is None:
            start, stop = 0, int(start)
        values = range(int(start), int(stop), int(step))
        if not values:
            raise ValueError("empty range for randrange()")
        return int(values[self._randbelow(len(values))])

    def choice(self, seq: Sequence[_T]) -> _T:
        if not seq:
            raise IndexError("Cannot choose from an empty sequence")
        return seq[self._randbelow(len(seq))]


class Crand(CrtRand):
    """MSVCRT-compatible `rand()` LCG."""
