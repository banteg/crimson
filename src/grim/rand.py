from __future__ import annotations

import os
from collections.abc import Callable
from typing import Protocol, TypeAlias, runtime_checkable

from crimson.rng_caller_static import RngCallerStatic

CallerStatic: TypeAlias = RngCallerStatic | None

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011

RngTraceSink = Callable[[int, int, int, CallerStatic], None]


class MissingRngCallerStaticError(ValueError):
    """Raised when strict RNG tracing sees an untagged gameplay draw."""


@runtime_checkable
class CrandLike(Protocol):
    """Protocol for RNGs that follow the native CRT rand/srand/state contract."""

    @property
    def state(self) -> int: ...

    def srand(self, seed: int) -> None: ...

    def rand(self, *, caller_static_u32: CallerStatic = None) -> int: ...


@runtime_checkable
class RandDrawLike(Protocol):
    """Callable RNG source that accepts optional caller provenance."""

    def __call__(self, *, caller_static_u32: CallerStatic = None) -> int: ...


class CrtRand:
    """MSVCRT-compatible `rand()` LCG used by the original game.

    Matches:
      seed = seed * 214013 + 2531011
      return (seed >> 16) & 0x7fff
    """

    __slots__ = ("_state", "_trace_require_caller_static", "_trace_sink")

    def __init__(self, seed: int | None = None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(4), "little")
        self._state = seed & 0xFFFFFFFF
        self._trace_sink: RngTraceSink | None = None
        self._trace_require_caller_static = False

    @property
    def state(self) -> int:
        return self._state

    def srand(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    @property
    def trace_sink(self) -> RngTraceSink | None:
        return self._trace_sink

    @property
    def trace_require_caller_static(self) -> bool:
        return bool(self._trace_require_caller_static)

    def set_trace_sink(
        self,
        sink: RngTraceSink | None,
        *,
        require_caller_static: bool = False,
    ) -> None:
        self._trace_sink = sink
        self._trace_require_caller_static = bool(require_caller_static)

    def rand(self, *, caller_static_u32: CallerStatic = None) -> int:
        state_before = self._state
        self._state = (self._state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        value = (self._state >> 16) & 0x7FFF
        if caller_static_u32 is not None and not (0 <= caller_static_u32 <= 0xFFFFFFFF):
            raise ValueError(f"caller_static_u32 must be a uint32, got {caller_static_u32}")
        trace_sink = self._trace_sink
        if trace_sink is not None:
            if self._trace_require_caller_static and caller_static_u32 is None:
                raise MissingRngCallerStaticError("strict RNG trace requires caller_static_u32")
            trace_sink(int(state_before), int(self._state), int(value), caller_static_u32)
        return value


class Crand(CrtRand):
    """MSVCRT-compatible `rand()` LCG."""
