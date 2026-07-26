from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Exact static caller address when known.
type CallerStatic = int
type RecordedCallerStatic = CallerStatic | None

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011

RngTraceSink = Callable[[int, int, int, RecordedCallerStatic], None]


@dataclass(frozen=True, slots=True)
class RngDrawRecord:
    state_before: int
    state_after: int
    value: int
    caller: RecordedCallerStatic


class MissingRngCallerError(ValueError):
    """Raised when strict RNG tracing sees an untagged gameplay draw."""


@runtime_checkable
class CrandLike(Protocol):
    """Protocol for RNGs that follow the native CRT rand/srand/state contract."""

    @property
    def state(self) -> int: ...

    def srand(self, seed: int) -> None: ...

    def rand(self) -> int: ...

    def rand_tagged(self, caller: CallerStatic) -> int: ...

    def advance(self, draws: int) -> None: ...


class CrtRand:
    """MSVCRT-compatible `rand()` LCG used by the original game.

    Matches:
      seed = seed * 214013 + 2531011
      return (seed >> 16) & 0x7fff
    """

    __slots__ = ("_state", "_trace_require_caller", "_trace_sink")

    def __init__(self, seed: int | None = None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(4), "little")
        self._state = seed & 0xFFFFFFFF
        self._trace_sink: RngTraceSink | None = None
        self._trace_require_caller = False

    @property
    def state(self) -> int:
        return self._state

    def srand(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    def advance(self, draws: int) -> None:
        steps = int(draws)
        if steps < 0:
            raise ValueError(f"draws must be >= 0, got {draws}")
        state = self._state
        for _ in range(steps):
            state = (state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        self._state = state

    @property
    def trace_sink(self) -> RngTraceSink | None:
        return self._trace_sink

    @property
    def trace_require_caller(self) -> bool:
        return bool(self._trace_require_caller)

    def set_trace_sink(
        self,
        sink: RngTraceSink | None,
        *,
        require_caller: bool = False,
    ) -> None:
        self._trace_sink = sink
        self._trace_require_caller = bool(require_caller)

    def _draw(self, caller: CallerStatic | None) -> int:
        state_before = self._state
        self._state = (self._state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        value = (self._state >> 16) & 0x7FFF
        if caller is not None and not (0 <= caller <= 0xFFFFFFFF):
            raise ValueError(f"caller must be a uint32, got {caller}")
        trace_sink = self._trace_sink
        if trace_sink is not None:
            if self._trace_require_caller and caller is None:
                raise MissingRngCallerError("strict RNG trace requires caller")
            trace_sink(int(state_before), int(self._state), int(value), caller)
        return value

    def rand(self) -> int:
        return self._draw(None)

    def rand_tagged(self, caller: CallerStatic) -> int:
        return self._draw(int(caller))


class Crand(CrtRand):
    """MSVCRT-compatible `rand()` LCG."""


class _RecordingState:
    __slots__ = ("base", "records")

    def __init__(self, base: CrandLike) -> None:
        self.base = base
        self.records: list[RngDrawRecord] = []


class RecordingCrand:
    __slots__ = ("_shared",)

    def __init__(
        self,
        base: CrandLike,
        _shared: _RecordingState | None = None,
    ) -> None:
        self._shared = _RecordingState(base) if _shared is None else _shared

    @property
    def state(self) -> int:
        return int(self._shared.base.state)

    @property
    def calls(self) -> int:
        return len(self._shared.records)

    @property
    def records(self) -> tuple[RngDrawRecord, ...]:
        return tuple(self._shared.records)

    def srand(self, seed: int) -> None:
        self._shared.base.srand(int(seed))
        self._shared.records.clear()

    def rand(self) -> int:
        state_before = int(self._shared.base.state)
        value = self._shared.base.rand()
        state_after = int(self._shared.base.state)
        self._shared.records.append(
            RngDrawRecord(
                state_before=state_before,
                state_after=state_after,
                value=value,
                caller=None,
            ),
        )
        return value

    def rand_tagged(self, caller: CallerStatic) -> int:
        state_before = int(self._shared.base.state)
        value = self._shared.base.rand_tagged(int(caller))
        state_after = int(self._shared.base.state)
        self._shared.records.append(
            RngDrawRecord(
                state_before=state_before,
                state_after=state_after,
                value=value,
                caller=int(caller),
            ),
        )
        return value

    def advance(self, draws: int) -> None:
        steps = int(draws)
        if steps < 0:
            raise ValueError(f"draws must be >= 0, got {draws}")
        self._shared.base.advance(steps)

    def records_since(self, start_call: int = 0) -> list[RngDrawRecord]:
        start = max(0, int(start_call))
        return list(self._shared.records[start:])

    def values_since(self, start_call: int = 0) -> list[int]:
        return [record.value for record in self.records_since(start_call)]
