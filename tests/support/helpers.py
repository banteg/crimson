from __future__ import annotations

from collections.abc import Sequence
from enum import Enum, auto
from typing import Any, Protocol

import pytest

from grim.rand import CallerStatic, RngDrawRecord


class ScriptedCrandFallback(Enum):
    RAISE = auto()
    REPEAT_LAST = auto()
    ZERO = auto()


class _ScriptedCrandState:
    __slots__ = ("fallback", "index", "records", "state", "values")

    def __init__(self, values: Sequence[int], fallback: ScriptedCrandFallback) -> None:
        self.values = [int(value) for value in values]
        self.fallback = fallback
        self.index = 0
        self.records: list[RngDrawRecord] = []
        self.state = 0


class ScriptedCrand:
    """Deterministic scripted `CrandLike` for tests that need exact draw sequences."""

    Fallback = ScriptedCrandFallback

    def __init__(
        self,
        values: int | Sequence[int] | None = None,
        *,
        fallback: ScriptedCrandFallback = ScriptedCrandFallback.RAISE,
        _shared: _ScriptedCrandState | None = None,
    ) -> None:
        if values is None:
            normalized: list[int] = []
        elif isinstance(values, int):
            normalized = [int(values)]
        else:
            normalized = [int(value) for value in values]

        self._shared = _ScriptedCrandState(normalized, fallback) if _shared is None else _shared

    @property
    def state(self) -> int:
        return int(self._shared.state)

    @property
    def calls(self) -> int:
        return len(self._shared.records)

    @property
    def records(self) -> tuple[RngDrawRecord, ...]:
        return tuple(self._shared.records)

    def srand(self, seed: int) -> None:
        self._shared.state = int(seed) & 0xFFFFFFFF
        self._shared.index = 0
        self._shared.records.clear()

    def _next_value(self, caller: CallerStatic | None) -> int:
        state_before = int(self._shared.state)
        values = self._shared.values
        index = int(self._shared.index)
        fallback = self._shared.fallback

        value: int
        if index < len(values):
            value = int(values[index])
            self._shared.index = index + 1
        elif fallback is ScriptedCrandFallback.REPEAT_LAST and values:
            value = int(values[-1])
        elif fallback is ScriptedCrandFallback.ZERO:
            value = 0
        else:
            raise IndexError("scripted RNG exhausted")

        state_after = int(value) & 0xFFFFFFFF
        self._shared.state = state_after
        self._shared.records.append(
            RngDrawRecord(
                state_before=state_before,
                state_after=state_after,
                value=int(value),
                caller=caller,
            ),
        )
        return int(value)

    def rand(self) -> int:
        return self._next_value(None)

    def rand_tagged(self, caller: CallerStatic) -> int:
        return self._next_value(int(caller))

    def advance(self, draws: int) -> None:
        steps = int(draws)
        if steps < 0:
            raise ValueError(f"draws must be >= 0, got {draws}")
        values = self._shared.values
        for _ in range(steps):
            index = int(self._shared.index)
            fallback = self._shared.fallback
            if index < len(values):
                value = int(values[index])
                self._shared.index = index + 1
            elif fallback is ScriptedCrandFallback.REPEAT_LAST and values:
                value = int(values[-1])
            elif fallback is ScriptedCrandFallback.ZERO:
                value = 0
            else:
                raise IndexError("scripted RNG exhausted")
            self._shared.state = int(value) & 0xFFFFFFFF

    def records_since(self, start_call: int = 0) -> list[RngDrawRecord]:
        start = max(0, int(start_call))
        return list(self._shared.records[start:])

    def values_since(self, start_call: int = 0) -> list[int]:
        return [record.value for record in self.records_since(start_call)]


class SupportsRngProgression(Protocol):
    @property
    def calls(self) -> int: ...

    @property
    def state(self) -> int: ...


def assert_float_close(actual: Any, expected: Any) -> None:
    assert float(actual) == pytest.approx(float(expected), abs=1e-9)


def assert_rng_progression(
    rng: SupportsRngProgression,
    *,
    before_calls: int,
    before_state: int,
    expected_draws: int | None = None,
    min_draws: int | None = None,
    expected_after_state: int | None = None,
) -> None:
    assert rng.calls >= int(before_calls)
    draws = int(rng.calls) - int(before_calls)
    after_state = int(rng.state)

    if expected_draws is not None:
        assert draws == int(expected_draws)
    if min_draws is not None:
        assert draws >= int(min_draws)
    if expected_after_state is not None:
        assert after_state == int(expected_after_state)
    elif draws == 0:
        assert after_state == int(before_state)
