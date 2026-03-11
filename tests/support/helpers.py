from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Protocol

import pytest

from grim.rand import CallerStatic, RngDrawRecord

ScriptedCrandFallback = Literal["raise", "repeat_last", "zero"]


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

    def __init__(
        self,
        values: int | Sequence[int] | None = None,
        *,
        fallback: ScriptedCrandFallback = "raise",
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

    def rand(self, *, caller: CallerStatic = None) -> int:
        state_before = int(self._shared.state)
        values = self._shared.values
        index = int(self._shared.index)
        fallback = self._shared.fallback

        value: int
        if index < len(values):
            value = int(values[index])
            self._shared.index = index + 1
        elif fallback == "repeat_last" and values:
            value = int(values[-1])
        elif fallback == "zero":
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

    def records_since(self, start_call: int = 0) -> list[RngDrawRecord]:
        start = max(0, int(start_call))
        return list(self._shared.records[start:])

    def values_since(self, start_call: int = 0) -> list[int]:
        return [record.value for record in self.records_since(start_call)]


class SupportsRngProgression(Protocol):
    calls: int

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
