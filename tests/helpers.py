from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

import pytest

MockCrandFallback = Literal["repeat_last", "zero", "cycle"]


class MockCrand:
    """Deterministic test double for `CrandLike` that can be fixed or scripted."""

    def __init__(self, values: int | Sequence[int] | None = None, *, fallback: MockCrandFallback = "repeat_last") -> None:
        if values is None:
            normalized: list[int] = []
        elif isinstance(values, int):
            normalized = [int(values)]
        else:
            normalized = [int(value) for value in values]

        self._values = normalized
        self._fallback = fallback
        self._index = 0
        self._state = 0
        self.calls = 0

    @property
    def state(self) -> int:
        return int(self._state)

    def srand(self, seed: int) -> None:
        self._state = int(seed) & 0xFFFFFFFF
        self._index = 0
        self.calls = 0

    def rand(self) -> int:
        value: int
        if self._index < len(self._values):
            value = int(self._values[self._index])
            self._index += 1
        elif self._fallback == "cycle" and self._values:
            value = int(self._values[self._index % len(self._values)])
            self._index += 1
        elif self._fallback == "repeat_last" and self._values:
            value = int(self._values[-1])
        else:
            value = 0

        self.calls += 1
        self._state = int(value) & 0xFFFFFFFF
        return int(value)

    def __call__(self) -> int:
        return self.rand()


def assert_float_close(actual: float, expected: float) -> None:
    assert float(actual) == pytest.approx(float(expected), abs=1e-6)
