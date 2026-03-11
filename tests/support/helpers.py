from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any, Literal, Protocol

import pytest

from grim.rand import CallerStatic

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
        self._history: list[int] = []

    @property
    def state(self) -> int:
        return int(self._state)

    def srand(self, seed: int) -> None:
        self._state = int(seed) & 0xFFFFFFFF
        self._index = 0
        self.calls = 0
        self._history.clear()

    def rand(self, *, caller_static_u32: CallerStatic = None) -> int:
        _ = caller_static_u32
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
        self._history.append(int(value))
        self._state = int(value) & 0xFFFFFFFF
        return int(value)

    def __call__(self, *, caller_static_u32: CallerStatic = None) -> int:
        return self.rand(caller_static_u32=caller_static_u32)

    def draw_hash(self, *, start_call: int = 0) -> str:
        start = max(0, int(start_call))
        values = self._history[start:]
        payload = ",".join(str(int(value) & 0xFFFFFFFF) for value in values)
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


class SupportsRngProgression(Protocol):
    calls: int

    @property
    def state(self) -> int:
        ...


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
    expected_hash: str | None = None,
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
    if expected_hash is not None:
        draw_hash = getattr(rng, "draw_hash", None)
        assert callable(draw_hash), "expected_hash requires rng.draw_hash(...) support"
        assert draw_hash(start_call=int(before_calls)) == str(expected_hash)
