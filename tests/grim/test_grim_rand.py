from __future__ import annotations

import pytest

from grim.rand import (
    CRT_RAND_INC,
    CRT_RAND_MULT,
    CrtRand,
    MissingRngCallerError,
    RecordedCallerStatic,
    RecordingCrand,
)
from tests.support.helpers import ScriptedCrand


def test_crt_rand_trace_sink_receives_caller() -> None:
    rows: list[tuple[int, int, int, RecordedCallerStatic]] = []
    rng = CrtRand(0x1234)
    caller = 0x0040ABCD

    def _sink(
        state_before_u32: int,
        state_after_u32: int,
        value_15: int,
        caller: RecordedCallerStatic,
    ) -> None:
        rows.append((state_before_u32, state_after_u32, value_15, caller))

    rng.set_trace_sink(_sink)
    value = rng.rand_tagged(caller)

    expected_after = (0x1234 * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
    assert value == ((expected_after >> 16) & 0x7FFF)
    assert rows == [(0x1234, expected_after, value, caller)]


def test_crt_rand_strict_trace_requires_caller() -> None:
    rng = CrtRand(0x1234)
    rng.set_trace_sink(lambda *_args: None, require_caller=True)

    with pytest.raises(MissingRngCallerError, match="caller"):
        rng.rand()


def test_recording_crand_records_history() -> None:
    rng = RecordingCrand(CrtRand(0x1234))
    caller = 0x0040ABCD

    first = rng.rand_tagged(caller)
    second = rng.rand()

    assert rng.calls == 2
    assert rng.values_since() == [first, second]
    assert [record.caller for record in rng.records_since()] == [caller, None]
    assert rng.records_since(1)[0].value == second


@pytest.mark.parametrize("seed", [0, 1, 0x1234, 0xDEADBEEF])
@pytest.mark.parametrize("draws", [0, 1, 2, 5, 37])
def test_crt_rand_advance_matches_repeated_rand(seed: int, draws: int) -> None:
    advanced = CrtRand(seed)
    stepped = CrtRand(seed)

    advanced.advance(draws)
    for _ in range(draws):
        stepped.rand()

    assert int(advanced.state) == int(stepped.state)


def test_crt_rand_advance_is_silent_for_trace_sink() -> None:
    rows: list[tuple[int, int, int, RecordedCallerStatic]] = []
    rng = CrtRand(0x1234)
    rng.set_trace_sink(lambda before, after, value, caller: rows.append((before, after, value, caller)))

    rng.advance(5)

    assert rows == []


def test_recording_crand_advance_is_silent() -> None:
    rng = RecordingCrand(CrtRand(0x1234))

    rng.advance(5)

    assert rng.calls == 0
    assert rng.records_since() == []


def test_scripted_crand_advance_is_silent() -> None:
    rng = ScriptedCrand([3, 5], fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    rng.advance(3)

    assert rng.calls == 0
    assert rng.records_since() == []
    assert int(rng.state) == 5


def test_crt_rand_advance_rejects_negative_draws() -> None:
    rng = CrtRand(0x1234)

    with pytest.raises(ValueError, match="draws must be >= 0"):
        rng.advance(-1)


def test_scripted_crand_raises_on_exhaustion_by_default() -> None:
    rng = ScriptedCrand([7])

    assert rng.rand() == 7
    with pytest.raises(IndexError, match="exhausted"):
        rng.rand()


def test_scripted_crand_repeat_last_is_explicit() -> None:
    rng = ScriptedCrand([3, 5], fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    assert rng.rand() == 3
    assert rng.rand() == 5
    assert rng.rand() == 5
    assert rng.values_since() == [3, 5, 5]
