from __future__ import annotations

import pytest

from crimson.rng_caller_static import RngCallerStatic
from grim.rand import CRT_RAND_INC, CRT_RAND_MULT, CallerStatic, CrtRand, MissingRngCallerError, RecordingCrand
from tests.support.helpers import ScriptedCrand


def test_crt_rand_trace_sink_receives_caller() -> None:
    rows: list[tuple[int, int, int, CallerStatic]] = []
    rng = CrtRand(0x1234)
    caller = RngCallerStatic.SURVIVAL_UPDATE

    def _sink(
        state_before_u32: int,
        state_after_u32: int,
        value_15: int,
        caller: CallerStatic,
    ) -> None:
        rows.append((state_before_u32, state_after_u32, value_15, caller))

    rng.set_trace_sink(_sink)
    value = rng.rand(caller=caller)

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

    first = rng.rand(caller=RngCallerStatic.SURVIVAL_UPDATE)
    second = rng.rand()

    assert rng.calls == 2
    assert rng.values_since() == [first, second]
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.SURVIVAL_UPDATE, None]
    assert rng.records_since(1)[0].value == second


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
