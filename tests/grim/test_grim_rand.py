from __future__ import annotations

import pytest

from crimson.rng_caller_static import RngCallerStatic
from grim.rand import CRT_RAND_INC, CRT_RAND_MULT, CallerStatic, CrtRand, MissingRngCallerError


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
