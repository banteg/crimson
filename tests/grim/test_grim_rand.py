from __future__ import annotations

import pytest

from grim.rand import CRT_RAND_INC, CRT_RAND_MULT, CrtRand, MissingRngCallerStaticError


def test_crt_rand_trace_sink_receives_caller_static_u32() -> None:
    rows: list[tuple[int, int, int, int | None]] = []
    rng = CrtRand(0x1234)

    def _sink(state_before_u32: int, state_after_u32: int, value_15: int, caller_static_u32: int | None) -> None:
        rows.append((state_before_u32, state_after_u32, value_15, caller_static_u32))

    rng.set_trace_sink(_sink)
    value = rng.rand(caller_static_u32=0x00430B88)

    expected_after = (0x1234 * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
    assert value == ((expected_after >> 16) & 0x7FFF)
    assert rows == [(0x1234, expected_after, value, 0x00430B88)]


def test_crt_rand_strict_trace_requires_caller_static_u32() -> None:
    rng = CrtRand(0x1234)
    rng.set_trace_sink(lambda *_args: None, require_caller_static=True)

    with pytest.raises(MissingRngCallerStaticError, match="caller_static_u32"):
        rng.rand()
