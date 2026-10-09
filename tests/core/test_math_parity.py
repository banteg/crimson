from __future__ import annotations

import random
import struct

import pytest

from crimson.math_parity import (
    f32,
    heading_from_delta_f32,
    x87_pc24_mul,
    x87_pc24_mul_chain,
)


def test_heading_from_delta_left_axis_preserves_positive_zero_branch() -> None:
    heading = heading_from_delta_f32(dx=-1.0, dy=0.0)
    assert heading == 4.71238899230957
    assert heading == f32(heading)


def test_heading_from_delta_left_axis_preserves_negative_zero_branch() -> None:
    heading = heading_from_delta_f32(dx=-1.0, dy=-0.0)
    assert heading == -1.570796251296997
    assert heading == f32(heading)


def test_heading_from_delta_keeps_small_positive_dy_positive() -> None:
    dx = -696.0988159179688
    dy = 0.000457763671875
    heading = heading_from_delta_f32(dx=dx, dy=dy)
    assert heading == 4.712388515472412
    assert heading == f32(heading)


def test_x87_pc24_mul_chain_matches_stepwise_bits_and_overflow() -> None:
    rng = random.Random(0x50433234)
    edges = (-0.0, 0.0, 1.0, -1.0, 1e-45, 3.4028234663852886e38, float("inf"), float("nan"))
    cases: list[tuple[float, tuple[float, ...]]] = [(first, ()) for first in (*edges, 1.0000000001)]
    cases += [(first, (factor,)) for first in edges for factor in edges]
    cases += [
        (rng.uniform(-100.0, 100.0), tuple(rng.uniform(-100.0, 100.0) for _ in range(rng.randrange(9))))
        for _ in range(10_000)
    ]
    for first, factors in cases:
        expected = float(first)
        try:
            for factor in factors:
                expected = x87_pc24_mul(expected, factor)
        except OverflowError:
            with pytest.raises(OverflowError):
                x87_pc24_mul_chain(first, *factors)
            continue
        actual = x87_pc24_mul_chain(first, *factors)
        assert struct.pack("<d", actual) == struct.pack("<d", expected), (first, factors)
