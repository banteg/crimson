from __future__ import annotations

import math

import pytest

from crimson.math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    f32,
    heading_add_pi_f32,
    heading_from_delta_f32,
    heading_to_direction_f32,
)


def test_heading_from_delta_uses_native_half_pi_constant() -> None:
    heading = heading_from_delta_f32(dx=1.0, dy=0.0)
    assert heading == pytest.approx(NATIVE_HALF_PI, abs=1e-7)
    assert heading == f32(heading)


def test_heading_from_delta_left_axis_prefers_negative_half_pi_representation() -> None:
    heading = heading_from_delta_f32(dx=-1.0, dy=0.0)
    assert heading < 0.0
    assert heading == pytest.approx(-NATIVE_HALF_PI, abs=2e-7)
    assert heading == f32(heading)


def test_heading_from_delta_remaps_near_axis_tiny_dy_to_negative_branch() -> None:
    heading = heading_from_delta_f32(dx=-696.0988159179688, dy=0.000457763671875)
    assert heading < 0.0
    assert heading == pytest.approx(-NATIVE_HALF_PI, abs=2e-6)
    assert heading == f32(heading)


def test_heading_from_delta_keeps_positive_branch_for_larger_dy() -> None:
    heading = heading_from_delta_f32(dx=-1.0, dy=0.001)
    assert heading > 0.0
    assert heading > (NATIVE_HALF_PI * 2.0)
    assert heading == f32(heading)


def test_heading_add_pi_is_float32_and_does_not_wrap() -> None:
    heading = heading_add_pi_f32(NATIVE_PI)
    assert heading == pytest.approx(f32(NATIVE_PI + NATIVE_PI), abs=1e-7)
    assert heading > math.pi
    assert heading == f32(heading)


def test_heading_to_direction_matches_native_heading_basis() -> None:
    direction = heading_to_direction_f32(NATIVE_HALF_PI)
    assert direction.x == pytest.approx(1.0, abs=1e-7)
    assert direction.y == pytest.approx(0.0, abs=1e-7)
    assert direction.x == f32(direction.x)
    assert direction.y == f32(direction.y)
