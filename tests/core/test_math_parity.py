from __future__ import annotations

import math

from crimson.math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    NATIVE_TAU,
    f32,
    heading_add_pi_f32,
    heading_from_delta_f32,
    heading_to_direction_f32,
)
from tests.support.helpers import assert_float_close


def test_heading_from_delta_uses_native_half_pi_constant() -> None:
    heading = heading_from_delta_f32(dx=1.0, dy=0.0)
    assert_float_close(heading, NATIVE_HALF_PI)
    assert heading == f32(heading)


def test_heading_from_delta_left_axis_prefers_negative_half_pi_representation() -> None:
    heading = heading_from_delta_f32(dx=-1.0, dy=0.0)
    assert heading < 0.0
    expected = f32(f32(math.atan2(0.0, -1.0) + NATIVE_HALF_PI) - NATIVE_TAU)
    assert_float_close(heading, expected)
    assert heading == f32(heading)


def test_heading_from_delta_remaps_near_axis_tiny_dy_to_negative_branch() -> None:
    dx = -696.0988159179688
    dy = 0.000457763671875
    heading = heading_from_delta_f32(dx=dx, dy=dy)
    assert heading < 0.0
    expected = f32(f32(math.atan2(dy, dx) + NATIVE_HALF_PI) - NATIVE_TAU)
    assert_float_close(heading, expected)
    assert heading == f32(heading)


def test_heading_from_delta_keeps_positive_branch_for_larger_dy() -> None:
    heading = heading_from_delta_f32(dx=-1.0, dy=0.001)
    assert heading > 0.0
    assert heading > (NATIVE_HALF_PI * 2.0)
    assert heading == f32(heading)


def test_heading_add_pi_is_float32_and_does_not_wrap() -> None:
    heading = heading_add_pi_f32(NATIVE_PI)
    assert_float_close(heading, f32(NATIVE_PI + NATIVE_PI))
    assert heading > math.pi
    assert heading == f32(heading)


def test_heading_to_direction_matches_native_heading_basis() -> None:
    direction = heading_to_direction_f32(NATIVE_HALF_PI)
    assert_float_close(direction.x, 1.0)
    assert_float_close(direction.y, 0.0)
    assert direction.x == f32(direction.x)
    assert direction.y == f32(direction.y)


def test_heading_to_direction_rounds_angle_subtraction_before_trig() -> None:
    direction = heading_to_direction_f32(6.330781936645508)

    assert direction.x == 0.04757849872112274
    assert direction.y == -0.9988675117492676
