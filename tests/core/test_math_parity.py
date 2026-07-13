from __future__ import annotations

import math

from crimson.math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    f32,
    heading_add_pi_f32,
    heading_from_delta_f32,
    heading_to_direction_f32,
    native_fire_muzzle_pos,
    native_shot_angle_from_jitter_draws,
    x87_fpatan,
    x87_pc24_cos_mul,
    x87_pc24_mul_chain,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_heading_from_delta_uses_native_half_pi_constant() -> None:
    heading = heading_from_delta_f32(dx=1.0, dy=0.0)
    assert_float_close(heading, NATIVE_HALF_PI)
    assert heading == f32(heading)


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


def test_x87_pc24_helpers_preserve_operation_order() -> None:
    radians = x87_pc24_sub(6.330781936645508, NATIVE_HALF_PI)

    assert radians == 4.759985446929932
    assert x87_pc24_cos_mul(radians, 14.256000518798828, 0.05900000408291817, 9.0) == 0.3601662218570709
    assert x87_pc24_sin_mul(radians, 14.256000518798828, 0.05900000408291817, 9.0) == -7.56136417388916
    assert x87_pc24_mul_chain(-0.7071233067741324, 2.0, 3.1415627002716064, 2.0, 7.957746982574463) == -70.7116470336914


def test_x87_fpatan_uses_pc24_rounded_input_arithmetic() -> None:
    dy = x87_pc24_sub(868.6661376953125, 597.0)
    dx = x87_pc24_sub(275.0183410644531, 821.0)
    atan = x87_fpatan(dy, dx)

    assert x87_pc24_sub(atan, NATIVE_HALF_PI) == 1.1090916395187378


def test_native_fire_muzzle_uses_combined_angle_before_trig() -> None:
    muzzle = native_fire_muzzle_pos(
        Vec2(137.84991455078125, 935.0262451171875),
        -4.14423131942749,
    )

    assert muzzle == Vec2(152.47727966308594, 941.5100708007812)


def test_native_shot_jitter_preserves_fpatan_branch_and_pc24_rounding() -> None:
    angle = native_shot_angle_from_jitter_draws(
        aim=Vec2(200.0, 100.0),
        player_pos=Vec2(100.0, 100.0),
        spread_heat=0.2,
        dir_draw=65,
        mag_draw=3,
    )

    assert angle == -4.71196985244751
