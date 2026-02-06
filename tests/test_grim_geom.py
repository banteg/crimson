from __future__ import annotations

import math

from grim.geom import Rect, Vec2


def test_vec2_length_and_length_sq() -> None:
    vec = Vec2(3.0, 4.0)

    assert math.isclose(vec.length_sq(), 25.0, abs_tol=1e-9)
    assert math.isclose(vec.length(), 5.0, abs_tol=1e-9)


def test_vec2_normalized_returns_unit_vector_without_mutating_original() -> None:
    vec = Vec2(3.0, 4.0)

    normalized = vec.normalized()

    assert normalized is not vec
    assert math.isclose(normalized.x, 0.6, abs_tol=1e-9)
    assert math.isclose(normalized.y, 0.8, abs_tol=1e-9)
    assert math.isclose(normalized.length(), 1.0, abs_tol=1e-9)
    assert math.isclose(vec.x, 3.0, abs_tol=1e-9)
    assert math.isclose(vec.y, 4.0, abs_tol=1e-9)


def test_vec2_normalized_returns_normalized_copy() -> None:
    vec = Vec2(3.0, 4.0)

    result = vec.normalized()

    assert result is not vec
    assert math.isclose(result.x, 0.6, abs_tol=1e-9)
    assert math.isclose(result.y, 0.8, abs_tol=1e-9)
    assert math.isclose(result.length(), 1.0, abs_tol=1e-9)
    assert math.isclose(vec.x, 3.0, abs_tol=1e-9)
    assert math.isclose(vec.y, 4.0, abs_tol=1e-9)


def test_vec2_normalization_of_zero_vector_returns_zero() -> None:
    vec = Vec2()

    normalized = vec.normalized()

    assert math.isclose(normalized.x, 0.0, abs_tol=1e-9)
    assert math.isclose(normalized.y, 0.0, abs_tol=1e-9)


def test_vec2_angle_helpers_round_trip() -> None:
    angle = 1.2

    vec = Vec2.from_angle(angle)

    assert math.isclose(vec.to_angle(), angle, abs_tol=1e-9)


def test_vec2_polar_helpers_round_trip() -> None:
    angle = 1.2
    radius = 3.5

    vec = Vec2.from_polar(angle, radius)
    polar_angle, polar_radius = vec.to_polar()

    assert math.isclose(polar_angle, angle, abs_tol=1e-9)
    assert math.isclose(polar_radius, radius, abs_tol=1e-9)


def test_vec2_heading_helpers_round_trip() -> None:
    heading = 1.2

    vec = Vec2.from_heading(heading)

    assert math.isclose(vec.to_heading(), heading, abs_tol=1e-9)


def test_vec2_rotated() -> None:
    vec = Vec2(1.0, 0.0)

    rotated = vec.rotated(math.pi / 2.0)

    assert math.isclose(rotated.x, 0.0, abs_tol=1e-9)
    assert math.isclose(rotated.y, 1.0, abs_tol=1e-9)


def test_vec2_clamp_rect() -> None:
    vec = Vec2(-5.0, 20.0)

    clamped = vec.clamp_rect(0.0, 1.0, 10.0, 8.0)

    assert math.isclose(clamped.x, 0.0, abs_tol=1e-9)
    assert math.isclose(clamped.y, 8.0, abs_tol=1e-9)


def test_vec2_distance_sq() -> None:
    a = Vec2(1.0, 2.0)
    b = Vec2(4.0, 6.0)

    assert math.isclose(Vec2.distance_sq(a, b), 25.0, abs_tol=1e-9)


def test_vec2_distance_to() -> None:
    a = Vec2(1.0, 2.0)
    b = Vec2(4.0, 6.0)

    assert math.isclose(a.distance_to(b), 5.0, abs_tol=1e-9)


def test_vec2_direction_to() -> None:
    a = Vec2(2.0, 3.0)
    b = Vec2(5.0, 7.0)

    direction = a.direction_to(b)

    assert math.isclose(direction.length(), 1.0, abs_tol=1e-9)
    assert math.isclose(direction.x, 0.6, abs_tol=1e-9)
    assert math.isclose(direction.y, 0.8, abs_tol=1e-9)


def test_vec2_direction_to_returns_zero_when_points_are_equal() -> None:
    point = Vec2(4.0, -1.5)

    assert point.direction_to(point) == Vec2()


def test_vec2_lerp() -> None:
    a = Vec2(1.0, 5.0)
    b = Vec2(5.0, 1.0)

    lerped = Vec2.lerp(a, b, 0.25)

    assert math.isclose(lerped.x, 2.0, abs_tol=1e-9)
    assert math.isclose(lerped.y, 4.0, abs_tol=1e-9)


def test_vec2_operator_helpers() -> None:
    a = Vec2(1.0, 2.0)
    b = Vec2(3.0, 4.0)

    assert a + b == Vec2(4.0, 6.0)
    assert b - a == Vec2(2.0, 2.0)
    assert a * 2.0 == Vec2(2.0, 4.0)
    assert 2.0 * a == Vec2(2.0, 4.0)


def test_vec2_component_helpers() -> None:
    a = Vec2(6.0, 8.0)
    b = Vec2(2.0, 4.0)

    assert a.mul_components(b) == Vec2(12.0, 32.0)
    assert a.div_components(b) == Vec2(3.0, 2.0)
    assert math.isclose(a.avg_component(), 7.0, abs_tol=1e-9)


def test_vec2_perpendicular_helpers() -> None:
    vec = Vec2(3.0, -2.0)

    assert vec.perp_left() == Vec2(2.0, 3.0)
    assert vec.perp_right() == Vec2(-2.0, -3.0)


def test_vec2_offset_helper() -> None:
    vec = Vec2(3.0, -2.0)

    assert vec.offset(dx=5.0, dy=-1.5) == Vec2(8.0, -3.5)


def test_vec2_to_rl() -> None:
    vec = Vec2(1.25, -4.5)

    result = vec.to_rl()

    assert hasattr(result, "x")
    assert hasattr(result, "y")
    assert math.isclose(float(result.x), 1.25, abs_tol=1e-9)
    assert math.isclose(float(result.y), -4.5, abs_tol=1e-9)


def test_rect_properties_and_helpers() -> None:
    rect = Rect(10.0, 20.0, 30.0, 40.0)

    assert rect.top_left == Vec2(10.0, 20.0)
    assert rect.size == Vec2(30.0, 40.0)
    assert math.isclose(rect.right, 40.0, abs_tol=1e-9)
    assert math.isclose(rect.bottom, 60.0, abs_tol=1e-9)
    assert rect.center == Vec2(25.0, 40.0)


def test_rect_offset_and_inset() -> None:
    rect = Rect(10.0, 20.0, 30.0, 40.0)

    assert rect.offset(dx=2.0, dy=-3.0) == Rect(12.0, 17.0, 30.0, 40.0)
    assert rect.inset(dx=5.0, dy=4.0) == Rect(15.0, 24.0, 20.0, 32.0)
    assert rect.inset(dx=100.0, dy=100.0) == Rect(110.0, 120.0, 0.0, 0.0)


def test_rect_contains_edges() -> None:
    rect = Rect(10.0, 20.0, 30.0, 40.0)

    assert rect.contains(Vec2(10.0, 20.0))
    assert rect.contains(Vec2(40.0, 60.0))
    assert not rect.contains(Vec2(9.99, 20.0))
    assert not rect.contains(Vec2(40.01, 60.0))


def test_rect_conversion_helpers() -> None:
    rect = Rect.from_pos_size(Vec2(1.0, 2.0), Vec2(3.0, 4.0))
    round_trip = Rect.from_xywh(rect.to_rl())

    assert rect == Rect(1.0, 2.0, 3.0, 4.0)
    assert round_trip == rect
