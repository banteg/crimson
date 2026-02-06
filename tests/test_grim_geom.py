from __future__ import annotations

import math

from grim.geom import Vec2


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


def test_vec2_normalize_ip_mutates_in_place() -> None:
    vec = Vec2(3.0, 4.0)

    result = vec.normalize_ip()

    assert result is vec
    assert math.isclose(vec.x, 0.6, abs_tol=1e-9)
    assert math.isclose(vec.y, 0.8, abs_tol=1e-9)
    assert math.isclose(vec.length(), 1.0, abs_tol=1e-9)


def test_vec2_normalization_of_zero_vector_returns_zero() -> None:
    vec = Vec2()

    normalized = vec.normalized()
    result = vec.normalize_ip()

    assert math.isclose(normalized.x, 0.0, abs_tol=1e-9)
    assert math.isclose(normalized.y, 0.0, abs_tol=1e-9)
    assert result is vec
    assert math.isclose(vec.x, 0.0, abs_tol=1e-9)
    assert math.isclose(vec.y, 0.0, abs_tol=1e-9)


def test_vec2_angle_helpers_round_trip() -> None:
    angle = 1.2

    vec = Vec2.from_angle(angle)

    assert math.isclose(vec.to_angle(), angle, abs_tol=1e-9)


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
