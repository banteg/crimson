from __future__ import annotations

from grim.geom import Rect, Vec2
from tests.support.helpers import assert_float_close


def test_vec2_normalized_returns_unit_vector_without_mutating_original() -> None:
    vec = Vec2(3.0, 4.0)

    normalized = vec.normalized()

    assert normalized is not vec
    assert normalized == Vec2(0.6000000238418579, 0.800000011920929)
    assert normalized.length() == 1.000000023841858
    assert_float_close(vec.x, 3.0)
    assert_float_close(vec.y, 4.0)


def test_vec2_normalization_of_zero_vector_returns_zero() -> None:
    vec = Vec2()

    normalized = vec.normalized()

    assert_float_close(normalized.x, 0.0)
    assert_float_close(normalized.y, 0.0)


def test_vec2_normalization_preserves_native_near_unit_vector() -> None:
    normalized = Vec2(1.0, 0.0001).normalized()

    assert normalized == Vec2(1.0, 9.999999747378752e-05)


def test_vec2_normalization_zeros_native_subnormal_length() -> None:
    assert Vec2(1e-20, 0.0).normalized() == Vec2()


def test_rect_contains_edges() -> None:
    rect = Rect(10.0, 20.0, 30.0, 40.0)

    assert rect.contains(Vec2(10.0, 20.0))
    assert rect.contains(Vec2(40.0, 60.0))
    assert not rect.contains(Vec2(9.99, 20.0))
    assert not rect.contains(Vec2(40.01, 60.0))
