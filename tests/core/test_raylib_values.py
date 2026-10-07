from __future__ import annotations

import gc

import pytest
from raylib import ffi

from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2


def _bytes(value: rl.Color | rl.Rectangle | rl.Vector2) -> bytes:
    return bytes(ffi.buffer(ffi.addressof(value), ffi.sizeof(value)))


@pytest.mark.parametrize("args", [(0, 0, 0, 0), (255, 255, 255, 255), (77, 153, 204, 37)])
def test_color_value_matches_pyray_and_owns_its_storage(args: tuple[int, int, int, int]) -> None:
    expected = _bytes(rl.Color(*args))
    actual = rl_color(*args)
    gc.collect()
    assert _bytes(actual) == expected


@pytest.mark.parametrize("args", [(0.0, -0.0, 1.0, 2.0), (-1024.25, 768.5, 80.1, 90.2), (1e-40, -1e-40, 0.1, 0.3)])
def test_rectangle_value_matches_pyray_float_bits(args: tuple[float, float, float, float]) -> None:
    expected = _bytes(rl.Rectangle(*args))
    actual = rl_rectangle(*args)
    gc.collect()
    assert _bytes(actual) == expected


@pytest.mark.parametrize("args", [(0.0, -0.0), (-1024.25, 768.5), (1e-40, -1e-40), (0.1, 0.3)])
def test_vector_value_matches_pyray_float_bits(args: tuple[float, float]) -> None:
    expected = _bytes(rl.Vector2(*args))
    actual = rl_vector2(*args)
    gc.collect()
    assert _bytes(actual) == expected
