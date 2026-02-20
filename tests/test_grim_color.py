from __future__ import annotations

from grim.color import RGBA
from tests.helpers import assert_float_close


def test_rgba_clamp_and_alpha_helpers() -> None:
    color = RGBA(1.2, -0.1, 0.5, 0.25)

    assert color.clamped() == RGBA(1.0, 0.0, 0.5, 0.25)
    assert color.scaled(0.5) == RGBA(0.6, -0.05, 0.25, 0.125)
    assert color.scaled_alpha(0.5) == RGBA(1.2, -0.1, 0.5, 0.125)
    assert color.with_alpha(1.0) == RGBA(1.2, -0.1, 0.5, 1.0)
    assert color.replace(a=1.0) == RGBA(1.2, -0.1, 0.5, 1.0)
    assert color.replace(r=0.3, b=0.7) == RGBA(0.3, -0.1, 0.7, 0.25)


def test_rgba_to_rl_and_from_rl_round_trip() -> None:
    color = RGBA(0.6, 0.4, 0.2, 0.8)

    rl_color = color.to_rl()
    round_trip = RGBA.from_rl(rl_color)

    assert (int(rl_color.r), int(rl_color.g), int(rl_color.b), int(rl_color.a)) == (153, 102, 51, 204)
    assert_float_close(round_trip.r, 0.6)
    assert_float_close(round_trip.g, 0.4)
    assert_float_close(round_trip.b, 0.2)
    assert_float_close(round_trip.a, 0.8)


def test_rgba_lerp() -> None:
    a = RGBA(1.0, 0.0, 0.0, 1.0)
    b = RGBA(0.0, 0.0, 1.0, 0.5)

    lerped = RGBA.lerp(a, b, 0.25)

    assert lerped == RGBA(0.75, 0.0, 0.25, 0.875)
