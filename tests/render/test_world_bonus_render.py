from __future__ import annotations

import math

import pytest

from crimson.render.world.bonuses import bonus_bubble_fade, bonus_fade, bonus_icon_pulse


@pytest.mark.parametrize(
    ("time_left", "time_max", "expected"),
    [
        (4.0, 5.0, 1.0),
        (0.25, 5.0, 0.5),
        (4.75, 5.0, 0.5),
    ],
)
def test_bonus_icon_fade_matches_native_edges(
    time_left: float,
    time_max: float,
    expected: float,
) -> None:
    assert bonus_fade(time_left, time_max) == pytest.approx(expected)


def test_bonus_bubble_fade_blinks_during_last_two_seconds() -> None:
    positive_phase = 1.0 / 24.0

    assert math.sin(positive_phase * math.pi * 6.0) > 0.0
    assert bonus_bubble_fade(positive_phase, 5.0) == pytest.approx(positive_phase * 0.25)


def test_bonus_bubble_fade_uses_half_rate_on_nonpositive_blink_phase() -> None:
    time_left = 0.2

    assert math.sin(time_left * math.pi * 6.0) < 0.0
    assert bonus_bubble_fade(time_left, 5.0) == pytest.approx(time_left * 0.5)


def test_bonus_bubble_spawn_fade_overrides_terminal_blink() -> None:
    assert bonus_bubble_fade(4.75, 5.0) == pytest.approx(0.5)


def test_bonus_icon_pulse_is_native_sine_squared() -> None:
    assert bonus_icon_pulse(math.pi / 4.0) == pytest.approx(0.875)
