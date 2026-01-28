from __future__ import annotations


def clamp(value: float, low: float, high: float) -> float:
    if value < low:
        return low
    if value > high:
        return high
    return value


def clamp01(value: float) -> float:
    return clamp(value, 0.0, 1.0)


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t
