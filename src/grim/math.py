from __future__ import annotations

import math


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


def distance_sq(x0: float, y0: float, x1: float, y1: float) -> float:
    dx = float(x1) - float(x0)
    dy = float(y1) - float(y0)
    return dx * dx + dy * dy


def distance(x0: float, y0: float, x1: float, y1: float) -> float:
    return math.sqrt(distance_sq(x0, y0, x1, y1))
