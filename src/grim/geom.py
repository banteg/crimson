from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable, Protocol, TypeVar

from .math import clamp

TVector2 = TypeVar("TVector2")


class SupportsXY(Protocol):
    x: float
    y: float


@dataclass(slots=True, frozen=True)
class Vec2:
    x: float = 0.0
    y: float = 0.0

    def length_sq(self) -> float:
        return self.x * self.x + self.y * self.y

    def length(self) -> float:
        return math.sqrt(self.length_sq())

    def __add__(self, other: Vec2) -> Vec2:
        return Vec2(self.x + other.x, self.y + other.y)

    def __sub__(self, other: Vec2) -> Vec2:
        return Vec2(self.x - other.x, self.y - other.y)

    def __mul__(self, scalar: float) -> Vec2:
        return Vec2(self.x * scalar, self.y * scalar)

    def __rmul__(self, scalar: float) -> Vec2:
        return self * scalar

    def normalized(self) -> Vec2:
        magnitude_sq = self.length_sq()
        if magnitude_sq <= 0.0:
            return Vec2()
        inv_magnitude = 1.0 / math.sqrt(magnitude_sq)
        return Vec2(self.x * inv_magnitude, self.y * inv_magnitude)

    def normalized_with_length(self, *, epsilon: float = 1e-6) -> tuple[Vec2, float]:
        magnitude = self.length()
        if magnitude <= epsilon:
            return Vec2(), 0.0
        return self * (1.0 / magnitude), magnitude

    def distance_to(self, other: Vec2) -> float:
        return (other - self).length()

    def direction_to(self, other: Vec2, *, epsilon: float = 1e-6) -> Vec2:
        direction, _ = (other - self).normalized_with_length(epsilon=epsilon)
        return direction

    @classmethod
    def from_angle(cls, theta: float) -> Vec2:
        return cls(x=math.cos(theta), y=math.sin(theta))

    @classmethod
    def from_xy(cls, value: SupportsXY) -> Vec2:
        return cls(x=float(value.x), y=float(value.y))

    @classmethod
    def from_heading(cls, heading: float) -> Vec2:
        return cls.from_angle(heading - math.pi / 2.0)

    def to_angle(self) -> float:
        return math.atan2(self.y, self.x)

    def to_heading(self) -> float:
        return self.to_angle() + math.pi / 2.0

    def perp_left(self) -> Vec2:
        return Vec2(-self.y, self.x)

    def perp_right(self) -> Vec2:
        return Vec2(self.y, -self.x)

    def to_vector2(self, constructor: Callable[[float, float], TVector2]) -> TVector2:
        """Build a target vector type (for example `pyray.Vector2`) from this Vec2."""

        return constructor(self.x, self.y)

    def to_dict(self, *, ndigits: int | None = None) -> dict[str, float]:
        if ndigits is None:
            return {"x": float(self.x), "y": float(self.y)}
        return {
            "x": round(float(self.x), ndigits),
            "y": round(float(self.y), ndigits),
        }

    def rotated(self, theta: float) -> Vec2:
        cos_theta = math.cos(theta)
        sin_theta = math.sin(theta)
        return Vec2(
            x=self.x * cos_theta - self.y * sin_theta,
            y=self.x * sin_theta + self.y * cos_theta,
        )

    def clamp_rect(self, min_x: float, min_y: float, max_x: float, max_y: float) -> Vec2:
        return Vec2(
            x=clamp(self.x, min_x, max_x),
            y=clamp(self.y, min_y, max_y),
        )

    @staticmethod
    def distance_sq(a: Vec2, b: Vec2) -> float:
        dx = b.x - a.x
        dy = b.y - a.y
        return dx * dx + dy * dy

    @staticmethod
    def lerp(a: Vec2, b: Vec2, t: float) -> Vec2:
        return Vec2(
            x=a.x + (b.x - a.x) * t,
            y=a.y + (b.y - a.y) * t,
        )
