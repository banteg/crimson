from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING, Protocol

from .math import clamp

if TYPE_CHECKING:
    import pyray as rl


class SupportsXY(Protocol):
    x: float
    y: float


class SupportsRect(Protocol):
    x: float
    y: float
    width: float
    height: float


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

    def __truediv__(self, scalar: float) -> Vec2:
        return Vec2(self.x / scalar, self.y / scalar)

    def mul_components(self, other: Vec2) -> Vec2:
        return Vec2(self.x * other.x, self.y * other.y)

    def div_components(self, other: Vec2) -> Vec2:
        return Vec2(self.x / other.x, self.y / other.y)

    def avg_component(self) -> float:
        return (self.x + self.y) * 0.5

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
        return self / magnitude, magnitude

    def distance_to(self, other: Vec2) -> float:
        return (other - self).length()

    def direction_to(self, other: Vec2, *, epsilon: float = 1e-6) -> Vec2:
        direction, _ = (other - self).normalized_with_length(epsilon=epsilon)
        return direction

    @classmethod
    def from_angle(cls, theta: float) -> Vec2:
        return cls(x=math.cos(theta), y=math.sin(theta))

    @classmethod
    def from_polar(cls, theta: float, radius: float = 1.0) -> Vec2:
        return cls.from_angle(theta) * radius

    @classmethod
    def from_xy(cls, value: SupportsXY) -> Vec2:
        return cls(x=value.x, y=value.y)

    @classmethod
    def from_heading(cls, heading: float) -> Vec2:
        return cls.from_angle(heading - math.pi / 2.0)

    def to_angle(self) -> float:
        return math.atan2(self.y, self.x)

    def to_heading(self) -> float:
        return self.to_angle() + math.pi / 2.0

    def to_polar(self) -> tuple[float, float]:
        return self.to_angle(), self.length()

    def offset(self, *, dx: float = 0.0, dy: float = 0.0) -> Vec2:
        return Vec2(self.x + dx, self.y + dy)

    def perp_left(self) -> Vec2:
        return Vec2(-self.y, self.x)

    def perp_right(self) -> Vec2:
        return Vec2(self.y, -self.x)

    def to_rl(self) -> rl.Vector2:
        import pyray as rl

        return rl.Vector2(self.x, self.y)

    def to_dict(self, *, ndigits: int | None = None) -> dict[str, float]:
        if ndigits is None:
            return {"x": self.x, "y": self.y}
        return {
            "x": round(self.x, ndigits),
            "y": round(self.y, ndigits),
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


@dataclass(slots=True, frozen=True)
class Rect:
    x: float = 0.0
    y: float = 0.0
    w: float = 0.0
    h: float = 0.0

    @classmethod
    def from_xywh(cls, value: SupportsRect) -> Rect:
        return cls(
            x=value.x,
            y=value.y,
            w=float(value.width),
            h=float(value.height),
        )

    @classmethod
    def from_top_left(cls, top_left: SupportsXY, width: float, height: float) -> Rect:
        return cls(x=top_left.x, y=top_left.y, w=width, h=height)

    @classmethod
    def from_pos_size(cls, pos: Vec2, size: Vec2) -> Rect:
        return cls(x=pos.x, y=pos.y, w=size.x, h=size.y)

    @property
    def left(self) -> float:
        return self.x

    @property
    def top(self) -> float:
        return self.y

    @property
    def top_left(self) -> Vec2:
        return Vec2(self.x, self.y)

    @property
    def top_right(self) -> Vec2:
        return Vec2(self.right, self.y)

    @property
    def bottom_left(self) -> Vec2:
        return Vec2(self.x, self.bottom)

    @property
    def bottom_right(self) -> Vec2:
        return Vec2(self.right, self.bottom)

    @property
    def size(self) -> Vec2:
        return Vec2(self.w, self.h)

    @property
    def width(self) -> float:
        return self.w

    @property
    def height(self) -> float:
        return self.h

    @property
    def right(self) -> float:
        return self.x + self.w

    @property
    def bottom(self) -> float:
        return self.y + self.h

    @property
    def center(self) -> Vec2:
        return Vec2(self.x + self.w * 0.5, self.y + self.h * 0.5)

    @classmethod
    def from_center(cls, center: SupportsXY, width: float, height: float) -> Rect:
        return cls(
            x=center.x - width * 0.5,
            y=center.y - height * 0.5,
            w=width,
            h=height,
        )

    def offset(self, *, dx: float = 0.0, dy: float = 0.0) -> Rect:
        return Rect(x=self.x + dx, y=self.y + dy, w=self.w, h=self.h)

    def inset(self, *, dx: float = 0.0, dy: float = 0.0) -> Rect:
        return Rect(
            x=self.x + dx,
            y=self.y + dy,
            w=max(0.0, self.w - 2.0 * dx),
            h=max(0.0, self.h - 2.0 * dy),
        )

    def contains(self, point: SupportsXY) -> bool:
        px = point.x
        py = point.y
        return self.x <= px <= self.right and self.y <= py <= self.bottom

    def to_rl(self) -> rl.Rectangle:
        import pyray as rl

        return rl.Rectangle(self.x, self.y, self.w, self.h)
