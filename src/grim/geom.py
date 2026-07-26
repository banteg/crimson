from __future__ import annotations

import math
import struct
from typing import TYPE_CHECKING, Protocol

import msgspec

from .math import clamp

_F32 = struct.Struct("<f")
_F32_MAX = 3.4028234663852886e38
_FLOAT_EPSILON = 1.1920928955078125e-7
_FLOAT_MIN = 1.1754943508222875e-38


def _f32(value: float) -> float:
    narrowed = float(value)
    if narrowed > _F32_MAX:
        return math.inf
    if narrowed < -_F32_MAX:
        return -math.inf
    return _F32.unpack(_F32.pack(narrowed))[0]

if TYPE_CHECKING:
    from grim.raylib_api import rl


class SupportsXY(Protocol):
    @property
    def x(self) -> float: ...

    @property
    def y(self) -> float: ...


class Vec2(msgspec.Struct, frozen=True):
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
        x = _f32(self.x)
        y = _f32(self.y)
        magnitude_sq = _f32(_f32(y * y) + _f32(x * x))
        difference = _f32(magnitude_sq - 1.0)
        if -_FLOAT_EPSILON <= difference <= _FLOAT_EPSILON:
            return Vec2(x, y)
        if not magnitude_sq > _FLOAT_MIN:
            return Vec2()
        inv_magnitude = _f32(1.0 / _f32(math.sqrt(magnitude_sq)))
        return Vec2(_f32(inv_magnitude * x), _f32(inv_magnitude * y))

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
        from grim.raylib_api import rl

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


class Rect(msgspec.Struct, frozen=True):
    x: float = 0.0
    y: float = 0.0
    w: float = 0.0
    h: float = 0.0

    @classmethod
    def from_xywh(cls, value: Rect | rl.Rectangle) -> Rect:
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
        from grim.raylib_api import rl

        return rl.Rectangle(self.x, self.y, self.w, self.h)
