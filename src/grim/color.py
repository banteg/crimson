from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .math import clamp

if TYPE_CHECKING:
    import pyray as rl


class SupportsRGBA(Protocol):
    r: float
    g: float
    b: float
    a: float


@dataclass(slots=True, frozen=True)
class RGBA:
    r: float = 1.0
    g: float = 1.0
    b: float = 1.0
    a: float = 1.0

    @classmethod
    def from_rgba(cls, value: RGBA | tuple[float, float, float, float]) -> RGBA:
        if isinstance(value, RGBA):
            return value
        return cls(float(value[0]), float(value[1]), float(value[2]), float(value[3]))

    @classmethod
    def from_rl(cls, value: SupportsRGBA) -> RGBA:
        inv_255 = 1.0 / 255.0
        return cls(
            float(value.r) * inv_255,
            float(value.g) * inv_255,
            float(value.b) * inv_255,
            float(value.a) * inv_255,
        )

    @staticmethod
    def lerp(a: RGBA, b: RGBA, t: float) -> RGBA:
        t = float(t)
        return RGBA(
            r=a.r + (b.r - a.r) * t,
            g=a.g + (b.g - a.g) * t,
            b=a.b + (b.b - a.b) * t,
            a=a.a + (b.a - a.a) * t,
        )

    def to_tuple(self) -> tuple[float, float, float, float]:
        return (self.r, self.g, self.b, self.a)

    def __iter__(self) -> Iterator[float]:
        yield self.r
        yield self.g
        yield self.b
        yield self.a

    def clamped(self) -> RGBA:
        return RGBA(
            r=clamp(self.r, 0.0, 1.0),
            g=clamp(self.g, 0.0, 1.0),
            b=clamp(self.b, 0.0, 1.0),
            a=clamp(self.a, 0.0, 1.0),
        )

    def replace(
        self,
        *,
        r: float | None = None,
        g: float | None = None,
        b: float | None = None,
        a: float | None = None,
    ) -> RGBA:
        return RGBA(
            r=self.r if r is None else float(r),
            g=self.g if g is None else float(g),
            b=self.b if b is None else float(b),
            a=self.a if a is None else float(a),
        )

    def with_alpha(self, alpha: float) -> RGBA:
        return self.replace(a=alpha)

    def scaled(self, factor: float) -> RGBA:
        factor = float(factor)
        return RGBA(
            r=self.r * factor,
            g=self.g * factor,
            b=self.b * factor,
            a=self.a * factor,
        )

    def scaled_alpha(self, factor: float) -> RGBA:
        return self.with_alpha(self.a * float(factor))

    def to_rl(self) -> rl.Color:
        import pyray as rl

        c = self.clamped()
        return rl.Color(
            int(c.r * 255.0 + 0.5),
            int(c.g * 255.0 + 0.5),
            int(c.b * 255.0 + 0.5),
            int(c.a * 255.0 + 0.5),
        )
