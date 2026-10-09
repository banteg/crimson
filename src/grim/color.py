from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import msgspec

from .math import clamp

if TYPE_CHECKING:
    from grim.raylib_api import rl


class RGBA(msgspec.Struct, frozen=True):
    r: float = 1.0
    g: float = 1.0
    b: float = 1.0
    a: float = 1.0

    @classmethod
    def from_rgba(cls, value: RGBA | tuple[float, float, float, float]) -> RGBA:
        if isinstance(value, RGBA):
            return value
        return cls(float(value[0]), float(value[1]), float(value[2]), float(value[3]))

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

    def scaled_alpha(self, factor: float) -> RGBA:
        return self.with_alpha(self.a * float(factor))

    def to_rl(self) -> rl.Color:
        from grim.raylib_api import rl_color

        c = self.clamped()
        return rl_color(
            int(c.r * 255.0 + 0.5),
            int(c.g * 255.0 + 0.5),
            int(c.b * 255.0 + 0.5),
            int(c.a * 255.0 + 0.5),
        )


def grim_color(r: float, g: float, b: float, a: float) -> rl.Color:
    """`grim_set_color`: clamp alpha, then truncate each channel to a byte."""
    from grim.raylib_api import rl_color

    a = clamp(a, 0.0, 1.0)
    return rl_color(int(r * 255.0) & 0xFF, int(g * 255.0) & 0xFF, int(b * 255.0) & 0xFF, int(a * 255.0) & 0xFF)
