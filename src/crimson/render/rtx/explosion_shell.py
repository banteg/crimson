"""Shared art-directed pressure-shell geometry, independent of native effect slots."""

from __future__ import annotations

import math

import msgspec


class ExplosionShell(msgspec.Struct, frozen=True):
    radius: float
    strength: float
    alpha: float
    energy: float


def explosion_shell(age: float, scale: float) -> ExplosionShell | None:
    """A warm visible front and its nearby light travel together for 0.65 seconds."""
    elapsed = age - 0.05
    if elapsed < 0.0 or elapsed >= 0.65:
        return None
    fade = min(1.0, max(0.0, (elapsed - 0.28) / 0.37))
    strength = 1.0 - fade * fade * (3.0 - 2.0 * fade)
    radius = 30.0 + 650.0 * elapsed
    dilution = min(1.0, 100.0 / radius)
    return ExplosionShell(
        radius * max(0.1, scale), strength, 0.36 * strength * dilution**0.65, strength * math.sqrt(dilution),
    )
