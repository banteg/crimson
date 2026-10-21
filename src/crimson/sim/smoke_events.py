"""Immutable native smoke spawns handed from one simulation tick to presentation."""

from __future__ import annotations

from typing import Literal

import msgspec

from grim.color import RGBA
from grim.geom import Vec2


class SmokeEmission(msgspec.Struct, frozen=True):
    """Copied spawn values; scale is full world diameter, expansion is radial units/s.

    General-effect overflow slots follow the fixed pool's indices. Identities are
    presentation-local and reset when a checkpoint restores a different pool.
    """

    slot: int
    generation: int
    pos: Vec2
    vel: Vec2
    scale: float
    color: RGBA
    rotation: float
    source: Literal["sprite", "effect"] = "sprite"
    delay_seconds: float = 0.0
    expansion: float = 0.0
    retention_seconds: float = 10.0
    profile: Literal["ordinary", "nuke"] = "ordinary"
