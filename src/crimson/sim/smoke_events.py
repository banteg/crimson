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
    profile: Literal["ordinary", "nuke", "muzzle", "rocket"] = "ordinary"
    flow_dir: Vec2 = Vec2()


class AtmosphereImpulse(msgspec.Struct, frozen=True):
    """Presentation-only airflow; strength is a world-units/second impulse.

    Muzzle and wake impulses act once along ``start`` to ``end``. Blasts deliver
    that total impulse over ``duration`` while their annular front expands.
    Neither form deposits smoke or heat or consumes simulation RNG.
    """

    start: Vec2
    end: Vec2
    radius: float
    strength: float
    curl: float = 0.0
    kind: Literal["muzzle", "wake", "blast"] = "wake"
    duration: float = 0.15
    expansion_speed: float = 0.0
