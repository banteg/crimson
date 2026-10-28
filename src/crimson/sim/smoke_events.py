"""Immutable native smoke spawns handed from one simulation tick to presentation."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal

import msgspec

from grim.color import RGBA
from grim.geom import Vec2

if TYPE_CHECKING:
    from .world_state import WorldState


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
    source: Literal["sprite", "effect", "particle"] = "sprite"
    delay_seconds: float = 0.0
    expansion: float = 0.0
    retention_seconds: float = 10.0
    profile: Literal["ordinary", "nuke", "muzzle", "rocket", "soot"] = "ordinary"
    flow_dir: Vec2 = Vec2()


class AtmosphereImpulse(msgspec.Struct, frozen=True):
    """Presentation-only airflow; strength is a world-units/second impulse.

    Muzzle, wake and body impulses act once along ``start`` to ``end``. Blasts deliver
    that total impulse over ``duration`` while their annular front expands.
    Neither form deposits smoke or heat or consumes simulation RNG.
    """

    start: Vec2
    end: Vec2
    radius: float
    strength: float
    curl: float = 0.0
    kind: Literal["muzzle", "wake", "blast", "body"] = "wake"
    duration: float = 0.15
    expansion_speed: float = 0.0


# A body moving through the air drags it along its path and parts it to its sides (the wake's vortex pair): its radius
# a share of the body's size, its strength and curl per world unit the body moved in the tick. A longer step is a spawn,
# a slot reused or a teleport, not motion.
BODY_RADIUS = 0.35
BODY_PUSH = 4.0
BODY_CURL = 1.0
BODY_STEP_LIMIT = 30.0

Body = tuple[Vec2, float] | None


def body_positions(world: WorldState) -> list[Body]:
    """Each living body's position and size, creature slots then players; None for a slot without one."""
    return [
        *((creature.pos, creature.size) if creature.active and creature.hp > 0 else None
          for creature in world.creatures.entries),
        *((player.pos, player.size) if player.health > 0 else None for player in world.players),
    ]


def body_wakes(before: Sequence[Body], after: Sequence[Body]) -> list[AtmosphereImpulse]:
    """The air each body that lived through a tick pushed along its path in it."""
    wakes = []
    for start, end in zip(before, after, strict=True):
        if start is None or end is None:
            continue
        step = (end[0] - start[0]).length()
        if 0.0 < step <= BODY_STEP_LIMIT:
            wakes.append(AtmosphereImpulse(
                start=start[0], end=end[0], radius=end[1] * BODY_RADIUS, strength=step * BODY_PUSH,
                curl=step * BODY_CURL, kind="body",
            ))
    return wakes
