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

    Muzzle and wake impulses act once along ``start`` to ``end``. Blasts deliver
    that total impulse over ``duration`` while their annular front expands. A body's
    is its path through the tick, its strength the body's speed: the air under it
    eases toward that velocity. None deposits smoke or heat or consumes simulation RNG.
    """

    start: Vec2
    end: Vec2
    radius: float
    strength: float
    curl: float = 0.0
    kind: Literal["muzzle", "wake", "blast", "body"] = "wake"
    duration: float = 0.15
    expansion_speed: float = 0.0


# A body moving through the air drags the air under it toward its own velocity (smoke_solver.frag's mode 6), over a
# radius that is a share of its size. A step longer than the limit is a spawn, a slot reused or a teleport, not motion.
BODY_RADIUS = 0.35
BODY_STEP_LIMIT = 30.0

Body = tuple[Vec2, float] | None


def body_positions(world: WorldState) -> list[Body]:
    """Each living body's position and size, creature slots then players; None for a slot without one."""
    return [
        *((creature.pos, creature.size) if creature.active and creature.hp > 0 else None
          for creature in world.creatures.entries),
        *((player.pos, player.size) if player.health > 0 else None for player in world.players),
    ]


def body_wakes(before: Sequence[Body], after: Sequence[Body], dt: float) -> list[AtmosphereImpulse]:
    """Each body that lived through a tick of `dt` seconds and moved in it: its path and speed."""
    wakes = []
    for start, end in zip(before, after, strict=True):
        if start is None or end is None:
            continue
        step = (end[0] - start[0]).length()
        if 0.0 < step <= BODY_STEP_LIMIT and dt > 0.0:
            wakes.append(AtmosphereImpulse(
                start=start[0], end=end[0], radius=end[1] * BODY_RADIUS, strength=step / dt, kind="body",
            ))
    return wakes
