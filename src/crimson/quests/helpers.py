from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Iterator

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from .types import SpawnEntry


@dataclass(frozen=True, slots=True)
class EdgePoints:
    left: Vec2
    right: Vec2
    top: Vec2
    bottom: Vec2


def center_point(width: float, height: float | None = None) -> Vec2:
    if height is None:
        height = width
    return Vec2(float(width) * 0.5, float(height) * 0.5)


def edge_midpoints(width: float, height: float | None = None, offset: float = 64.0) -> EdgePoints:
    if height is None:
        height = width
    center = center_point(width, height)
    return EdgePoints(
        left=Vec2(-offset, center.y),
        right=Vec2(float(width) + offset, center.y),
        top=Vec2(center.x, -offset),
        bottom=Vec2(center.x, float(height) + offset),
    )


def corner_points(width: float, height: float | None = None, offset: float = 64.0) -> tuple[Vec2, ...]:
    if height is None:
        height = width
    return (
        Vec2(-offset, -offset),
        Vec2(float(width) + offset, -offset),
        Vec2(-offset, float(height) + offset),
        Vec2(float(width) + offset, float(height) + offset),
    )


def iter_angles(count: int, *, step: float | None = None, start: float = 0.0) -> Iterator[float]:
    if count <= 0:
        return iter(())
    if step is None:
        step = math.tau / float(count)
    for idx in range(count):
        yield start + float(idx) * step


def ring_points(
    center: Vec2,
    radius: float,
    count: int,
    *,
    step: float | None = None,
    start: float = 0.0,
) -> Iterator[tuple[Vec2, float]]:
    for angle in iter_angles(count, step=step, start=start):
        yield center + Vec2.from_angle(angle) * radius, angle


def random_angle(rng: random.Random) -> float:
    return float(rng.randrange(0x264)) * 0.01


def radial_points(
    center: Vec2,
    angle: float,
    radius_start: float,
    radius_end: float,
    radius_step: float,
) -> Iterator[Vec2]:
    direction = Vec2.from_angle(angle)
    radius = radius_start
    while radius < radius_end:
        yield center + direction * radius
        radius += radius_step


def heading_from_center(point: Vec2, center: Vec2) -> float:
    return (point - center).to_angle() - (math.pi / 2.0)


def line_points(start: Vec2, step: Vec2, count: int) -> Iterator[Vec2]:
    for idx in range(count):
        yield start + step * float(idx)


def spawn(
    point: Vec2,
    *,
    heading: float = 0.0,
    spawn_id: SpawnId,
    trigger_ms: int,
    count: int,
) -> SpawnEntry:
    return SpawnEntry(
        x=point.x,
        y=point.y,
        heading=heading,
        spawn_id=spawn_id,
        trigger_ms=trigger_ms,
        count=count,
    )


def spawn_at(
    point: Vec2,
    *,
    heading: float = 0.0,
    spawn_id: SpawnId,
    trigger_ms: int,
    count: int,
) -> SpawnEntry:
    return spawn(
        point,
        heading=heading,
        spawn_id=spawn_id,
        trigger_ms=trigger_ms,
        count=count,
    )
