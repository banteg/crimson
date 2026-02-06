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
    left: tuple[float, float]
    right: tuple[float, float]
    top: tuple[float, float]
    bottom: tuple[float, float]


def center_point(width: float, height: float | None = None) -> tuple[float, float]:
    if height is None:
        height = width
    return float(width) / 2.0, float(height) / 2.0


def edge_midpoints(width: float, height: float | None = None, offset: float = 64.0) -> EdgePoints:
    if height is None:
        height = width
    cx, cy = center_point(width, height)
    return EdgePoints(
        left=(-offset, cy),
        right=(float(width) + offset, cy),
        top=(cx, -offset),
        bottom=(cx, float(height) + offset),
    )


def corner_points(width: float, height: float | None = None, offset: float = 64.0) -> tuple[tuple[float, float], ...]:
    if height is None:
        height = width
    return (
        (-offset, -offset),
        (float(width) + offset, -offset),
        (-offset, float(height) + offset),
        (float(width) + offset, float(height) + offset),
    )


def iter_angles(count: int, *, step: float | None = None, start: float = 0.0) -> Iterator[float]:
    if count <= 0:
        return iter(())
    if step is None:
        step = math.tau / float(count)
    for idx in range(count):
        yield start + float(idx) * step


def ring_points(
    center_x: float,
    center_y: float,
    radius: float,
    count: int,
    *,
    step: float | None = None,
    start: float = 0.0,
) -> Iterator[tuple[float, float, float]]:
    for angle in iter_angles(count, step=step, start=start):
        yield (
            math.cos(angle) * radius + center_x,
            math.sin(angle) * radius + center_y,
            angle,
        )


def random_angle(rng: random.Random) -> float:
    return float(rng.randrange(0x264)) * 0.01


def radial_points(
    center_x: float,
    center_y: float,
    angle: float,
    radius_start: float,
    radius_end: float,
    radius_step: float,
) -> Iterator[tuple[float, float]]:
    cos_a = math.cos(angle)
    sin_a = math.sin(angle)
    radius = radius_start
    while radius < radius_end:
        yield (
            cos_a * radius + center_x,
            sin_a * radius + center_y,
        )
        radius += radius_step


def heading_from_center(x: float, y: float, center_x: float, center_y: float) -> float:
    return Vec2(x - center_x, y - center_y).to_angle() - (math.pi / 2.0)


def line_points_x(start: float, step: float, count: int, y: float) -> Iterator[tuple[float, float]]:
    for idx in range(count):
        yield start + float(idx) * step, y


def line_points_y(start: float, step: float, count: int, x: float) -> Iterator[tuple[float, float]]:
    for idx in range(count):
        yield x, start + float(idx) * step


def spawn(
    *,
    x: float,
    y: float,
    heading: float = 0.0,
    spawn_id: SpawnId,
    trigger_ms: int,
    count: int,
) -> SpawnEntry:
    return SpawnEntry(
        x=x,
        y=y,
        heading=heading,
        spawn_id=spawn_id,
        trigger_ms=trigger_ms,
        count=count,
    )


def spawn_at(
    point: tuple[float, float],
    *,
    heading: float = 0.0,
    spawn_id: SpawnId,
    trigger_ms: int,
    count: int,
) -> SpawnEntry:
    x, y = point
    return spawn(
        x=x,
        y=y,
        heading=heading,
        spawn_id=spawn_id,
        trigger_ms=trigger_ms,
        count=count,
    )
