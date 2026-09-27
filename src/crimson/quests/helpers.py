from __future__ import annotations

import math
from collections.abc import Iterator

import msgspec

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..math_parity import (
    NATIVE_HALF_PI,
    f32,
    f32_vec2,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ..sim.state_types import TERRAIN_SIZE
from .types import SpawnEntry

NATIVE_CENTER = Vec2(TERRAIN_SIZE * 0.5, TERRAIN_SIZE * 0.5)

# `(float)(crt_rand() % 612) * 0.01f`: random quest angles in [0, 6.11].
_RANDOM_ANGLE_SCALE = f32(0.01)


class EdgePoints(msgspec.Struct, frozen=True):
    left: Vec2
    right: Vec2
    top: Vec2
    bottom: Vec2


def edge_midpoints(offset: float = 64.0) -> EdgePoints:
    return EdgePoints(
        left=Vec2(-offset, NATIVE_CENTER.y),
        right=Vec2(TERRAIN_SIZE + offset, NATIVE_CENTER.y),
        top=Vec2(NATIVE_CENTER.x, -offset),
        bottom=Vec2(NATIVE_CENTER.x, TERRAIN_SIZE + offset),
    )


def corner_points(offset: float = 64.0) -> tuple[Vec2, ...]:
    return (
        Vec2(-offset, -offset),
        Vec2(TERRAIN_SIZE + offset, -offset),
        Vec2(-offset, TERRAIN_SIZE + offset),
        Vec2(TERRAIN_SIZE + offset, TERRAIN_SIZE + offset),
    )


def random_angle(draw: int) -> float:
    """Quest angle from a CRT draw: `(float)(draw % 612) * 0.01f`, rounded by the x87 `fmul`."""

    return x87_pc24_mul(float(draw % 612), _RANDOM_ANGLE_SCALE)


def angle_step(index: int, step: float, *, start: float = 0.0) -> float:
    """`(float)index * step_f + start_f` with each x87 op rounded to float32."""

    angle = x87_pc24_mul(float(index), f32(step))
    if start:
        angle = x87_pc24_add(angle, f32(start))
    return angle


def ring_point(center: Vec2, radius: float, angle: float) -> Vec2:
    """`(float)cos(angle) * radius + center`: `fcos`/`fsin` stay wide, the `fmul` and `fadd` round."""

    return Vec2(
        x87_pc24_add(x87_pc24_cos_mul(angle, radius), center.x),
        x87_pc24_add(x87_pc24_sin_mul(angle, radius), center.y),
    )


def ring_points(
    center: Vec2,
    radius: float,
    count: int,
    *,
    step: float,
    start: float = 0.0,
) -> Iterator[tuple[Vec2, float]]:
    """Ring positions at the float32 angles `index * step + start`, with those angles."""

    for index in range(count):
        angle = angle_step(index, step, start=start)
        yield ring_point(center, radius, angle), angle


def radial_points(
    center: Vec2,
    angle: float,
    radius_start: int,
    radius_end: int,
    radius_step: int,
) -> Iterator[Vec2]:
    """Integer radii along `angle`.

    `quest_build_sweep_stakes` (0x00437810) and `quest_build_deja_vu` (0x00437920)
    spill `cos(angle)` to a float local but keep `sin(angle)` on the x87 stack.
    """

    cos_f32 = f32(math.cos(angle))
    sin_wide = math.sin(angle)
    for radius in range(radius_start, radius_end, radius_step):
        yield Vec2(
            x87_pc24_add(x87_pc24_mul(float(radius), cos_f32), center.x),
            x87_pc24_add(x87_pc24_mul(float(radius), sin_wide), center.y),
        )


def heading_from_center(point: Vec2, center: Vec2) -> float:
    """`atan2(pos - center) - 1.5707964f` on the stored float32 entry position.

    `fpatan` stays wide; the `fsub` rounds (`quest_build_target_practice` 0x00437a00).
    """

    stored = f32_vec2(point)
    angle = math.atan2(x87_pc24_sub(stored.y, center.y), x87_pc24_sub(stored.x, center.x))
    return x87_pc24_sub(angle, NATIVE_HALF_PI)


def line_points(start: Vec2, step: Vec2, count: int) -> Iterator[Vec2]:
    """`(float)index * step_f + start` per axis with each x87 op rounded to float32."""

    step_x = f32(step.x)
    step_y = f32(step.y)
    for index in range(count):
        yield Vec2(
            x87_pc24_add(x87_pc24_mul(float(index), step_x), start.x),
            x87_pc24_add(x87_pc24_mul(float(index), step_y), start.y),
        )


def spawn(
    point: Vec2,
    *,
    heading: float = 0.0,
    spawn_id: SpawnId,
    trigger_ms: int,
    count: int,
) -> SpawnEntry:
    # `quest_spawn_entry_t` position and heading are float32 fields.
    return SpawnEntry(
        pos=f32_vec2(point),
        heading=f32(heading),
        spawn_id=spawn_id,
        trigger_ms=trigger_ms,
        count=count,
    )
