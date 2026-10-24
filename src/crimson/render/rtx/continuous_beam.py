"""Energy-section beam lighting; presentation state only."""

from __future__ import annotations

import math
from collections.abc import Sequence
from functools import lru_cache

import msgspec

from grim.geom import Vec2

from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight

SUPPORT = 0.85998995


ION_DIRECT_GAIN = 4.0
FIRE_DIRECT_GAIN = 3.0


@lru_cache(maxsize=1)
def source_radial_marginal() -> tuple[float, ...]:
    """Small, fixed-cost lookup for the three-cell appearance approximation."""
    values: list[float] = []
    for i in range(65):
        x = SUPPORT * i / 64
        total = 0.0
        for j in range(33):
            y = SUPPORT * j / 32
            radius = math.hypot(x, y)
            density = min(1.0, max(0.0, 1.3 * math.exp(-4.8 * radius - radius * radius) - 0.01))
            total += density * (0.5 if j in (0, 32) else 1.0)
        values.append(total * 2 * SUPPORT / 32)
    return tuple(values)


SOURCE_CELLS = 3


@lru_cache(maxsize=128)
def source_cells(length: float, radius: float, step: float, head_multiplier: float) -> tuple[float, ...]:
    """Three energy-weighted source cells: mass, offset, longitudinal half-span, zero.

    Positions and half-spans are world units relative to the beam midpoint.
    Each cell samples only the nearby authored stamps plus the head. Matching
    its variance to a uniform segment gives the source extent used by the
    analytic finite-source visibility integral.
    """
    radial = source_radial_marginal()
    support = radius * SUPPORT
    head_radius = radius * head_multiplier
    pad = head_radius * SUPPORT
    span = length + 2 * pad
    stamp_count = math.ceil(length / step)
    samples = 32
    values: list[float] = []
    total = 0.0

    def density(r: float) -> float:
        r = abs(r)
        if r >= SUPPORT:
            return 0.0
        t = r / SUPPORT * (len(radial) - 1)
        index = int(t)
        return radial[index] + (radial[index + 1] - radial[index]) * (t - index)

    for cell in range(SOURCE_CELLS):
        mass = first = second = 0.0
        for j in range(samples):
            u = (cell + (j + 0.5) / samples) / SOURCE_CELLS
            x = -pad + u * span
            energy = head_radius * density((x - length) / head_radius)
            if length > 0:
                lo = max(0, math.ceil((x - support) / step))
                hi = min(stamp_count - 1, math.floor((x + support) / step))
                for k in range(lo, hi + 1):
                    position = k * step
                    energy += position / length * radius * density((x - position) / radius)
            mass += energy
            first += energy * u
            second += energy * u * u
        mean = first / mass if mass else (cell + 0.5) / SOURCE_CELLS
        half_span = math.sqrt(max(0.0, 3 * (second / mass - mean * mean))) if mass else 0.0
        values.extend((mass, -pad + mean * span - length * 0.5, half_span * span, 0.0))
        total += mass
    return tuple(v / total if i % 4 == 0 else v for i, v in enumerate(values))


def beam_cells(light: MaterialLight) -> tuple[float, ...]:
    """Mask unselected lamps; reflection-only retained sources must not illuminate."""
    if light.beam_profile is None or light.illumination_gain <= 0:
        return (0.0,) * (SOURCE_CELLS * 4)
    values = source_cells(light.length, *light.beam_profile)
    return tuple(float(light.beam_ion) if i % 4 == 3 else value for i, value in enumerate(values))


def prepare_beam_lights(lights: Sequence[MaterialLight]) -> tuple[list[float], list[MaterialLight]]:
    """Pack one uniform array and conservative grid-only copies of the sources.

    The copies only lengthen and orient a beam's support; pass the largest
    packed half-span as the grid's beam margin, so section walks retain every
    body across the complete section support while other lights keep their
    own margin. Upload original lights for reflection/illumination radiance.
    """
    assert len(lights) <= MAX_MATERIAL_LIGHTS
    values: list[float] = []
    grid_sources: list[MaterialLight] = []
    for light in lights:
        cells = beam_cells(light)
        values.extend(cells)
        if light.beam_profile is None or light.illumination_gain <= 0:
            grid_sources.append(light)
            continue
        radius, _, head = light.beam_profile
        pad = radius * head * SUPPORT
        direction = light.direction if light.direction.length_sq() > 0.0001 else Vec2(1.0, 0.0)
        grid_sources.append(
            msgspec.structs.replace(
                light,
                direction=direction,
                length=light.length + 2 * pad,
            ),
        )
    return values, grid_sources
