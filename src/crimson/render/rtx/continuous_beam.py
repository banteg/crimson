"""One-source beam lighting; presentation state only."""

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
    """A glow stamp's density projected onto the beam axis, in stamp radii out to SUPPORT."""
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


@lru_cache(maxsize=1)
def stamp_half_width() -> float:
    """A stamp's longitudinal extent as a uniform stretch of equal variance, in stamp radii: sqrt(3) sigma."""
    radial = source_radial_marginal()
    step = SUPPORT / (len(radial) - 1)
    mass = second = 0.0
    for i, value in enumerate(radial):
        weight = value * (0.5 if i in (0, len(radial) - 1) else 1.0)
        mass += weight
        second += weight * (i * step) ** 2
    return math.sqrt(3 * second / mass)


@lru_cache(maxsize=128)
def beam_shape(length: float, radius: float, step: float, head_multiplier: float) -> tuple[float, float, float]:
    """The beam's energy along its axis: the head's share, its half-width, and the support's half-extent.

    The authored stamps every `step` weigh their position over the length, so in the limit they are a ramp
    from the tail to the head; the head adds its own brighter stamp. Each stamp holds radius^2 times the same
    projected mass, so the head's share is its radius squared against the ramp's summed weights. The head is a
    uniform stretch of the stamp's equivalent half-width around the head end. The support adds the head's
    halo past the end.
    """
    head_radius = radius * head_multiplier
    stamps = math.ceil(length / step) if length > 0 else 0
    ramp = radius * radius * step * stamps * (stamps - 1) / (2 * length) if stamps > 1 else 0.0
    head_share = head_radius * head_radius / (head_radius * head_radius + ramp)
    return head_share, stamp_half_width() * head_radius, length * 0.5 + head_radius * SUPPORT


def beam_uniform(light: MaterialLight) -> tuple[float, float, float, float]:
    """A light's `u_beam_shape`: head share, head half-width, Ion, support half-extent (0 for no beam).

    Unselected lamps stay dark, as do reflection-only sources.
    """
    if light.beam_profile is None or light.illumination_gain <= 0:
        return (0.0, 0.0, 0.0, 0.0)
    head_share, head_half_width, support = beam_shape(light.length, *light.beam_profile)
    return (head_share, head_half_width, float(light.beam_ion), support)


def prepare_beam_lights(lights: Sequence[MaterialLight]) -> tuple[list[float], list[MaterialLight]]:
    """Pack one uniform array and conservative grid-only copies of the sources.

    The copies only lengthen and orient a beam's support; pass the largest
    support half-extent as the grid's beam margin, so a beam's one walk
    retains every body across the stretch it lights while other lights keep
    their own margin. Upload original lights for reflection/illumination radiance.
    """
    assert len(lights) <= MAX_MATERIAL_LIGHTS
    values: list[float] = []
    grid_sources: list[MaterialLight] = []
    for light in lights:
        shape = beam_uniform(light)
        values.extend(shape)
        if not shape[3]:
            grid_sources.append(light)
            continue
        direction = light.direction if light.direction.length_sq() > 0.0001 else Vec2(1.0, 0.0)
        grid_sources.append(msgspec.structs.replace(light, direction=direction, length=2 * shape[3]))
    return values, grid_sources
