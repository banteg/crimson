from __future__ import annotations

from enum import Enum

import msgspec

from grim.rand import CrandLike

from ..rng_caller_static import RngCallerStatic
from ..terrain_slots import (
    TerrainSlotTriplet,
    choose_unlock_terrain_slots,
)

# Terrain stamping RNG consumption mirrors `grim/terrain_render.py` + `docs/crimsonland-exe/terrain.md`.
TERRAIN_RANDOM_PRELUDE_DRAWS = 3
TERRAIN_DENSITY_BASE = 800
TERRAIN_DENSITY_OVERLAY = 0x23
TERRAIN_DENSITY_DETAIL = 0x0F
TERRAIN_DENSITY_SHIFT = 19
TERRAIN_RAND_DRAWS_PER_STAMP = 3  # rotation, then position draws (see terrain renderer parity notes)


class TerrainGenerationKind(str, Enum):
    EXPLICIT = "explicit"
    UNLOCK_RANDOM = "unlock_random"


TerrainStampCallerTriplet = tuple[RngCallerStatic, RngCallerStatic, RngCallerStatic]

_UNLOCK_RANDOM_TERRAIN_PRELUDE_CALLERS: tuple[RngCallerStatic, ...] = (
    RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_1,
    RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_2,
    RngCallerStatic.TERRAIN_GENERATE_RANDOM_PRELUDE_3,
)

_UNLOCK_RANDOM_TERRAIN_STAMP_CALLERS: tuple[TerrainStampCallerTriplet, ...] = (
    (
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_BASE_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_OVERLAY_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_RANDOM_DETAIL_X,
    ),
)

_EXPLICIT_TERRAIN_STAMP_CALLERS: tuple[TerrainStampCallerTriplet, ...] = (
    (
        RngCallerStatic.TERRAIN_GENERATE_BASE_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_BASE_Y,
        RngCallerStatic.TERRAIN_GENERATE_BASE_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_Y,
        RngCallerStatic.TERRAIN_GENERATE_OVERLAY_X,
    ),
    (
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_ROTATION,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_Y,
        RngCallerStatic.TERRAIN_GENERATE_DETAIL_X,
    ),
)


def terrain_stamping_draws(*, width: int, height: int) -> int:
    """Return the number of `rand()` draws consumed by the procedural terrain stamps."""

    w = max(0, width)
    h = max(0, height)
    area = w * h
    stamps = (
        ((area * TERRAIN_DENSITY_BASE) >> TERRAIN_DENSITY_SHIFT)
        + ((area * TERRAIN_DENSITY_OVERLAY) >> TERRAIN_DENSITY_SHIFT)
        + ((area * TERRAIN_DENSITY_DETAIL) >> TERRAIN_DENSITY_SHIFT)
    )

    return stamps * TERRAIN_RAND_DRAWS_PER_STAMP


class TerrainSetup(msgspec.Struct, frozen=True):
    terrain_slots: TerrainSlotTriplet
    terrain_seed: int
    generation_kind: TerrainGenerationKind = TerrainGenerationKind.EXPLICIT


def _advance_random_terrain_prelude_rng(rng: CrandLike) -> None:
    # Native `terrain_generate_random()` consumes three CRT draws before the
    # unlock-gated variant rolls. The values are not used by the rewrite, but
    # the state advance is required for parity.
    for caller in _UNLOCK_RANDOM_TERRAIN_PRELUDE_CALLERS:
        rng.rand_tagged(caller)


def _advance_terrain_stamping_rng(
    rng: CrandLike,
    *,
    width: int,
    height: int,
    generation_kind: TerrainGenerationKind,
) -> None:
    area = max(0, width) * max(0, height)
    caller_sets = (
        _UNLOCK_RANDOM_TERRAIN_STAMP_CALLERS
        if generation_kind is TerrainGenerationKind.UNLOCK_RANDOM
        else _EXPLICIT_TERRAIN_STAMP_CALLERS
    )
    for density, callers in zip(
        (TERRAIN_DENSITY_BASE, TERRAIN_DENSITY_OVERLAY, TERRAIN_DENSITY_DETAIL),
        caller_sets,
        strict=True,
    ):
        count = (area * density) >> TERRAIN_DENSITY_SHIFT
        for _ in range(count):
            rng.rand_tagged(callers[0])
            rng.rand_tagged(callers[1])
            rng.rand_tagged(callers[2])


def advance_unlock_terrain(
    rng: CrandLike,
    *,
    unlock_index: int,
    width: int,
    height: int,
) -> TerrainSetup:
    """Advance RNG through the shared unlock-driven terrain startup window.

    Mutates the authoritative RNG to match native `terrain_generate_random()`
    and returns the minimal render boundary data needed by the detached terrain
    renderer.
    """

    _advance_random_terrain_prelude_rng(rng)
    terrain_slots = choose_unlock_terrain_slots(unlock_index=unlock_index, rng=rng)
    terrain_seed = rng.state
    _advance_terrain_stamping_rng(
        rng,
        width=width,
        height=height,
        generation_kind=TerrainGenerationKind.UNLOCK_RANDOM,
    )
    return TerrainSetup(
        terrain_slots=terrain_slots,
        terrain_seed=terrain_seed,
        generation_kind=TerrainGenerationKind.UNLOCK_RANDOM,
    )


def advance_explicit_terrain(
    rng: CrandLike,
    *,
    terrain_slots: TerrainSlotTriplet,
    width: int,
    height: int,
) -> TerrainSetup:
    """Advance RNG through explicit terrain generation when slots are fixed."""

    terrain_seed = rng.state
    _advance_terrain_stamping_rng(
        rng,
        width=width,
        height=height,
        generation_kind=TerrainGenerationKind.EXPLICIT,
    )
    return TerrainSetup(
        terrain_slots=terrain_slots,
        terrain_seed=terrain_seed,
        generation_kind=TerrainGenerationKind.EXPLICIT,
    )
