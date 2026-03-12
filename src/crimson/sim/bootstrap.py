from __future__ import annotations

import msgspec

from grim.rand import CrandLike

from ..terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    UNLOCK_TERRAIN_SLOTS,
    TerrainSlotTriplet,
    choose_unlock_terrain_slots,
)

# Terrain stamping RNG consumption mirrors `grim/terrain_render.py` + `docs/crimsonland-exe/terrain.md`.
TERRAIN_DENSITY_BASE = 800
TERRAIN_DENSITY_OVERLAY = 0x23
TERRAIN_DENSITY_DETAIL = 0x0F
TERRAIN_DENSITY_SHIFT = 19
TERRAIN_RAND_DRAWS_PER_STAMP = 3  # rotation, then position draws (see terrain renderer parity notes)


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


class TerrainPreludeResult(msgspec.Struct, frozen=True):
    seed_before: int
    seed_after: int
    terrain_slots: TerrainSlotTriplet
    terrain_seed: int
    selection_draws: int
    stamping_draws: int

    @property
    def total_draws(self) -> int:
        return self.selection_draws + self.stamping_draws


def _selection_draws_for_result(*, unlock_index: int, terrain_slots: TerrainSlotTriplet) -> int:
    draws = 0
    for threshold, slots in UNLOCK_TERRAIN_SLOTS.items():
        if unlock_index < threshold:
            continue
        draws += 1
        if terrain_slots == slots:
            break
        if terrain_slots == DEFAULT_TERRAIN_SLOTS:
            continue
    return draws


def _advance_terrain_stamping_rng(
    rng: CrandLike,
    *,
    width: int,
    height: int,
) -> int:
    stamping_draws = terrain_stamping_draws(width=width, height=height)
    for _ in range(stamping_draws):
        rng.rand()
    return stamping_draws


def run_unlock_terrain_prelude(
    rng: CrandLike,
    *,
    unlock_index: int,
    width: int,
    height: int,
) -> TerrainPreludeResult:
    """Consume RNG draws for the shared unlock-driven terrain prelude.

    This advances the authoritative run RNG to match the classic terrain-generation
    window while also returning the terrain descriptor + seed needed for rendering.
    """

    seed_before = rng.state
    terrain_slots = choose_unlock_terrain_slots(unlock_index=unlock_index, rng=rng)
    selection_draws = _selection_draws_for_result(
        unlock_index=unlock_index,
        terrain_slots=terrain_slots,
    )
    terrain_seed = rng.state
    stamping_draws = _advance_terrain_stamping_rng(
        rng,
        width=width,
        height=height,
    )
    seed_after = rng.state
    return TerrainPreludeResult(
        seed_before=seed_before,
        seed_after=seed_after,
        terrain_slots=terrain_slots,
        terrain_seed=terrain_seed,
        selection_draws=selection_draws,
        stamping_draws=stamping_draws,
    )


def run_explicit_terrain_prelude(
    rng: CrandLike,
    *,
    terrain_slots: TerrainSlotTriplet,
    width: int,
    height: int,
) -> TerrainPreludeResult:
    """Consume RNG draws for terrain generation when slots are fixed up front."""

    seed_before = rng.state
    terrain_seed = rng.state
    stamping_draws = _advance_terrain_stamping_rng(
        rng,
        width=width,
        height=height,
    )
    seed_after = rng.state
    return TerrainPreludeResult(
        seed_before=seed_before,
        seed_after=seed_after,
        terrain_slots=terrain_slots,
        terrain_seed=terrain_seed,
        selection_draws=0,
        stamping_draws=stamping_draws,
    )
