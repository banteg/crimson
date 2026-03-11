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

    w = max(0, int(width))
    h = max(0, int(height))
    area = int(w * h)
    stamps = (
        int((area * TERRAIN_DENSITY_BASE) >> TERRAIN_DENSITY_SHIFT)
        + int((area * TERRAIN_DENSITY_OVERLAY) >> TERRAIN_DENSITY_SHIFT)
        + int((area * TERRAIN_DENSITY_DETAIL) >> TERRAIN_DENSITY_SHIFT)
    )

    return int(stamps * TERRAIN_RAND_DRAWS_PER_STAMP)


class TerrainPreludeResult(msgspec.Struct, frozen=True):
    seed_before: int
    seed_after: int
    terrain_slots: TerrainSlotTriplet
    terrain_seed: int
    selection_draws: int
    stamping_draws: int

    @property
    def total_draws(self) -> int:
        return int(self.selection_draws) + int(self.stamping_draws)


def _selection_draws_for_result(*, unlock_index: int, terrain_slots: TerrainSlotTriplet) -> int:
    draws = 0
    chosen = tuple(int(slot) for slot in terrain_slots)
    for threshold, slots in UNLOCK_TERRAIN_SLOTS.items():
        if int(unlock_index) < int(threshold):
            continue
        draws += 1
        if chosen == tuple(int(slot) for slot in slots):
            break
        if chosen == tuple(int(slot) for slot in DEFAULT_TERRAIN_SLOTS):
            continue
    return int(draws)


def _advance_terrain_stamping_rng(
    rng: CrandLike,
    *,
    width: int,
    height: int,
) -> int:
    stamping_draws = terrain_stamping_draws(width=int(width), height=int(height))
    for _ in range(int(stamping_draws)):
        rng.rand()
    return int(stamping_draws)


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

    seed_before = int(rng.state)
    terrain_slots = choose_unlock_terrain_slots(unlock_index=int(unlock_index), rng=rng)
    selection_draws = _selection_draws_for_result(
        unlock_index=int(unlock_index),
        terrain_slots=terrain_slots,
    )
    terrain_seed = int(rng.state)
    stamping_draws = _advance_terrain_stamping_rng(
        rng,
        width=int(width),
        height=int(height),
    )
    seed_after = int(rng.state)
    return TerrainPreludeResult(
        seed_before=int(seed_before),
        seed_after=int(seed_after),
        terrain_slots=terrain_slots,
        terrain_seed=int(terrain_seed),
        selection_draws=int(selection_draws),
        stamping_draws=int(stamping_draws),
    )


def run_explicit_terrain_prelude(
    rng: CrandLike,
    *,
    terrain_slots: TerrainSlotTriplet,
    width: int,
    height: int,
) -> TerrainPreludeResult:
    """Consume RNG draws for terrain generation when slots are fixed up front."""

    seed_before = int(rng.state)
    terrain_seed = int(rng.state)
    stamping_draws = _advance_terrain_stamping_rng(
        rng,
        width=int(width),
        height=int(height),
    )
    seed_after = int(rng.state)
    return TerrainPreludeResult(
        seed_before=int(seed_before),
        seed_after=int(seed_after),
        terrain_slots=terrain_slots,
        terrain_seed=int(terrain_seed),
        selection_draws=0,
        stamping_draws=int(stamping_draws),
    )
