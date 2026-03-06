from __future__ import annotations

import msgspec

from grim.rand import CrandLike

from ..terrain_slots import (
    TerrainSlotTriplet,
    choose_menu_terrain_slots,
)

BOOTSTRAP_KIND_NONE = "none"
BOOTSTRAP_KIND_TERRAIN_V1 = "terrain_v1"

# Terrain stamping RNG consumption mirrors `grim/terrain_render.py` + `docs/crimsonland-exe/terrain.md`.
TERRAIN_DENSITY_BASE = 800
TERRAIN_DENSITY_OVERLAY = 0x23
TERRAIN_DENSITY_DETAIL = 0x0F
TERRAIN_DENSITY_SHIFT = 19
TERRAIN_RAND_DRAWS_PER_STAMP = 3  # rotation, then position draws (see terrain renderer parity notes)


def terrain_stamping_draws(*, width: int, height: int, layers: int = 3) -> int:
    """Return the number of `rand()` draws consumed by the procedural terrain stamps."""

    w = max(0, int(width))
    h = max(0, int(height))
    area = int(w * h)
    layers = max(0, min(int(layers), 3))

    stamps = 0
    if layers >= 1:
        stamps += int((area * TERRAIN_DENSITY_BASE) >> TERRAIN_DENSITY_SHIFT)
    if layers >= 2:
        stamps += int((area * TERRAIN_DENSITY_OVERLAY) >> TERRAIN_DENSITY_SHIFT)
    if layers >= 3:
        stamps += int((area * TERRAIN_DENSITY_DETAIL) >> TERRAIN_DENSITY_SHIFT)

    return int(stamps * TERRAIN_RAND_DRAWS_PER_STAMP)


class TerrainBootstrapResult(msgspec.Struct, frozen=True):
    kind: str
    seed_before: int
    seed_after: int
    terrain_slots: TerrainSlotTriplet
    terrain_seed: int
    selection_draws: int
    stamping_draws: int

    @property
    def total_draws(self) -> int:
        return int(self.selection_draws) + int(self.stamping_draws)


def run_terrain_bootstrap(
    rng: CrandLike,
    *,
    quest_unlock_index: int,
    width: int,
    height: int,
    layers: int = 3,
) -> TerrainBootstrapResult:
    """Consume RNG draws performed by the classic boot/menu terrain generation.

    This is a simulation bootstrap step: it advances the authoritative gameplay RNG
    to match the exe's terrain generation window while also returning the terrain
    descriptor + seed needed for deterministic rendering.
    """

    seed_before = int(rng.state)
    selection_draws = 0

    def _rand() -> int:
        nonlocal selection_draws
        selection_draws += 1
        return int(rng.rand())

    terrain_slots = choose_menu_terrain_slots(quest_unlock_index=int(quest_unlock_index), rand=_rand)
    terrain_seed = int(rng.state)

    stamping_draws = terrain_stamping_draws(width=int(width), height=int(height), layers=int(layers))
    for _ in range(int(stamping_draws)):
        rng.rand()

    seed_after = int(rng.state)
    return TerrainBootstrapResult(
        kind=BOOTSTRAP_KIND_TERRAIN_V1,
        seed_before=int(seed_before),
        seed_after=int(seed_after),
        terrain_slots=terrain_slots,
        terrain_seed=int(terrain_seed),
        selection_draws=int(selection_draws),
        stamping_draws=int(stamping_draws),
    )
