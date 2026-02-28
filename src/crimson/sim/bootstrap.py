from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

import msgspec

from ..terrain_assets import TerrainTextureId


class RandStream(Protocol):
    @property
    def state(self) -> int: ...

    def rand(self) -> int: ...


BOOTSTRAP_KIND_NONE = "none"
BOOTSTRAP_KIND_TERRAIN_V1 = "terrain_v1"

# Mirror classic `terrain_generate_random` menu selection rules.
TERRAIN_DEFAULT_IDS: tuple[int, int, int] = (
    TerrainTextureId.Q1_BASE,
    TerrainTextureId.Q1_OVERLAY,
    TerrainTextureId.Q1_BASE,
)
TERRAIN_UNLOCK_RULES: tuple[tuple[int, tuple[int, int, int]], ...] = (
    (0x28, (TerrainTextureId.Q4_BASE, TerrainTextureId.Q4_OVERLAY, TerrainTextureId.Q4_BASE)),
    (0x1E, (TerrainTextureId.Q3_BASE, TerrainTextureId.Q3_OVERLAY, TerrainTextureId.Q3_BASE)),
    (0x14, (TerrainTextureId.Q2_BASE, TerrainTextureId.Q2_OVERLAY, TerrainTextureId.Q2_BASE)),
)

# Terrain stamping RNG consumption mirrors `grim/terrain_render.py` + `docs/crimsonland-exe/terrain.md`.
TERRAIN_DENSITY_BASE = 800
TERRAIN_DENSITY_OVERLAY = 0x23
TERRAIN_DENSITY_DETAIL = 0x0F
TERRAIN_DENSITY_SHIFT = 19
TERRAIN_RAND_DRAWS_PER_STAMP = 3  # rotation, then position draws (see terrain renderer parity notes)


def choose_terrain_ids(
    *,
    quest_unlock_index: int,
    rand: Callable[[], int],
) -> tuple[int, int, int]:
    """Choose classic terrain IDs using the canonical RNG stream."""

    unlock_index = int(quest_unlock_index)
    for threshold, ids in TERRAIN_UNLOCK_RULES:
        if unlock_index >= int(threshold) and (int(rand()) & 7) == 3:
            return ids
    return TERRAIN_DEFAULT_IDS


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
    terrain_ids: tuple[int, int, int]
    terrain_seed: int
    selection_draws: int
    stamping_draws: int

    @property
    def total_draws(self) -> int:
        return int(self.selection_draws) + int(self.stamping_draws)


def run_terrain_bootstrap(
    rng: RandStream,
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

    terrain_ids = choose_terrain_ids(quest_unlock_index=int(quest_unlock_index), rand=_rand)
    terrain_seed = int(rng.state)

    stamping_draws = terrain_stamping_draws(width=int(width), height=int(height), layers=int(layers))
    for _ in range(int(stamping_draws)):
        rng.rand()

    seed_after = int(rng.state)
    return TerrainBootstrapResult(
        kind=BOOTSTRAP_KIND_TERRAIN_V1,
        seed_before=int(seed_before),
        seed_after=int(seed_after),
        terrain_ids=(int(terrain_ids[0]), int(terrain_ids[1]), int(terrain_ids[2])),
        terrain_seed=int(terrain_seed),
        selection_draws=int(selection_draws),
        stamping_draws=int(stamping_draws),
    )
