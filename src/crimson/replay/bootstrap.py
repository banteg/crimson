from __future__ import annotations

from typing import Protocol

import msgspec

from ..sim.bootstrap import (
    BOOTSTRAP_KIND_NONE,
    BOOTSTRAP_KIND_TERRAIN_V1,
    TerrainBootstrapResult,
    run_terrain_bootstrap,
)
from .types import ReplayHeader


class ReplayBootstrapError(ValueError):
    pass


class ReplayRng(Protocol):
    @property
    def state(self) -> int: ...

    def srand(self, seed: int) -> None: ...

    def rand(self) -> int: ...


class AppliedReplayBootstrap(msgspec.Struct, frozen=True):
    """Bootstrap data produced when applying a replay header."""

    terrain: TerrainBootstrapResult


def apply_replay_bootstrap(
    header: ReplayHeader,
    *,
    rng: ReplayRng,
    world_size: float,
    strict: bool = True,
) -> AppliedReplayBootstrap | None:
    """Seed/advance `rng` to tick-0 state for a replay header.

    - If `header.bootstrap_kind` is `none`, this seeds directly from `header.seed`.
    - If `bootstrap_kind` is `terrain_v1`, this seeds from `header.bootstrap_seed` and consumes the deterministic
      terrain bootstrap window, then (optionally) validates `header.seed` matches the computed tick-0 RNG state.
    """

    kind = str(header.bootstrap_kind)
    if kind == BOOTSTRAP_KIND_NONE:
        rng.srand(int(header.seed))
        return None

    if kind != BOOTSTRAP_KIND_TERRAIN_V1:
        if strict:
            raise ReplayBootstrapError(f"unsupported replay bootstrap_kind={kind!r}")
        rng.srand(int(header.seed))
        return None

    bootstrap_seed = int(header.bootstrap_seed)
    width = max(1, int(float(world_size)))
    height = width

    rng.srand(int(bootstrap_seed))
    terrain = run_terrain_bootstrap(
        rng,
        quest_unlock_index=int(header.status.quest_unlock_index),
        width=int(width),
        height=int(height),
        layers=3,
    )

    if strict:
        if int(header.seed) != int(terrain.seed_after):
            raise ReplayBootstrapError(
                f"bootstrap seed mismatch: header.seed={int(header.seed)} != computed={int(terrain.seed_after)}",
            )

    return AppliedReplayBootstrap(terrain=terrain)
