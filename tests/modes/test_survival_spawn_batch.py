from __future__ import annotations

from collections.abc import Iterator
from typing import SupportsIndex, overload

import msgspec
import pytest

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.sim.mode_updates import SurvivalSpawnState, survival_update
from grim.rand import Crand, CrandLike, RecordingCrand
from tests.support.builders.session import make_world


def _pool_snapshot(pool: CreaturePool, spawn: SurvivalSpawnState) -> bytes:
    return msgspec.msgpack.encode((
        pool.entries, pool.phantom, pool.spawn_slots, pool.kill_count,
        pool.alloc_count, pool.spawned_count, spawn,
    ))


@pytest.mark.parametrize("preserve_bugs", (False, True))
@pytest.mark.parametrize(
    ("free_slots", "experience", "player_count", "elapsed_ms"),
    [
        ((), 143_802_723, 1, 2_154_555),
        ((0, 17, 383), 30_000, 2, 905_400),
        (tuple(range(384)), 120_000, 1, 1_800_000),
        ((1, 100, 200), 0, 4, 900_000),
    ],
)
def test_survival_batch_matches_searching_from_zero(
    monkeypatch: pytest.MonkeyPatch,
    preserve_bugs: bool,
    free_slots: tuple[int, ...],
    experience: int,
    player_count: int,
    elapsed_ms: int,
) -> None:
    worlds = [make_world(seed=97, player_count=player_count, preserve_bugs=preserve_bugs) for _ in range(2)]
    rngs = [RecordingCrand(Crand(97)) for _ in worlds]
    spawns = [SurvivalSpawnState(stage=10) for _ in worlds]
    for world, rng in zip(worlds, rngs, strict=True):
        world.state.rng = rng
        world.state.survival_shrinkifier_handout_enabled = False
        world.players[0].experience = experience
        for index, creature in enumerate(world.creatures.entries):
            creature.active = index not in free_slots
            creature.generation = 7
            creature.link_index = 23
        world.creatures.phantom.link_index = 19
        world.creatures.phantom.generation = 11

    original_alloc = CreaturePool.alloc_slot

    def search_from_zero(pool: CreaturePool, rng: CrandLike, *, start_index: int = 0) -> int:
        return original_alloc(pool, rng)

    # A later free must be visible even if the previous wave saturated the pool.
    for update in range(2):
        if update:
            for world in worlds:
                for index in (0, 17):
                    world.creatures.entries[index].active = False
        survival_update(worlds[0], spawns[0], elapsed_ms=elapsed_ms, dt_ms=16)
        with monkeypatch.context() as patch:
            patch.setattr(CreaturePool, "alloc_slot", search_from_zero)
            survival_update(worlds[1], spawns[1], elapsed_ms=elapsed_ms, dt_ms=16)
        assert _pool_snapshot(worlds[0].creatures, spawns[0]) == _pool_snapshot(worlds[1].creatures, spawns[1])
        assert rngs[0].records == rngs[1].records
        assert rngs[0].state == rngs[1].state


class _CountedEntries(list[CreatureState]):
    reads: int = 0

    @overload
    def __getitem__(self, index: SupportsIndex) -> CreatureState: ...

    @overload
    def __getitem__(self, index: slice[SupportsIndex | None]) -> list[CreatureState]: ...

    def __getitem__(self, index: SupportsIndex | slice[SupportsIndex | None]) -> CreatureState | list[CreatureState]:
        self.reads += 1
        return super().__getitem__(index)

    def __iter__(self) -> Iterator[CreatureState]:
        for entry in super().__iter__():
            self.reads += 1
            yield entry


def test_saturated_survival_wave_scans_pool_once() -> None:
    world = make_world(seed=97)
    world.state.survival_shrinkifier_handout_enabled = False
    world.players[0].experience = 143_802_723
    for creature in world.creatures.entries:
        creature.active = True
    counted = _CountedEntries(world.creatures.entries)
    world.creatures._entries = counted
    rng = RecordingCrand(Crand(97))
    world.state.rng = rng

    survival_update(world, SurvivalSpawnState(stage=10), elapsed_ms=2_154_555, dt_ms=16)

    # The original performs 5,584 * 384 reads; all 83,533 draws still happen.
    assert counted.reads == 384
    assert rng.calls == 83_533
    assert world.creatures.phantom.active
    assert world.creatures.alloc_count == 0
