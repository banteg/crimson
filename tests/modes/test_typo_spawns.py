from __future__ import annotations

import math

from crimson.creatures.spawn import CreatureTypeId
from crimson.math_parity import f32
from crimson.sim.state_types import TERRAIN_SIZE
from crimson.sim.world_state import WorldState
from crimson.typo.runtime import typo_mode_update
from crimson.typo.state import reset_typo_state
from tests.support.builders.session import make_world


def _typo_world() -> WorldState:
    world = make_world()
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries), dictionary_words=("word",))
    return world


def _spawned(world: WorldState) -> list[tuple[CreatureTypeId, float, float]]:
    return [(creature.type_id, creature.pos.x, creature.pos.y) for creature in world.creatures.entries if creature.active]


def test_typo_spawns_a_spider_and_alien_pair_from_the_sides() -> None:
    world = _typo_world()

    typo_mode_update(world, elapsed_ms=0.0, dt_ms=1.0)

    assert world.state.typo.spawn_cooldown_ms == 3499
    y = 256.0 + TERRAIN_SIZE * 0.5
    assert _spawned(world) == [
        (CreatureTypeId.SPIDER_SP2, TERRAIN_SIZE + 64.0, y),
        (CreatureTypeId.ALIEN, -64.0, y),
    ]


def test_typo_spawns_a_pair_per_elapsed_cooldown() -> None:
    world = _typo_world()

    typo_mode_update(world, elapsed_ms=8000.0, dt_ms=10_000.0)

    spawned = _spawned(world)
    assert world.state.typo.spawn_cooldown_ms >= 100
    assert len(spawned) >= 2 and len(spawned) % 2 == 0
    assert {type_id for type_id, _, _ in spawned} == {CreatureTypeId.SPIDER_SP2, CreatureTypeId.ALIEN}
    # Native: fcos(8000 * 0.001f) stays wide into the PC24 `* 256.0f`, then `+ h * 0.5f`.
    assert spawned[0][2] == f32(f32(math.cos(f32(8000.0 * f32(0.001))) * 256.0) + TERRAIN_SIZE * 0.5)
