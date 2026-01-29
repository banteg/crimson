from __future__ import annotations

import math

import pytest

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import GameplayState


class _StubRand:
    def __init__(self, values: list[int]) -> None:
        self._values = list(values)
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return 0
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def test_split_on_death_spawns_two_smaller_children() -> None:
    state = GameplayState()
    rng = _StubRand([0x123, 0x456])

    pool = CreaturePool()
    parent = pool.entries[0]
    parent.active = True
    parent.flags = CreatureFlags.SPLIT_ON_DEATH
    parent.x = 100.0
    parent.y = 200.0
    parent.heading = 0.0
    parent.hp = 0.0
    parent.max_hp = 400.0
    parent.reward_value = 90.0
    parent.size = 40.0
    parent.move_speed = 2.0
    parent.contact_damage = 10.0

    pool.handle_death(
        0,
        state=state,
        players=[],
        rand=rng.rand,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )

    child1 = pool.entries[1]
    child2 = pool.entries[2]
    assert child1.active and child2.active
    assert child1.hitbox_size == CREATURE_HITBOX_ALIVE
    assert child2.hitbox_size == CREATURE_HITBOX_ALIVE
    assert child1.phase_seed == float(0x123 & 0xFF)
    assert child2.phase_seed == float(0x456 & 0xFF)
    assert child1.heading == pytest.approx(-math.pi / 2.0)
    assert child2.heading == pytest.approx(math.pi / 2.0)
    assert child1.hp == parent.max_hp * 0.25
    assert child2.hp == parent.max_hp * 0.25
    assert child1.size == parent.size - 8.0
    assert child2.size == parent.size - 8.0
    assert child1.move_speed == pytest.approx(parent.move_speed + 0.1)
    assert child2.move_speed == pytest.approx(parent.move_speed + 0.1)
    assert child1.contact_damage == pytest.approx(parent.contact_damage * 0.7)
    assert child2.contact_damage == pytest.approx(parent.contact_damage * 0.7)
    assert child1.reward_value == pytest.approx(parent.reward_value * (2.0 / 3.0))
    assert child2.reward_value == pytest.approx(parent.reward_value * (2.0 / 3.0))
