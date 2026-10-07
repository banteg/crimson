"""Plaguebearer candidate culling vs the original pool-order radius scan."""

from __future__ import annotations

import random
import struct

from crimson.creatures.runtime import CreaturePool
from crimson.math_parity import f32
from grim.geom import Vec2

from ._support import CREATURE_LAYOUT, CREATURE_POOL_SLOTS, CREATURE_STRIDE

_INFECTION_OFFSET = 0x09
_RADIUS_OFFSETS = (
    Vec2(44.999996185302734, 0.0),
    Vec2(45.0, 0.0),
    Vec2(45.000003814697266, 0.0),
    Vec2(-44.999996185302734, 0.0),
    Vec2(-45.0, 0.0),
    Vec2(0.0, 44.999996185302734),
    Vec2(0.0, -45.0),
    # The wide distance is inside 45, but the native PC24 distance rounds to 45.
    Vec2(14.757906913757324, -42.51122283935547),
)


def test_plaguebearer_spread_matches_native_across_dense_and_sparse_pools(oracle) -> None:
    rng = random.Random(0x00425D80)
    address = oracle.resolve("creature_pool")
    for case in range(128):
        pool = CreaturePool()
        origin_index = (0, 1, 127, 383)[case % 4]
        extent = 60.0 if case % 2 else 1024.0
        center = Vec2() if case % 3 else Vec2(f32(rng.uniform(100.0, 900.0)), f32(rng.uniform(100.0, 900.0)))
        image = bytearray(CREATURE_POOL_SLOTS * CREATURE_STRIDE)
        for index, creature in enumerate(pool.entries):
            creature.active = index == origin_index or rng.random() < 0.8
            creature.plague_infected = bool(rng.getrandbits(1))
            creature.hp = rng.choice((0.0, 100.0, 149.99998474121094, 150.0, 150.00001525878906, 500.0))
            creature.death_timer = rng.choice((-1.0, 0.0, 16.0))
            creature.pos = Vec2(f32(center.x + rng.uniform(-extent, extent)), f32(center.y + rng.uniform(-extent, extent)))
            if index == origin_index:
                creature.pos = center
            elif index < len(_RADIUS_OFFSETS):
                offset = _RADIUS_OFFSETS[(index + case) % len(_RADIUS_OFFSETS)]
                creature.pos = Vec2(f32(center.x + offset.x), f32(center.y + offset.y))
            base = index * CREATURE_STRIDE
            image[base] = int(creature.active)
            image[base + _INFECTION_OFFSET] = int(creature.plague_infected)
            for name, value in (
                ("pos_x", creature.pos.x),
                ("pos_y", creature.pos.y),
                ("health", creature.hp),
                ("death_timer", creature.death_timer),
            ):
                struct.pack_into("<f", image, base + CREATURE_LAYOUT[name][0], value)

        oracle.write(address, image)
        oracle.call("plaguebearer_spread_infection", origin_index)
        pool._plaguebearer_spread_infection(origin_index)

        expected = [
            bool(oracle.read_u8(address + index * CREATURE_STRIDE + _INFECTION_OFFSET))
            for index in range(CREATURE_POOL_SLOTS)
        ]
        assert [creature.plague_infected for creature in pool.entries] == expected, f"case {case}, origin {origin_index}"
