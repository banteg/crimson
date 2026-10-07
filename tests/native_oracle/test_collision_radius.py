"""Collision axis culling vs the original strict PC24 radius predicate."""

from __future__ import annotations

import random
import struct

from crimson.collision_math import creature_find_in_radius, native_find_size_margin
from crimson.creatures.runtime import CreaturePool
from grim.geom import Vec2
from grim.math import f32, i32

from ._support import CREATURE_LAYOUT, CREATURE_POOL_SLOTS, CREATURE_STRIDE


def test_collision_radius_matches_native_at_axis_boundaries_and_translated_positions(oracle) -> None:
    rng = random.Random(0x004206A0)
    pool = CreaturePool()
    address = oracle.resolve("creature_pool")
    origin_address = oracle.alloc_f32s(0.0, 0.0)
    for case in range(512):
        radius = rng.choice((0.0, 8.0, 12.0, 30.0, 66.75615692138672, 128.0))
        size = rng.choice((0.0, 10.0, 32.0, 64.0, 158.70140075683594, 512.0))
        origin = Vec2(f32(rng.uniform(-1024.0, 1024.0)), f32(rng.uniform(-1024.0, 1024.0)))
        if case % 3:
            origin = Vec2()
        reach_bits = struct.unpack("<I", struct.pack("<f", radius + native_find_size_margin(size)))[0]
        edge = struct.unpack("<f", struct.pack("<I", reach_bits + (case % 3) - 1))[0]
        if case % 2:
            edge = -edge
        offset = Vec2(edge, 0.0) if case % 4 < 2 else Vec2(0.0, edge)
        if case % 5 == 0:
            offset = Vec2(rng.uniform(-512.0, 512.0), rng.uniform(-512.0, 512.0))
        position = Vec2(f32(origin.x + offset.x), f32(origin.y + offset.y))
        creature = pool.entries[0]
        creature.active = True
        creature.pos = position
        creature.size = size
        creature.death_timer = rng.choice((5.0, 5.000000476837158, 16.0))

        image = bytearray(CREATURE_POOL_SLOTS * CREATURE_STRIDE)
        image[0] = 1
        for name, value in (("pos_x", position.x), ("pos_y", position.y), ("size", size), ("death_timer", creature.death_timer)):
            struct.pack_into("<f", image, CREATURE_LAYOUT[name][0], value)
        oracle.write(address, image)
        oracle.write(origin_address, struct.pack("<2f", origin.x, origin.y))
        expected = i32(oracle.call("creature_find_in_radius", origin_address, radius, 0).eax)
        actual = creature_find_in_radius(pool.entries, pos=origin, radius=radius, start_index=0)
        assert actual == expected, f"case {case}: {origin}, {position}, radius {radius}, size {size}"
