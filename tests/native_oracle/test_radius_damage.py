"""Radius damage reaches later split children, but never revisits earlier slots."""

from __future__ import annotations

import random
import struct

from crimson.creatures.damage import creatures_apply_radius_damage
from crimson.creatures.damage_types import CreatureDamageType
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spatial_hash import CreatureSpatialHash
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue
from crimson.math_parity import f32
from grim.geom import Vec2
from tests.support.factories import make_step_runtime, world_with_creature

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_STRIDE,
    Mismatch,
    compare_effect_pool,
    compare_fields,
    mismatch_report,
    prepare_gameplay,
)


def _fields(creature: CreatureState) -> dict[str, float | int]:
    return {
        "active": int(creature.active), "phase_seed": creature.phase_seed,
        "death_timer": creature.death_timer, "pos_x": creature.pos.x, "pos_y": creature.pos.y,
        "vel_x": creature.vel.x, "vel_y": creature.vel.y,
        "health": creature.hp, "max_health": creature.max_hp, "heading": creature.heading,
        "size": creature.size, "contact_damage": creature.contact_damage,
        "move_speed": creature.move_speed, "reward_value": creature.reward_value,
        "flags": int(creature.flags), "type_id": int(creature.type_id),
    }


def test_radius_damage_matches_native_with_split_children_in_earlier_and_later_slots(oracle) -> None:
    prepare_gameplay(oracle)
    oracle.write_u32("config_detail_preset", 5)
    oracle.write_u8("scripted_burst_active", 1)
    origin_address = oracle.alloc_f32s(512.0, 512.0)
    pristine = oracle.snapshot()
    address = oracle.resolve("creature_pool")
    rng = random.Random(0x420300)
    mismatches: list[Mismatch] = []
    split_parent_indices: set[int] = set()
    cases = 96
    for case in range(cases):
        oracle.restore(pristine)
        seed = rng.getrandbits(32)
        oracle.rand_state = seed
        oracle.write_f32("frame_dt", f32(0.016))
        world = world_with_creature(CreatureState())
        world.state.preserve_bugs = True
        world.state.scripted_burst_active = True
        world.state.rng.srand(seed)
        parent_index = case % 3 * 2
        for index in range(7):
            creature = world.creatures.entries[index]
            creature.active = index == parent_index or (index % 2 == 1 and case % 2 == 0)
            creature.pos = Vec2(f32(512.0 + rng.uniform(-160.0, 160.0)), f32(512.0 + rng.uniform(-160.0, 160.0)))
            creature.hp = f32(rng.choice((1.0, 100.0)))
            creature.max_hp = 100.0
            creature.size = f32(rng.choice((34.0, 36.0, 50.0, 70.0)))
            creature.reward_value = 10.0
            creature.death_timer = rng.choice((5.0, 5.000000476837158, 16.0))
            creature.flags = CreatureFlags.SPLIT_ON_DEATH if index == parent_index else CreatureFlags(0)
            if index == parent_index:
                creature.pos = Vec2(512.0, 512.0)
                creature.death_timer = 16.0
            for name, value in _fields(creature).items():
                offset, fmt = CREATURE_LAYOUT[name]
                oracle.write(address + index * CREATURE_STRIDE + offset, struct.pack("<" + fmt, value))
        radius = rng.choice((0.0, 12.0, 128.0, 300.0))
        damage = rng.choice((0.25, 5.0, 200.0))
        fx_queue = FxQueue()
        step = make_step_runtime(world, dt=f32(0.016), fx_queue=fx_queue)
        spatial = CreatureSpatialHash(pool=world.creatures, is_collidable=lambda c: c.active and c.death_timer > 5.0)
        oracle.call("creatures_apply_radius_damage", origin_address, radius, damage, int(CreatureDamageType.ION))
        creatures_apply_radius_damage(step, Vec2(512.0, 512.0), radius, damage, int(CreatureDamageType.ION), creature_spatial=spatial)
        if world.creatures.alloc_count:
            split_parent_indices.add(parent_index)
        for index, creature in enumerate(world.creatures.entries):
            native = oracle.read_fields(address + index * CREATURE_STRIDE, CREATURE_LAYOUT)
            if creature.active or native["active"]:
                mismatches += compare_fields(f"case {case}, slot {index}", native, _fields(creature), address=address + index * CREATURE_STRIDE)
        for name, native, python in (
            ("xp", oracle.read_i32("player_experience"), world.players[0].experience),
            ("kills", oracle.read_u32("creature_kill_count"), world.creatures.kill_count),
            ("fx_queue", oracle.read_u32("fx_queue_count"), fx_queue.count),
            ("rng", oracle.rand_state, world.state.rng.state),
        ):
            if native != python:
                mismatches.append(Mismatch(f"case {case}", name, native, python, 0))
        mismatches += compare_effect_pool(oracle, world.state.effects, f"case {case}")
    assert split_parent_indices == {0, 2, 4}
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
