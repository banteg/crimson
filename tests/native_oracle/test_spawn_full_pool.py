"""`creature_spawn_template` into an almost full pool vs `CreaturePool.spawn_template`.

Native has no failure path: `creature_alloc_slot` draws a phase seed per free slot it hands out and returns 0x180,
one past the pool, once the pool is full, and the spawn writes that creature there anyway. With a few free slots a
formation's root and its first members still land in the pool.

Each case spawns two templates back to back, so the second one sees the phantom slot's and the spawn-slot table's
state from the first.
"""

from __future__ import annotations

import random

from crimson.creatures.runtime import PHANTOM_CREATURE_INDEX, CreaturePool
from crimson.creatures.spawn import SpawnId
from crimson.math_parity import f32
from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import CREATURE_LAYOUT, CREATURE_POOL_SLOTS, CREATURE_STRIDE, Mismatch, compare_fields, mismatch_report
from .test_spawn_template import _python_creature, compare_spawn_slots

_FREE_COUNTS = (0, 1, 2, 3, 5)
# Gameplay never spawns the unused 0x02: native reads the zero-initialized static pool where the port's fresh slots
# carry non-zero defaults.
_TEMPLATES = tuple(template_id for template_id in SpawnId if template_id != SpawnId.UNUSED_02)


def test_spawn_template_into_a_nearly_full_pool_matches_native(oracle) -> None:
    oracle.stub("console_printf", None)
    # The pool-full path reads `cv_verbose->value` before logging.
    oracle.write_u32("cv_verbose", oracle.alloc(0x20))
    oracle.call("effect_defaults_reset")
    oracle.write_u8("demo_mode_active", 0)
    oracle.write_u32("terrain_texture_width", 1024)
    oracle.write_u32("terrain_texture_height", 1024)
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("creature_pool")
    pos_arg = oracle.alloc(8)
    active_offset = CREATURE_LAYOUT["active"][0]

    rng = random.Random(0x430AF1)
    mismatches: list[Mismatch] = []
    cases = 0
    for template_id in _TEMPLATES:
        for free in _FREE_COUNTS:
            free_slots = set(rng.sample(range(CREATURE_POOL_SLOTS), free))
            spawns = [(template_id, rng.getrandbits(32)), (rng.choice(_TEMPLATES), rng.getrandbits(32))]
            pos = Vec2(f32(rng.uniform(64.0, 960.0)), f32(rng.uniform(64.0, 960.0)))
            heading = f32(rng.uniform(0.0, 6.3))
            case = f"templates {[f'0x{int(t):02x}/0x{s:08x}' for t, s in spawns]} free={sorted(free_slots)}"

            pool = CreaturePool()
            oracle.restore(pristine)
            for index in range(CREATURE_POOL_SLOTS):
                occupied = index not in free_slots
                oracle.write_u8(pool_base + index * CREATURE_STRIDE + active_offset, int(occupied))
                pool.entries[index].active = occupied
            oracle.write_f32(pos_arg, pos.x)
            oracle.write_f32(pos_arg + 4, pos.y)
            for spawn_id, seed in spawns:
                oracle.rand_state = seed
                oracle.call("creature_spawn_template", int(spawn_id), pos_arg, heading)
                crand = CrtRand(seed)
                pool.spawn_template(spawn_id, pos, heading, state=GameplayState(rng=crand), detail_preset=5)
                if oracle.rand_state != crand.state:
                    mismatches.append(Mismatch(f"{case} 0x{int(spawn_id):02x}", "rand_state", oracle.rand_state, crand.state, 0))
            cases += 1

            for index in sorted(free_slots):
                address = pool_base + index * CREATURE_STRIDE
                native = oracle.read_fields(address, CREATURE_LAYOUT)
                python = pool.entries[index]
                if not native["active"] and not python.active:
                    continue
                mismatches += compare_fields(f"{case} creature[{index}]", native, _python_creature(python), address=address)
            address = pool_base + PHANTOM_CREATURE_INDEX * CREATURE_STRIDE
            native = oracle.read_fields(address, CREATURE_LAYOUT)
            mismatches += compare_fields(f"{case} phantom", native, _python_creature(pool.phantom), address=address)
            mismatches += compare_spawn_slots(oracle, case, pool)

    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
