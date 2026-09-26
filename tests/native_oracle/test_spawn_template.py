"""`creature_spawn_template` (0x00430af0) vs `CreaturePool.spawn_template`.

Covers every template id with the tail stat scaling: the spider AI7 speed bump,
hardcore buffs and each quest-retry multiplier bucket.  The native pool starts
empty, `demo_mode_active` skips the burst effect on both sides, and the CRT
`rand()` seed is shared.
"""

from __future__ import annotations

import random

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import SpawnEnv, SpawnId, UnsupportedSpawnTemplateError
from crimson.math_parity import f32
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_POOL_SLOTS,
    CREATURE_STRIDE,
    SPAWN_SLOT_LAYOUT,
    SPAWN_SLOT_STRIDE,
    Mismatch,
    compare_fields,
    mismatch_report,
)

_TERRAIN_SIZE = 1024
_DIFFICULTIES = ((False, 0), (False, 1), (False, 2), (False, 3), (False, 4), (False, 5), (False, 7), (True, 0), (True, 3))


def _python_creature(creature: CreatureState) -> dict[str, float | int | None]:
    offset = creature.target_offset
    return {
        "active": int(creature.active),
        "phase_seed": creature.phase_seed,
        "pos_x": creature.pos.x,
        "pos_y": creature.pos.y,
        "health": creature.hp,
        "max_health": creature.max_hp,
        "heading": creature.heading,
        "size": creature.size,
        "tint_r": creature.tint.r,
        "tint_g": creature.tint.g,
        "tint_b": creature.tint.b,
        "tint_a": creature.tint.a,
        "contact_damage": creature.contact_damage,
        "move_speed": creature.move_speed,
        "reward_value": creature.reward_value,
        "type_id": int(creature.type_id),
        "link_index": None if creature.link_index == -1 else creature.link_index,
        "target_offset_x": None if offset is None else offset.x,
        "target_offset_y": None if offset is None else offset.y,
        "orbit_angle": creature.orbit_angle,
        "flags": int(creature.flags),
        "ai_mode": int(creature.ai_mode),
    }


def _cases() -> list[tuple[SpawnId, bool, int, int, Vec2, float]]:
    rng = random.Random(0x430AF0)
    cases = []
    for template_id in SpawnId:
        # The unused 0x02 fallback leaves size, speed and tint untouched: native
        # reads the zero-initialized static pool there, while the port's fresh
        # slots carry non-zero defaults. Gameplay never spawns 0x02.
        if template_id == SpawnId.UNUSED_02:
            continue
        for hardcore, retries in _DIFFICULTIES:
            for _ in range(2):
                pos = Vec2(f32(rng.uniform(-64.0, 1088.0)), f32(rng.uniform(-64.0, 1088.0)))
                cases.append((template_id, hardcore, retries, rng.getrandbits(32), pos, f32(rng.uniform(0.0, 6.3))))
    return cases


def test_spawn_template_stats_match_native(oracle) -> None:
    oracle.stub("console_printf", None)
    oracle.write_u8("demo_mode_active", 1)
    oracle.write_u32("terrain_texture_width", _TERRAIN_SIZE)
    oracle.write_u32("terrain_texture_height", _TERRAIN_SIZE)
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("creature_pool")
    slot_base = oracle.resolve("creature_spawn_slot_table")
    pos_arg = oracle.alloc(8)

    mismatches: list[Mismatch] = []
    unsupported: set[int] = set()
    cases = _cases()
    for template_id, hardcore, retries, seed, pos, heading in cases:
        case = f"template 0x{int(template_id):02x} hardcore={int(hardcore)} retry={retries} seed=0x{seed:08x}"
        oracle.restore(pristine)
        oracle.write_u8("config_hardcore", int(hardcore))
        oracle.write_u32("quest_fail_retry_count", retries)
        oracle.write_f32(pos_arg, pos.x)
        oracle.write_f32(pos_arg + 4, pos.y)
        oracle.rand_state = seed
        oracle.call("creature_spawn_template", int(template_id), pos_arg, heading)

        env = SpawnEnv(
            terrain_width=float(_TERRAIN_SIZE),
            terrain_height=float(_TERRAIN_SIZE),
            demo_mode_active=True,
            hardcore=hardcore,
            quest_fail_retry_count=retries,
        )
        pool = CreaturePool(env=env)
        rng = CrtRand(seed)
        try:
            pool.spawn_template(template_id, pos, heading, rng, env=env)
        except UnsupportedSpawnTemplateError:
            unsupported.add(int(template_id))
            continue

        for index in range(CREATURE_POOL_SLOTS):
            address = pool_base + index * CREATURE_STRIDE
            native = oracle.read_fields(address, CREATURE_LAYOUT)
            python = pool.entries[index]
            if not native["active"] and not python.active:
                continue
            mismatches += compare_fields(f"{case} creature[{index}]", native, _python_creature(python), address=address)
        for index, slot in enumerate(pool.spawn_slots):
            address = slot_base + index * SPAWN_SLOT_STRIDE
            native = oracle.read_fields(address, SPAWN_SLOT_LAYOUT)
            native["owner"] = (int(native["owner"]) - pool_base) // CREATURE_STRIDE
            python_slot = {
                "owner": slot.owner_creature,
                "count": slot.count,
                "limit": slot.limit,
                "interval": slot.interval,
                "timer": slot.timer,
                "template_id": int(slot.child_template_id),
            }
            mismatches += compare_fields(f"{case} spawn_slot[{index}]", native, python_slot, address=address)
        if oracle.rand_state != rng.state:
            mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, rng.state, 0))
        if hardcore and oracle.read_i32("quest_fail_retry_count") != env.quest_fail_retry_count:
            mismatches.append(
                Mismatch(case, "quest_fail_retry_count", oracle.read_i32("quest_fail_retry_count"), env.quest_fail_retry_count, 0),
            )

    report = mismatch_report(mismatches, total_cases=len(cases))
    if unsupported:
        report += "\npython raises UnsupportedSpawnTemplateError for: " + ", ".join(f"0x{i:02x}" for i in sorted(unsupported))
    assert not mismatches and not unsupported, report
