"""`creature_handle_death` (0x0041e910) vs the port's `CreaturePool.handle_death`.

Each case kills pool slot 0 from the same `crt_rand` seed on both sides, across corpse-keeping and
eaten deaths, split-on-death parents, Quick Learner, Double Experience, Freeze and the kill-drop
guard, then compares the parent and its split children, player one's XP, the kill count, the
fx queue, the effect pool and the RNG state.
"""

from __future__ import annotations

import random

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.factories import kill_creature, world_with_creature

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_STRIDE,
    PLAYER_OFFSETS,
    Mismatch,
    compare_effect_pool,
    compare_fields,
    mismatch_report,
    prepare_gameplay,
)

_CREATURE_WRITES = (
    "death_timer", "pos_x", "pos_y", "health", "max_health", "heading", "size",
    "contact_damage", "move_speed", "reward_value",
)  # fmt: skip


def _python_creature(creature: CreatureState) -> dict[str, float | int | None]:
    return {
        "active": int(creature.active),
        "phase_seed": creature.phase_seed,
        "death_timer": creature.death_timer,
        "pos_x": creature.pos.x,
        "pos_y": creature.pos.y,
        "health": creature.hp,
        "max_health": creature.max_hp,
        "heading": creature.heading,
        "size": creature.size,
        "contact_damage": creature.contact_damage,
        "move_speed": creature.move_speed,
        "reward_value": creature.reward_value,
        "flags": int(creature.flags),
    }


def test_creature_handle_death_matches_native(oracle) -> None:
    prepare_gameplay(oracle)
    oracle.write_u32("config_detail_preset", 5)
    quick_learner_count = oracle.resolve("player_perk_counts") + 4 * int(PerkId.BLOODY_MESS_QUICK_LEARNER)
    oracle.write_u32("perk_id_bloody_mess_quick_learner", int(PerkId.BLOODY_MESS_QUICK_LEARNER))
    pristine = oracle.snapshot()
    pool_address = oracle.resolve("creature_pool")
    rng = random.Random(0x41E910)
    mismatches: list[Mismatch] = []
    cases = 600
    for case_index in range(cases):
        seed = rng.getrandbits(32)
        keep_corpse = rng.random() < 0.7
        split = rng.random() < 0.4
        quick_learner = rng.random() < 0.3
        double_experience = rng.choice((0.0, 3.0))
        freeze = rng.choice((0.0, 0.0, 2.0))
        guard = rng.random() < 0.3
        weapon_id = rng.choice((WeaponId.PISTOL, WeaponId.ASSAULT_RIFLE))
        experience = rng.choice((rng.randrange(0, 1 << 20), rng.randrange(1 << 24, 1 << 26)))
        dt = f32(rng.uniform(0.001, 0.05))
        values = {
            "death_timer": f32(rng.choice((16.0, rng.uniform(0.0, 16.0)))),
            "pos_x": f32(rng.uniform(40.0, 980.0)),
            "pos_y": f32(rng.uniform(40.0, 980.0)),
            "health": f32(rng.uniform(-30.0, 0.0)),
            "max_health": f32(rng.uniform(10.0, 800.0)),
            "heading": f32(rng.uniform(-7.0, 7.0)),
            "size": f32(rng.uniform(20.0, 70.0)),
            "contact_damage": f32(rng.uniform(0.0, 40.0)),
            "move_speed": f32(rng.uniform(0.5, 3.0)),
            "reward_value": f32(rng.uniform(0.0, 500.0)),
        }
        flags = CreatureFlags.SPLIT_ON_DEATH if split else CreatureFlags(0)
        case = (
            f"case={case_index} seed=0x{seed:08x} keep_corpse={keep_corpse} split={split} "
            f"quick_learner={quick_learner} double={double_experience} freeze={freeze} guard={guard}"
        )

        oracle.restore(pristine)
        oracle.rand_state = seed
        oracle.write_f32("frame_dt", dt)
        oracle.write_u32("player_experience", experience)
        oracle.write_u32(quick_learner_count, int(quick_learner))
        oracle.write_f32("bonus_double_xp_timer", double_experience)
        oracle.write_f32("bonus_freeze_timer", freeze)
        oracle.write_u8("scripted_burst_active", int(guard))
        oracle.write_u32(oracle.resolve("player_state_table") + PLAYER_OFFSETS["weapon_id"], int(weapon_id))
        oracle.write_u8(pool_address, 1)
        for name in _CREATURE_WRITES:
            oracle.write_f32(pool_address + CREATURE_LAYOUT[name][0], values[name])
        oracle.write_u32(pool_address + CREATURE_LAYOUT["flags"][0], int(flags))
        oracle.call("creature_handle_death", 0, int(keep_corpse))

        player = PlayerState(index=0, pos=Vec2(), experience=experience, weapon=WeaponSlot(weapon_id=weapon_id))
        world = world_with_creature(
            CreatureState(
                active=True,
                death_timer=values["death_timer"],
                pos=Vec2(values["pos_x"], values["pos_y"]),
                hp=values["health"],
                max_hp=values["max_health"],
                heading=values["heading"],
                size=values["size"],
                contact_damage=values["contact_damage"],
                move_speed=values["move_speed"],
                reward_value=values["reward_value"],
                flags=flags,
            ),
            players=[player],
        )
        # The native kill drop compares every drop's amount with the held weapon id.
        world.state.preserve_bugs = True
        world.state.rng.srand(seed)
        if quick_learner:
            world.state.perks[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1
        world.state.bonuses.double_experience = double_experience
        world.state.bonuses.freeze = freeze
        world.state.scripted_burst_active = guard
        fx_queue = FxQueue()
        kill_creature(world, keep_corpse=keep_corpse, fx_queue=fx_queue, dt=dt)

        # Split children land in the first free slots, 1 and 2.
        for index in range(3 if split and values["size"] > 35.0 else 1):
            address = pool_address + index * CREATURE_STRIDE
            mismatches += compare_fields(
                f"{case} creature[{index}]",
                oracle.read_fields(address, CREATURE_LAYOUT),
                _python_creature(world.creatures.entries[index]),
                address=address,
            )
        for field, native, python in (
            ("experience", oracle.read_i32("player_experience"), player.experience),
            ("kill_count", oracle.read_u32("creature_kill_count"), world.creatures.kill_count),
            ("fx_queue_count", oracle.read_u32("fx_queue_count"), fx_queue.count),
            ("rand_state", oracle.rand_state, world.state.rng.state),
        ):
            if native != python:
                mismatches.append(Mismatch(case, field, native, python, 0))
        mismatches += compare_effect_pool(oracle, world.state.effects, case)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
