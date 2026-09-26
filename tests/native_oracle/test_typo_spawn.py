"""Typ-o spawn block vs `typo_mid_step`.

Runs the spawn fragment of `typo_gameplay_update_and_render` natively
(0x00445a62..0x00445c85: cooldown, tint/position math, `creature_spawn_tinted`)
and compares the spawned creatures and the cooldown with the port.  Name
assignment is outside this check: the native `typo_target_name_assign_random`
is stubbed to resync the RNG to the port's draw stream after each spawn.
"""

from __future__ import annotations

import random

from crimson.creatures.runtime import CreatureState
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.sessions import MidStepContext
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from crimson.typo.runtime import typo_mid_step
from crimson.typo.state import reset_typo_state
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import CREATURE_LAYOUT, CREATURE_POOL_SLOTS, CREATURE_STRIDE, Mismatch, compare_fields, mismatch_report

_SPAWN_BLOCK_START = 0x00445A62
_SPAWN_BLOCK_END = 0x00445C85
_WORLD_SIZE = 1024


def _python_creature(creature: CreatureState) -> dict[str, float | int | None]:
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
        "flags": int(creature.flags),
        "ai_mode": int(creature.ai_mode),
    }


def _python_step(seed: int, *, elapsed_ms: int, dt_ms: int, cooldown_ms: int) -> tuple[WorldState, list[int]]:
    """Run the port's spawn step; return the world and the RNG state before each creature allocation."""

    world = WorldState.build(world_size=float(_WORLD_SIZE), demo_mode_active=False, hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    reset_typo_state(world.state.typo, creature_capacity=len(world.creatures.entries))
    world.state.typo.spawn_cooldown_ms = cooldown_ms
    rng = CrtRand(seed)
    alloc_states: list[int] = []

    def sink(state_before: int, _state_after: int, _value: int, caller: int | None) -> None:
        if caller == RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED:
            alloc_states.append(state_before)

    rng.set_trace_sink(sink)
    world.state.rng = rng
    typo_mid_step(
        MidStepContext(
            world=world,
            elapsed_before_ms=float(elapsed_ms),
            dt_sim_ms=float(dt_ms),
            dt_raw_ms=float(dt_ms),
            world_size=float(_WORLD_SIZE),
        ),
    )
    return world, alloc_states


def test_typo_spawn_block_matches_native(oracle) -> None:
    oracle.write_u32("terrain_texture_width", _WORLD_SIZE)
    oracle.write_u32("terrain_texture_height", _WORLD_SIZE)
    oracle.write_u32("config_player_count", 1)
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("creature_pool")

    rng = random.Random(0x445A62)
    mismatches: list[Mismatch] = []
    cases = spawned = 0
    for _ in range(300):
        cases += 1
        elapsed_ms = rng.choice((rng.randrange(0, 5000), rng.randrange(0, 3_000_000)))
        # Cooldown below dt so every case spawns; long frames spawn several pairs.
        dt_ms = rng.choice((rng.randrange(1, 40), rng.randrange(100, 800)))
        cooldown_ms = rng.randrange(0, dt_ms)
        seed = rng.getrandbits(32)
        world, alloc_states = _python_step(seed, elapsed_ms=elapsed_ms, dt_ms=dt_ms, cooldown_ms=cooldown_ms)
        # After each native spawn's name assignment, continue from the port's
        # state before its next allocation (or its final state).
        resync = [*alloc_states[1:], world.state.rng.state]

        def assign_name(_call, resync=resync) -> None:
            oracle.rand_state = resync.pop(0)

        oracle.restore(pristine)
        oracle.stub("typo_target_name_assign_random", assign_name)
        oracle.write_u32("survival_elapsed_ms", elapsed_ms)
        oracle.write_u32("frame_dt_ms", dt_ms)
        oracle.write_u32("survival_spawn_cooldown", cooldown_ms)
        oracle.rand_state = seed
        oracle.run(_SPAWN_BLOCK_START, _SPAWN_BLOCK_END, regs={"ebx": 0})

        case = f"typo elapsed_ms={elapsed_ms} dt_ms={dt_ms} cooldown_ms={cooldown_ms} seed=0x{seed:08x}"
        native_cooldown = oracle.read_i32("survival_spawn_cooldown")
        if native_cooldown != world.state.typo.spawn_cooldown_ms:
            mismatches.append(Mismatch(case, "spawn_cooldown_ms", native_cooldown, world.state.typo.spawn_cooldown_ms, 0))
        for index in range(CREATURE_POOL_SLOTS):
            address = pool_base + index * CREATURE_STRIDE
            native = oracle.read_fields(address, CREATURE_LAYOUT)
            python = world.creatures.entries[index]
            if not native["active"] and not python.active:
                continue
            spawned += 1
            mismatches += compare_fields(f"{case} creature[{index}]", native, _python_creature(python), address=address)
        if oracle.rand_state != world.state.rng.state:
            mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, world.state.rng.state, 0))
    assert spawned >= 2 * cases, f"only {spawned} creatures spawned over {cases} cases"
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
