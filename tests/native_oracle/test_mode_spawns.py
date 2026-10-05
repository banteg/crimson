"""Rush and Survival wave spawns vs `rush_mode_update` / `survival_spawn_creature`.

- `rush_mode_update` (0x004072b0) with the native `creature_spawn`: the cooldown
  loop, tint, edge positions and elapsed-scaled stats.
- `survival_spawn_creature` (0x00407510): type, speed, health, tint and reward
  from the player's experience.

`run_elapsed_ms` and the experience are ints that `fild` loads exactly, so
the cases include values past 2^24 where rounding them to f32 first would drift.
"""

from __future__ import annotations

import random

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import survival_spawn_creature
from crimson.math_parity import f32
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.mode_updates import RushSpawnState, rush_mode_update
from crimson.sim.state_types import TERRAIN_SIZE, PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import CREATURE_LAYOUT, CREATURE_POOL_SLOTS, CREATURE_STRIDE, Mismatch, compare_fields, mismatch_report

_LARGE_TIMES = ((1 << 24) - 1, 1 << 24, (1 << 24) + 1, 16_777_219, 20_000_001, 33_554_435)


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




def _compare_pool(oracle, case: str, pool: CreaturePool) -> tuple[list[Mismatch], int]:
    pool_base = oracle.resolve("creature_pool")
    mismatches: list[Mismatch] = []
    spawned = 0
    for index in range(CREATURE_POOL_SLOTS):
        address = pool_base + index * CREATURE_STRIDE
        native = oracle.read_fields(address, CREATURE_LAYOUT)
        python = pool.entries[index]
        if not native["active"] and not python.active:
            continue
        spawned += 1
        mismatches += compare_fields(f"{case} creature[{index}]", native, _python_creature(python), address=address)
    return mismatches, spawned


def test_rush_mode_spawns_match_native(oracle) -> None:
    oracle.write_u32("terrain_texture_width", TERRAIN_SIZE)
    oracle.write_u32("terrain_texture_height", TERRAIN_SIZE)
    pristine = oracle.snapshot()

    rng = random.Random(0x4072B0)
    mismatches: list[Mismatch] = []
    cases = spawned = 0
    for elapsed_ms in (*_LARGE_TIMES, *(rng.randrange(0, 3_000_000) for _ in range(120))):
        cases += 1
        player_count = rng.choice((1, 2))
        dt_ms = rng.choice((rng.randrange(1, 40), rng.randrange(100, 700)))
        cooldown_ms = rng.randrange(0, dt_ms)
        seed = rng.getrandbits(32)

        oracle.restore(pristine)
        oracle.write_u32("config_player_count", player_count)
        oracle.write_u32("frame_dt_ms", dt_ms)
        oracle.write_u32("survival_spawn_cooldown", cooldown_ms)
        oracle.write_u32("run_elapsed_ms", elapsed_ms)
        oracle.rand_state = seed
        oracle.call("rush_mode_update")

        crt = CrtRand(seed)
        pool = CreaturePool()
        players = [PlayerState(index=index, pos=Vec2()) for index in range(player_count)]
        spawn = RushSpawnState(spawn_cooldown_ms=float(cooldown_ms))
        world = WorldState(state=GameplayState(rng=crt), players=players, creatures=pool)
        rush_mode_update(world, spawn, elapsed_ms=float(elapsed_ms), dt_ms=float(dt_ms))
        cooldown = spawn.spawn_cooldown_ms

        case = f"rush elapsed_ms={elapsed_ms} dt_ms={dt_ms} players={player_count} seed=0x{seed:08x}"
        if oracle.read_i32("survival_spawn_cooldown") != cooldown:
            mismatches.append(Mismatch(case, "cooldown", oracle.read_i32("survival_spawn_cooldown"), cooldown, 0))
        case_mismatches, case_spawned = _compare_pool(oracle, case, pool)
        mismatches += case_mismatches
        spawned += case_spawned
        if oracle.rand_state != crt.state:
            mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, crt.state, 0))
    assert spawned >= 2 * cases, f"only {spawned} creatures spawned over {cases} cases"
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


def test_survival_spawn_creature_matches_native(oracle) -> None:
    pristine = oracle.snapshot()
    pos_arg = oracle.alloc(8)

    rng = random.Random(0x407510)
    experiences = [0, 11_999, 12_000, 24_999, 41_999, 49_999, 89_999, 109_999, 110_000, 250_000, *_LARGE_TIMES]
    experiences += [rng.randrange(0, 400_000) for _ in range(150)]
    mismatches: list[Mismatch] = []
    cases = 0
    for experience in experiences:
        for _ in range(3):
            cases += 1
            seed = rng.getrandbits(32)
            pos = Vec2(f32(rng.uniform(-40.0, 1064.0)), f32(rng.uniform(-40.0, 1064.0)))

            oracle.restore(pristine)
            oracle.write_u32("player_experience", experience)
            oracle.write_f32(pos_arg, pos.x)
            oracle.write_f32(pos_arg + 4, pos.y)
            oracle.rand_state = seed
            oracle.call("survival_spawn_creature", pos_arg)

            crt = CrtRand(seed)
            pool = CreaturePool()
            survival_spawn_creature(pool, pos, crt, player_experience=experience)

            case = f"survival experience={experience} seed=0x{seed:08x}"
            case_mismatches, _ = _compare_pool(oracle, case, pool)
            mismatches += case_mismatches
            if oracle.rand_state != crt.state:
                mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, crt.state, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
