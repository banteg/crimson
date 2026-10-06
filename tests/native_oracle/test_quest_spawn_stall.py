"""`quest_mode_update` (0x004070e0) vs the port: the stall timer reads a cached "no creatures" flag.

`quest_spawn_timeline_update` does not scan the pool; it reads `creatures_none_active_flag`, which
`creatures_none_active()` refreshes at the top of `quest_mode_update` only while a run is active,
and again in the completion check. With no run active (the run-down after a death) the flag keeps
the previous frame's value, so a corpse culled by render in between leaves it stale. Each case
seeds the flag, the pool, the stall timer and the run state, runs one frame on both sides and
compares the stall timer, the timeline, the flag, the spawn table and the pool.
"""

from __future__ import annotations

import itertools

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn_ids import SpawnId
from crimson.math_parity import f32
from crimson.quests.types import SpawnEntry
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.mode_updates import QuestSpawnState, quest_mode_update
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import CREATURE_POOL_SLOTS, CREATURE_STRIDE, Mismatch, mismatch_report, prepare_gameplay

_TIMELINE_MS = 2000  # past the 0x6a4 force-spawn floor
_DT_MS = 16
# Off the left edge: the template spawns without an in-arena burst.
_ENTRY = SpawnEntry(pos=Vec2(-50.0, 512.0), heading=0.0, spawn_id=SpawnId.ALIEN_RANDOM_06, trigger_ms=900_000, count=2)


def _write_entry(oracle, entry: SpawnEntry) -> None:
    base = oracle.resolve("quest_spawn_table")
    oracle.write_f32(base + 0x00, entry.pos.x)
    oracle.write_f32(base + 0x04, entry.pos.y)
    oracle.write_f32(base + 0x08, entry.heading)
    oracle.write_u32(base + 0x0C, int(entry.spawn_id))
    oracle.write_u32(base + 0x10, entry.trigger_ms)
    oracle.write_u32(base + 0x14, entry.count)
    oracle.write_u32("quest_spawn_count", 1)


def test_quest_stall_timer_reads_the_cached_flag(oracle) -> None:
    prepare_gameplay(oracle)
    oracle.write_u8("console_open_flag", 0)
    oracle.write_u32("frame_dt_ms", _DT_MS)
    pristine = oracle.snapshot()

    mismatches: list[Mismatch] = []
    cases = 0
    for run_active, cached_none, live_creature, stall_ms in itertools.product((0, 1), (0, 1), (False, True), (0, 2990)):
        cases += 1
        seed = 0x4070E0 + cases
        oracle.restore(pristine)
        _write_entry(oracle, _ENTRY)
        oracle.write_u8("run_active", run_active)
        oracle.write_u8("creatures_none_active_flag", cached_none)
        oracle.write_u32("quest_spawn_timeline", _TIMELINE_MS)
        oracle.write_u32("quest_spawn_stall_timer_ms", stall_ms)
        pool_base = oracle.resolve("creature_pool")
        oracle.write_u8(pool_base, int(live_creature))
        oracle.rand_state = seed
        oracle.call("quest_mode_update")

        crt = CrtRand(seed)
        pool = CreaturePool()
        pool.entries[0] = CreatureState(active=live_creature)
        state = GameplayState(rng=crt, run_active=bool(run_active))
        world = WorldState(state=state, players=[PlayerState(index=0, pos=Vec2(512.0, 512.0))], creatures=pool)
        spawn = QuestSpawnState(
            spawn_entries=(_ENTRY,),
            spawn_timeline_ms=float(_TIMELINE_MS),
            no_creatures_timer_ms=float(stall_ms),
            creatures_none_active=bool(cached_none),
        )
        quest_mode_update(world, spawn, dt_ms=float(_DT_MS))

        case = f"run_active={run_active} cached_none={cached_none} live={live_creature} stall={stall_ms}"
        native_active = sum(oracle.read_u8(pool_base + i * CREATURE_STRIDE) != 0 for i in range(CREATURE_POOL_SLOTS))
        for field, native, port in (
            ("stall_ms", oracle.read_i32("quest_spawn_stall_timer_ms"), int(spawn.no_creatures_timer_ms)),
            ("timeline_ms", oracle.read_i32("quest_spawn_timeline"), int(f32(spawn.spawn_timeline_ms))),
            ("none_active_flag", oracle.read_u8("creatures_none_active_flag"), int(spawn.creatures_none_active)),
            ("entry_count", oracle.read_i32(oracle.resolve("quest_spawn_table") + 0x14), spawn.spawn_entries[0].count),
            ("active_creatures", native_active, sum(c.active for c in pool.entries)),
            ("rand_state", oracle.rand_state, crt.state),
        ):
            if native != port:
                mismatches.append(Mismatch(case, field, native, port, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
