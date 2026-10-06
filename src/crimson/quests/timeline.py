from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from ..math_parity import f32
from ..sim.state_types import TERRAIN_SIZE
from .types import SpawnEntry

if TYPE_CHECKING:
    from ..sim.mode_updates import QuestSpawnState
    from ..sim.world_state import WorldState


def quest_spawn_table_empty(entries: tuple[SpawnEntry, ...]) -> bool:
    """Return True when all quest spawn entries are exhausted (count <= 0)."""
    return all(entry.count <= 0 for entry in entries)


def quest_spawn_timeline_update(world: WorldState, spawn: QuestSpawnState, *, dt_ms: float) -> None:
    """Port of `quest_spawn_timeline_update` (0x00434250): spawn the first due trigger group.

    Entries sharing the group's trigger time spawn together, `count` creatures each, spread
    40 apart along x (or y for entries off the sides of the arena); the table then zeroes them.
    After 3 s with no creatures active and 0x6A4 ms of timeline, the next group spawns early. Native
    reads the cached `creatures_none_active_flag`, not the pool; spawning a group clears it.
    """

    creatures_none_active = spawn.creatures_none_active
    if creatures_none_active:
        spawn.no_creatures_timer_ms = f32(spawn.no_creatures_timer_ms + f32(dt_ms))
    else:
        spawn.no_creatures_timer_ms = 0.0
    timeline_ms = f32(spawn.spawn_timeline_ms)
    force_spawn = creatures_none_active and spawn.no_creatures_timer_ms > 3000.0 and timeline_ms > 0x6A4

    entries = list(spawn.spawn_entries)
    start_idx = None
    for idx, entry in enumerate(entries):
        if entry.count > 0 and (f32(entry.trigger_ms) < timeline_ms or force_spawn):
            start_idx = idx
            break
    if start_idx is None:
        return

    trigger_ms = entries[start_idx].trigger_ms
    for idx in range(start_idx, len(entries)):
        entry = entries[idx]
        if entry.trigger_ms != trigger_ms:
            break
        offscreen_x = entry.pos.x < 0.0 or entry.pos.x > TERRAIN_SIZE
        for spawn_idx in range(entry.count):
            offset = f32(spawn_idx * 0x28)
            if spawn_idx & 1:
                offset = -offset
            pos = entry.pos.offset(dy=offset) if offscreen_x else entry.pos.offset(dx=offset)
            world.creatures.spawn_template(
                entry.spawn_id, pos, f32(entry.heading), state=world.state, detail_preset=world.state.detail_preset,
            )
        if entry.count != 0:
            entries[idx] = msgspec.structs.replace(entry, count=0)
        spawn.creatures_none_active = False
    spawn.spawn_entries = tuple(entries)
