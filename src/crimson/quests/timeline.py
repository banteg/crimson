from __future__ import annotations

from dataclasses import replace

from ..creatures.spawn import SpawnTemplateCall

from .types import SpawnEntry


def tick_quest_spawn_timeline(
    entries: tuple[SpawnEntry, ...],
    quest_spawn_timeline_ms: float,
    frame_dt_ms: float,
    *,
    terrain_width: float,
    creatures_none_active: bool,
    no_creatures_timer_ms: float,
) -> tuple[tuple[SpawnEntry, ...], bool, float, tuple[SpawnTemplateCall, ...]]:
    """Advance quest spawn-table firing (pure model of `quest_spawn_timeline_update` / 0x00434250).

    Returns:
      (updated_entries, creatures_none_active, no_creatures_timer_ms, spawn_calls)
    """
    timeline_ms = float(quest_spawn_timeline_ms)
    dt_ms = float(frame_dt_ms)

    if not creatures_none_active:
        no_creatures_timer_ms = 0.0
    else:
        no_creatures_timer_ms += dt_ms

    force_spawn = creatures_none_active and 3000.0 < no_creatures_timer_ms and 0x6A4 < timeline_ms

    start_idx: int | None = None
    for idx, entry in enumerate(entries):
        if entry.count <= 0:
            continue
        if float(entry.trigger_ms) < timeline_ms or force_spawn:
            start_idx = idx
            break

    if start_idx is None:
        return entries, creatures_none_active, no_creatures_timer_ms, ()

    spawns: list[SpawnTemplateCall] = []
    updated_entries = list(entries)

    trigger_ms = entries[start_idx].trigger_ms
    for idx in range(start_idx, len(entries)):
        entry = entries[idx]
        if entry.trigger_ms != trigger_ms:
            break

        base_x = float(entry.x)
        base_y = float(entry.y)
        offscreen_x = base_x < 0.0 or float(terrain_width) < base_x

        for spawn_idx in range(int(entry.count)):
            magnitude = float(spawn_idx * 0x28)
            offset = magnitude if (spawn_idx & 1) == 0 else -magnitude
            if offscreen_x:
                pos = (base_x, base_y + offset)
            else:
                pos = (base_x + offset, base_y)
            spawns.append(SpawnTemplateCall(template_id=entry.spawn_id, pos=pos, heading=float(entry.heading)))

        if entry.count != 0:
            updated_entries[idx] = replace(entry, count=0)

    # After spawning, the original forces the "none active" flag off.
    creatures_none_active = False

    return tuple(updated_entries), creatures_none_active, no_creatures_timer_ms, tuple(spawns)
