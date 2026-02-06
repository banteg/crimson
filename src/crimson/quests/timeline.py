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

        base_pos = entry.pos
        offscreen_x = base_pos.x < 0.0 or float(terrain_width) < base_pos.x

        for spawn_idx in range(int(entry.count)):
            magnitude = float(spawn_idx * 0x28)
            offset = magnitude if (spawn_idx & 1) == 0 else -magnitude
            if offscreen_x:
                pos = base_pos.offset(dy=offset)
            else:
                pos = base_pos.offset(dx=offset)
            spawns.append(SpawnTemplateCall(template_id=entry.spawn_id, pos=pos, heading=float(entry.heading)))

        if entry.count != 0:
            updated_entries[idx] = replace(entry, count=0)

    # After spawning, the original forces the "none active" flag off.
    creatures_none_active = False

    return tuple(updated_entries), creatures_none_active, no_creatures_timer_ms, tuple(spawns)


def quest_spawn_table_empty(entries: tuple[SpawnEntry, ...]) -> bool:
    """Return True when all quest spawn entries are exhausted (count <= 0)."""
    return all(entry.count <= 0 for entry in entries)


def tick_quest_mode_spawns(
    entries: tuple[SpawnEntry, ...],
    quest_spawn_timeline_ms: float,
    frame_dt_ms: float,
    *,
    terrain_width: float,
    creatures_none_active: bool,
    no_creatures_timer_ms: float,
) -> tuple[tuple[SpawnEntry, ...], float, bool, float, tuple[SpawnTemplateCall, ...]]:
    """Advance quest-mode spawning (spawn timeline + table firing).

    Modeled after the spawning portion of `quest_mode_update` (0x004070e0), which:
      - Advances `quest_spawn_timeline` unless the quest is idle-complete (no creatures active and
        the spawn table is empty).
      - Calls `quest_spawn_timeline_update` to fire spawn entries.

    Returns:
      (updated_entries, quest_spawn_timeline_ms, creatures_none_active, no_creatures_timer_ms, spawn_calls)
    """
    timeline_ms = float(quest_spawn_timeline_ms)
    dt_ms = float(frame_dt_ms)

    if (not creatures_none_active) or (not quest_spawn_table_empty(entries)):
        timeline_ms += dt_ms

    entries, creatures_none_active, no_creatures_timer_ms, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=timeline_ms,
        frame_dt_ms=dt_ms,
        terrain_width=terrain_width,
        creatures_none_active=creatures_none_active,
        no_creatures_timer_ms=no_creatures_timer_ms,
    )

    return entries, timeline_ms, creatures_none_active, no_creatures_timer_ms, spawns
