from __future__ import annotations

import msgspec

from ..creatures.spawn import SpawnId
from .types import QuestContext, QuestDefinition, SpawnEntry


def apply_hardcore_spawn_table_adjustment(entries: list[SpawnEntry]) -> list[SpawnEntry]:
    """Apply quest hardcore spawn-table count adjustment.

    Modeled after the quest start logic in the classic game, which bumps `SpawnEntry.count`
    for most multi-spawn entries in hardcore mode.
    """

    adjusted: list[SpawnEntry] = []
    for entry in entries:
        spawn_id = entry.spawn_id
        count = int(entry.count)
        if count > 1 and spawn_id != SpawnId.SPIDER_PLASMA_SHOOTER_3C:
            if spawn_id == SpawnId.ALIEN_DEADLY_FAST_2B:
                count += 2
            else:
                count += 8
        adjusted.append(entry if count == entry.count else msgspec.structs.replace(entry, count=count))
    return adjusted


def build_quest_spawn_table(quest: QuestDefinition, ctx: QuestContext) -> tuple[SpawnEntry, ...]:
    """Build the quest spawn script from the active startup RNG state."""

    entries = quest.builder(ctx)
    if ctx.hardcore:
        entries = apply_hardcore_spawn_table_adjustment(list(entries))
    return tuple(entries)
