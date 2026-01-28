from __future__ import annotations

from dataclasses import replace
import inspect
import random

from .types import QuestContext, QuestDefinition, SpawnEntry

QUEST_COMPLETION_TRANSITION_MS = 1000.0


def _call_builder(
    builder,
    ctx: QuestContext,
    *,
    rng: random.Random | None,
    full_version: bool,
) -> list[SpawnEntry]:
    params = inspect.signature(builder).parameters
    kwargs: dict[str, object] = {}
    if "rng" in params:
        kwargs["rng"] = rng
    if "full_version" in params:
        kwargs["full_version"] = bool(full_version)
    return builder(ctx, **kwargs)


def apply_hardcore_spawn_table_adjustment(entries: list[SpawnEntry]) -> list[SpawnEntry]:
    """Apply quest hardcore spawn-table count adjustment.

    Modeled after the quest start logic in the classic game, which bumps `SpawnEntry.count`
    for most multi-spawn entries in hardcore mode.
    """

    adjusted: list[SpawnEntry] = []
    for entry in entries:
        spawn_id = int(entry.spawn_id)
        count = int(entry.count)
        if count > 1 and spawn_id != 0x3C:
            if spawn_id == 0x2B:
                count += 2
            else:
                count += 8
        adjusted.append(entry if count == entry.count else replace(entry, count=count))
    return adjusted


def build_quest_spawn_table(
    quest: QuestDefinition,
    ctx: QuestContext,
    *,
    seed: int | None = None,
    hardcore: bool = False,
    full_version: bool = True,
) -> tuple[SpawnEntry, ...]:
    """Build the quest spawn script (with optional hardcore modifications)."""

    rng = random.Random(seed) if seed is not None else random.Random()
    entries = _call_builder(quest.builder, ctx, rng=rng, full_version=full_version)
    if hardcore:
        entries = apply_hardcore_spawn_table_adjustment(list(entries))
    return tuple(entries)


def tick_quest_completion_transition(
    completion_transition_ms: float,
    frame_dt_ms: float,
    *,
    creatures_none_active: bool,
    spawn_table_empty: bool,
) -> tuple[float, bool]:
    """Advance quest completion transition timer.

    The quest-mode update loop waits for a short delay after the quest is "idle complete"
    (no active creatures + no remaining spawn table entries) before transitioning to the
    results screen.

    Returns:
      (completion_transition_ms, completed)
    """

    dt_ms = float(frame_dt_ms)
    timer_ms = float(completion_transition_ms)

    if creatures_none_active and spawn_table_empty:
        if timer_ms < 0.0:
            timer_ms = 0.0
        timer_ms += dt_ms
        return timer_ms, bool(timer_ms >= QUEST_COMPLETION_TRANSITION_MS)

    return -1.0, False
