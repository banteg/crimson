from __future__ import annotations

import inspect
from typing import cast

from syrupy import SnapshotAssertion
from syrupy.types import PropertyMatcher

from crimson.quests import QuestContext, all_quests
from grim.rand import Crand


def _round_matcher(data: object, **_: object) -> object:
    if isinstance(data, float):
        return round(data, 9)
    return data


def _build_entries(builder, ctx: QuestContext, seed: int) -> list[dict[str, object]]:
    params = inspect.signature(builder).parameters
    kwargs: dict[str, object] = {}
    if "rng" in params:
        kwargs["rng"] = Crand(seed)
    if "full_version" in params:
        kwargs["full_version"] = True
    entries = builder(ctx, **kwargs)
    return [
        {
            "x": entry.pos.x,
            "y": entry.pos.y,
            "heading": entry.heading,
            "spawn_id": entry.spawn_id,
            "trigger_ms": entry.trigger_ms,
            "count": entry.count,
        }
        for entry in entries
    ]


def test_quest_builders_snapshot(snapshot: SnapshotAssertion) -> None:
    ctx = QuestContext(width=1024, height=1024, player_count=1)
    matcher = cast(PropertyMatcher, _round_matcher)
    for quest in all_quests():
        payload = {
            "level": quest.level,
            "title": quest.title,
            "time_limit_ms": quest.time_limit_ms,
            "start_weapon_id": quest.start_weapon_id,
            "unlock_perk_id": quest.unlock_perk_id,
            "unlock_weapon_id": quest.unlock_weapon_id,
            "terrain_ids": quest.terrain_ids,
            "builder_address": quest.builder_address,
            "entries": _build_entries(quest.builder, ctx, seed=1337),
        }
        snapshot(name=f"quest_{quest.level}", matcher=matcher).assert_match(
            payload,
        )
