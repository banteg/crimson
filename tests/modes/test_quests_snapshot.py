from __future__ import annotations

from typing import cast

from syrupy import SnapshotAssertion
from syrupy.types import PropertyMatcher

from crimson.quests import QUESTS, QuestContext
from grim.rand import Crand


def _round_matcher(data: object, **_: object) -> object:
    if isinstance(data, float):
        return round(data, 9)
    return data


def _build_entries(builder, seed: int) -> list[dict[str, object]]:
    entries = builder(QuestContext(player_count=1, rng=Crand(seed)))
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
    matcher = cast(PropertyMatcher, _round_matcher)
    for quest in QUESTS:
        payload = {
            "level": quest.level.text,
            "title": quest.title,
            "time_limit_ms": quest.time_limit_ms,
            "start_weapon_id": quest.start_weapon_id,
            "unlock_perk_id": quest.unlock_perk_id,
            "unlock_weapon_id": quest.unlock_weapon_id,
            "terrain_slots": quest.terrain_slots,
            "entries": _build_entries(quest.builder, seed=1337),
        }
        snapshot(name=f"quest_{quest.level.text}", matcher=matcher).assert_match(
            payload,
        )
