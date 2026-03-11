from __future__ import annotations

from crimson.creatures.spawn import SPAWN_ID_TO_TEMPLATE
from crimson.quests import QuestContext, all_quests
from grim.rand import Crand


def test_all_quest_spawn_ids_are_known() -> None:
    ctx = QuestContext(width=1024, height=1024, player_count=1)
    for quest in all_quests():
        entries = quest.builder(ctx, rng=Crand(1337), full_version=True)
        for entry in entries:
            assert entry.spawn_id in SPAWN_ID_TO_TEMPLATE, (quest.level, entry.spawn_id)
