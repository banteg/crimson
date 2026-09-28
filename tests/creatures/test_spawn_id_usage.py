from __future__ import annotations

from crimson.creatures.spawn import SPAWN_ID_TO_TEMPLATE
from crimson.quests import QUESTS, QuestContext
from grim.rand import Crand


def test_all_quest_spawn_ids_are_known() -> None:
    for quest in QUESTS:
        entries = quest.builder(QuestContext(player_count=1, rng=Crand(1337)))
        for entry in entries:
            assert entry.spawn_id in SPAWN_ID_TO_TEMPLATE, (quest.level, entry.spawn_id)
