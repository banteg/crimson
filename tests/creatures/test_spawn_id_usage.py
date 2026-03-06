from __future__ import annotations

import inspect
import random

from crimson.creatures.spawn import SPAWN_ID_TO_TEMPLATE
from crimson.quests import QuestContext, all_quests


def test_all_quest_spawn_ids_are_known() -> None:
    ctx = QuestContext(width=1024, height=1024, player_count=1)
    for quest in all_quests():
        params = inspect.signature(quest.builder).parameters
        kwargs: dict[str, object] = {}
        if "rng" in params:
            kwargs["rng"] = random.Random(1337)
        if "full_version" in params:
            kwargs["full_version"] = True
        entries = quest.builder(ctx, **kwargs)
        for entry in entries:
            assert entry.spawn_id in SPAWN_ID_TO_TEMPLATE, (quest.level, entry.spawn_id)

