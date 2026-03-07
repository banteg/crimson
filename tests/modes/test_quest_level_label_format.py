from __future__ import annotations

from crimson.quests.level import QuestLevel


def test_quest_level_text_matches_exe_format() -> None:
    assert QuestLevel(1, 1).text == "1.1"
    assert QuestLevel(1, 10).text == "1.10"
