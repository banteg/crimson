from __future__ import annotations

import pytest

from crimson.quests.level import QuestLevel


def test_quest_level_rejects_non_int_parts() -> None:
    with pytest.raises(TypeError, match="quest stage must be int"):
        QuestLevel.from_parts("1", 1)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="quest row must be int"):
        QuestLevel.from_parts(1, True)


def test_quest_level_from_parts_or_none_returns_none_for_zero_zero_and_invalid_types() -> None:
    assert QuestLevel.from_parts_or_none(0, 0) is None
    assert QuestLevel.from_parts_or_none("1", 1) is None  # type: ignore[arg-type]
