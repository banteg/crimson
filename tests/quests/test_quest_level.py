from __future__ import annotations

import msgspec
import pytest

from crimson.quests.level import QuestLevel


def test_quest_level_parse_rejects_invalid_parts() -> None:
    with pytest.raises(ValueError, match="invalid quest level"):
        QuestLevel.parse("q.1")

    with pytest.raises(ValueError, match="invalid quest level"):
        QuestLevel.parse("1.true")

    with pytest.raises(ValueError, match="invalid quest level"):
        QuestLevel.parse("")


def test_quest_level_msgspec_constraints_reject_out_of_range_parts() -> None:
    with pytest.raises(msgspec.ValidationError, match="Expected `int` >= 1"):
        msgspec.convert({"major": 0, "minor": 1}, type=QuestLevel)

    with pytest.raises(msgspec.ValidationError, match="Expected `int` <= 10"):
        msgspec.convert({"major": 1, "minor": 11}, type=QuestLevel)
