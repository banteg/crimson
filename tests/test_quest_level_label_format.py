from __future__ import annotations

from crimson.modes.quest_mode import _quest_level_label


def test_quest_level_label_matches_exe_format() -> None:
    assert _quest_level_label("1.1") == "1.1"
    assert _quest_level_label("1.10") == "1.10"


def test_quest_level_label_carries_minor_overflow() -> None:
    assert _quest_level_label("1.11") == "2.1"

