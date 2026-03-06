from __future__ import annotations

from crimson.ui.overlays.quest_run import quest_level_label


def test_quest_level_label_matches_exe_format() -> None:
    assert quest_level_label(1, 1) == "1.1"
    assert quest_level_label(1, 10) == "1.10"


def test_quest_level_label_carries_minor_overflow() -> None:
    assert quest_level_label(1, 11) == "2.1"
