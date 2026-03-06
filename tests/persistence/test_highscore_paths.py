from __future__ import annotations

from pathlib import Path
from typing import cast

from crimson.game_modes import GameMode
from crimson.persistence.highscores import scores_path_for_mode


def test_scores_path_for_mode(tmp_path: Path) -> None:
    root = tmp_path / "scores5"
    assert scores_path_for_mode(tmp_path, GameMode.SURVIVAL) == root / "survival.hi"
    assert scores_path_for_mode(tmp_path, GameMode.SURVIVAL, player_count=2) == root / "survival_2.hi"
    assert scores_path_for_mode(tmp_path, GameMode.SURVIVAL, player_count=3) == root / "survival_3.hi"
    assert scores_path_for_mode(tmp_path, GameMode.SURVIVAL, player_count=4) == root / "survival_4.hi"
    assert scores_path_for_mode(tmp_path, GameMode.RUSH) == root / "rush.hi"
    assert scores_path_for_mode(tmp_path, GameMode.RUSH, player_count=2) == root / "rush_2.hi"
    assert scores_path_for_mode(tmp_path, GameMode.RUSH, player_count=3) == root / "rush_3.hi"
    assert scores_path_for_mode(tmp_path, GameMode.RUSH, player_count=4) == root / "rush_4.hi"
    assert scores_path_for_mode(tmp_path, GameMode.TYPO) == root / "typo.hi"
    assert (
        scores_path_for_mode(tmp_path, GameMode.QUESTS, quest_stage_major=2, quest_stage_minor=7)
        == root / "questhc2_7.hi"
    )
    assert (
        scores_path_for_mode(tmp_path, GameMode.QUESTS, quest_stage_major=2, quest_stage_minor=7, player_count=2)
        == root / "questhc2_7_2.hi"
    )
    assert (
        scores_path_for_mode(tmp_path, GameMode.QUESTS, quest_stage_major=2, quest_stage_minor=7, player_count=3)
        == root / "questhc2_7_3.hi"
    )
    assert (
        scores_path_for_mode(tmp_path, GameMode.QUESTS, quest_stage_major=2, quest_stage_minor=7, player_count=4)
        == root / "questhc2_7_4.hi"
    )
    assert (
        scores_path_for_mode(tmp_path, GameMode.QUESTS, hardcore=True, quest_stage_major=2, quest_stage_minor=7)
        == root / "quest2_7.hi"
    )
    assert (
        scores_path_for_mode(
            tmp_path,
            GameMode.QUESTS,
            hardcore=True,
            quest_stage_major=2,
            quest_stage_minor=7,
            player_count=2,
        )
        == root / "quest2_7_2.hi"
    )
    assert (
        scores_path_for_mode(
            tmp_path,
            GameMode.QUESTS,
            hardcore=True,
            quest_stage_major=2,
            quest_stage_minor=7,
            player_count=3,
        )
        == root / "quest2_7_3.hi"
    )
    assert (
        scores_path_for_mode(
            tmp_path,
            GameMode.QUESTS,
            hardcore=True,
            quest_stage_major=2,
            quest_stage_minor=7,
            player_count=4,
        )
        == root / "quest2_7_4.hi"
    )
    assert scores_path_for_mode(tmp_path, cast(GameMode, 99)) == root / "unknown.hi"
