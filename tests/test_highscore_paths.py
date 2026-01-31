from __future__ import annotations

from pathlib import Path

from crimson.persistence.highscores import scores_path_for_mode


def test_scores_path_for_mode(tmp_path: Path) -> None:
    root = tmp_path / "scores5"
    assert scores_path_for_mode(tmp_path, 1) == root / "survival.hi"
    assert scores_path_for_mode(tmp_path, 2) == root / "rush.hi"
    assert scores_path_for_mode(tmp_path, 4) == root / "typo.hi"
    assert scores_path_for_mode(tmp_path, 3, quest_stage_major=2, quest_stage_minor=7) == root / "questhc2_7.hi"
    assert (
        scores_path_for_mode(tmp_path, 3, hardcore=True, quest_stage_major=2, quest_stage_minor=7) == root / "quest2_7.hi"
    )
    assert scores_path_for_mode(tmp_path, 99) == root / "unknown.hi"
