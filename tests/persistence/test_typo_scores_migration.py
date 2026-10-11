from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.persistence.highscores import (
    HighScoreRecord,
    migrate_typo_scores,
    read_highscore_table,
    scores_path_for_mode,
    write_highscore_records,
)


def _typo_record(name: str, score: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.set_name(name)
    record.game_mode_id = GameMode.TYPO
    record.score_xp = score
    return record


def test_migrate_typo_scores_folds_port_tables_into_the_originals(tmp_path: Path) -> None:
    root = tmp_path / "scores5"
    write_highscore_records(root / "unknown.hi", [_typo_record("Original", 300)])
    write_highscore_records(root / "typo.hi", [_typo_record("Port", 500)])
    write_highscore_records(root / "typo.hiBob", [_typo_record("Bob", 100)])

    assert migrate_typo_scores(tmp_path) == [root / "unknown.hi", root / "unknown.hiBob"]

    assert sorted(path.name for path in root.iterdir()) == ["unknown.hi", "unknown.hiBob"]
    table = read_highscore_table(scores_path_for_mode(tmp_path, GameMode.TYPO), game_mode_id=GameMode.TYPO)
    assert [record.name() for record in table] == ["Port", "Original"]
    named = read_highscore_table(
        scores_path_for_mode(tmp_path, GameMode.TYPO, named_list="Bob"), game_mode_id=GameMode.TYPO,
    )
    assert [record.name() for record in named] == ["Bob"]
    assert migrate_typo_scores(tmp_path) == []
