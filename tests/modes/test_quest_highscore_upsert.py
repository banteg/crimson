from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.persistence.highscores import (
    HighScoreRecord,
    read_highscore_table,
    scores_path_for_config,
    upsert_highscore_record,
)
from crimson.quests.level import QuestLevel
from grim.config import default_crimson_cfg


def _record(*, time_ms: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.QUESTS
    record.survival_elapsed_ms = int(time_ms)
    return record


def test_upsert_highscore_record_quest_sorts_ascending_with_zero_last(tmp_path: Path) -> None:
    config = default_crimson_cfg(tmp_path / "crimson.cfg")
    config.gameplay.mode = GameMode.QUESTS
    config.gameplay.quest_level = QuestLevel(1, 1)
    path = scores_path_for_config(tmp_path, config)

    upsert_highscore_record(path, _record(time_ms=5000))
    upsert_highscore_record(path, _record(time_ms=2000))
    upsert_highscore_record(path, _record(time_ms=0))

    records = read_highscore_table(path, game_mode_id=GameMode.QUESTS)
    assert [int(r.survival_elapsed_ms) for r in records] == [2000, 5000, 0]
