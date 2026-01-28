from __future__ import annotations

from pathlib import Path

from crimson.persistence.highscores import HighScoreRecord, read_highscore_table, scores_path_for_config, upsert_highscore_record
from grim.config import CrimsonConfig


def _record(*, time_ms: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = 3
    record.survival_elapsed_ms = int(time_ms)
    return record


def test_upsert_highscore_record_quest_sorts_ascending_with_zero_last(tmp_path: Path) -> None:
    config = CrimsonConfig(
        path=tmp_path / "crimson.cfg",
        data={
            "game_mode": 3,
            "quest_stage_major": 1,
            "quest_stage_minor": 1,
        },
    )
    path = scores_path_for_config(tmp_path, config)

    upsert_highscore_record(path, _record(time_ms=5000))
    upsert_highscore_record(path, _record(time_ms=2000))
    upsert_highscore_record(path, _record(time_ms=0))

    records = read_highscore_table(path, game_mode_id=3)
    assert [int(r.survival_elapsed_ms) for r in records] == [2000, 5000, 0]

