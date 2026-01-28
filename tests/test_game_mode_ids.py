from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import PlayerState, perk_can_offer
from crimson.persistence.highscores import HighScoreRecord, rank_index, scores_path_for_config, sort_highscores
from crimson.perks import PERK_BY_ID, PerkId
from grim.config import CrimsonConfig


def _record(*, mode: int, time_ms: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = int(mode)
    record.survival_elapsed_ms = int(time_ms)
    return record


def test_scores_path_for_config_quest_mode_uses_quest_filename(tmp_path: Path) -> None:
    config = CrimsonConfig(path=tmp_path / "crimson.cfg", data={"game_mode": int(GameMode.QUESTS)})
    path = scores_path_for_config(tmp_path, config, quest_stage_major=1, quest_stage_minor=2)
    assert path == tmp_path / "scores5" / "quest1_2.hi"


def test_quest_highscores_sort_by_time_ascending_with_zero_last() -> None:
    records = [
        _record(mode=GameMode.QUESTS, time_ms=5000),
        _record(mode=GameMode.QUESTS, time_ms=2000),
        _record(mode=GameMode.QUESTS, time_ms=0),
        _record(mode=GameMode.QUESTS, time_ms=1000),
    ]
    sorted_records = sort_highscores(records, game_mode_id=int(GameMode.QUESTS))
    assert [int(r.survival_elapsed_ms) for r in sorted_records] == [1000, 2000, 5000, 0]


def test_quest_rank_index_inserts_smaller_time_higher() -> None:
    records_sorted = sort_highscores(
        [
            _record(mode=GameMode.QUESTS, time_ms=1000),
            _record(mode=GameMode.QUESTS, time_ms=2000),
            _record(mode=GameMode.QUESTS, time_ms=5000),
        ],
        game_mode_id=int(GameMode.QUESTS),
    )
    record = _record(mode=GameMode.QUESTS, time_ms=1500)
    assert rank_index(records_sorted, record) == 1


def test_perk_mode_3_only_is_offered_only_in_mode_3() -> None:
    meta = PERK_BY_ID.get(int(PerkId.ALTERNATE_WEAPON))
    assert meta is not None

    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    assert perk_can_offer(player, meta, game_mode=int(GameMode.SURVIVAL), player_count=1) is False
    assert perk_can_offer(player, meta, game_mode=int(GameMode.QUESTS), player_count=1) is True
