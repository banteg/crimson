from __future__ import annotations

from grim.geom import Vec2

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PlayerState, perk_can_offer
from crimson.persistence.highscores import HighScoreRecord, rank_index, scores_path_for_config, sort_highscores
from crimson.perks import PERK_BY_ID, PerkId
from grim.config import CrimsonConfig


def _record(*, mode: int, time_ms: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = int(mode)
    record.survival_elapsed_ms = int(time_ms)
    return record


def _record_xp(*, mode: int, xp: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = int(mode)
    record.score_xp = int(xp)
    return record


def test_scores_path_for_config_quest_mode_uses_quest_filename(tmp_path: Path) -> None:
    config = CrimsonConfig(path=tmp_path / "crimson.cfg", data={"game_mode": int(GameMode.QUESTS)})
    path = scores_path_for_config(tmp_path, config, quest_stage_major=1, quest_stage_minor=2)
    assert path == tmp_path / "scores5" / "questhc1_2.hi"


def test_scores_path_for_config_quest_mode_uses_quest_filename_when_hardcore(tmp_path: Path) -> None:
    config = CrimsonConfig(path=tmp_path / "crimson.cfg", data={"game_mode": int(GameMode.QUESTS), "hardcore_flag": 1})
    path = scores_path_for_config(tmp_path, config, quest_stage_major=1, quest_stage_minor=2)
    assert path == tmp_path / "scores5" / "quest1_2.hi"


def test_scores_path_for_config_survival_mode_uses_survival_filename(tmp_path: Path) -> None:
    config = CrimsonConfig(path=tmp_path / "crimson.cfg", data={"game_mode": int(GameMode.SURVIVAL)})
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / "survival.hi"


def test_scores_path_for_config_rush_mode_uses_rush_filename(tmp_path: Path) -> None:
    config = CrimsonConfig(path=tmp_path / "crimson.cfg", data={"game_mode": int(GameMode.RUSH)})
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / "rush.hi"


def test_scores_path_for_config_quest_mode_uses_config_stage_fields_when_missing_args(tmp_path: Path) -> None:
    config = CrimsonConfig(
        path=tmp_path / "crimson.cfg",
        data={
            "game_mode": int(GameMode.QUESTS),
            "quest_stage_major": 4,
            "quest_stage_minor": 7,
        },
    )
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / "questhc4_7.hi"


def test_scores_path_for_config_typo_mode_uses_typo_filename(tmp_path: Path) -> None:
    config = CrimsonConfig(path=tmp_path / "crimson.cfg", data={"game_mode": int(GameMode.TYPO)})
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / "typo.hi"


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


def test_rush_highscores_sort_by_time_descending() -> None:
    records = [
        _record(mode=GameMode.RUSH, time_ms=5000),
        _record(mode=GameMode.RUSH, time_ms=2000),
        _record(mode=GameMode.RUSH, time_ms=0),
        _record(mode=GameMode.RUSH, time_ms=1000),
    ]
    sorted_records = sort_highscores(records, game_mode_id=int(GameMode.RUSH))
    assert [int(r.survival_elapsed_ms) for r in sorted_records] == [5000, 2000, 1000, 0]


def test_rush_rank_index_inserts_larger_time_higher() -> None:
    records_sorted = sort_highscores(
        [
            _record(mode=GameMode.RUSH, time_ms=5000),
            _record(mode=GameMode.RUSH, time_ms=2000),
            _record(mode=GameMode.RUSH, time_ms=1000),
        ],
        game_mode_id=int(GameMode.RUSH),
    )
    record = _record(mode=GameMode.RUSH, time_ms=1500)
    assert rank_index(records_sorted, record) == 2


def test_survival_highscores_sort_by_xp_descending() -> None:
    records = [
        _record_xp(mode=GameMode.SURVIVAL, xp=2500),
        _record_xp(mode=GameMode.SURVIVAL, xp=100),
        _record_xp(mode=GameMode.SURVIVAL, xp=5000),
        _record_xp(mode=GameMode.SURVIVAL, xp=0),
    ]
    sorted_records = sort_highscores(records, game_mode_id=int(GameMode.SURVIVAL))
    assert [int(r.score_xp) for r in sorted_records] == [5000, 2500, 100, 0]


def test_survival_rank_index_inserts_larger_xp_higher() -> None:
    records_sorted = sort_highscores(
        [
            _record_xp(mode=GameMode.SURVIVAL, xp=5000),
            _record_xp(mode=GameMode.SURVIVAL, xp=2000),
            _record_xp(mode=GameMode.SURVIVAL, xp=1000),
        ],
        game_mode_id=int(GameMode.SURVIVAL),
    )
    record = _record_xp(mode=GameMode.SURVIVAL, xp=1500)
    assert rank_index(records_sorted, record) == 2


def test_typo_highscores_sort_by_xp_descending() -> None:
    records = [
        _record_xp(mode=GameMode.TYPO, xp=2500),
        _record_xp(mode=GameMode.TYPO, xp=100),
        _record_xp(mode=GameMode.TYPO, xp=5000),
        _record_xp(mode=GameMode.TYPO, xp=0),
    ]
    sorted_records = sort_highscores(records, game_mode_id=int(GameMode.TYPO))
    assert [int(r.score_xp) for r in sorted_records] == [5000, 2500, 100, 0]


def test_typo_rank_index_inserts_larger_xp_higher() -> None:
    records_sorted = sort_highscores(
        [
            _record_xp(mode=GameMode.TYPO, xp=5000),
            _record_xp(mode=GameMode.TYPO, xp=2000),
            _record_xp(mode=GameMode.TYPO, xp=1000),
        ],
        game_mode_id=int(GameMode.TYPO),
    )
    record = _record_xp(mode=GameMode.TYPO, xp=1500)
    assert rank_index(records_sorted, record) == 2


def test_perk_mode_3_only_is_offered_only_in_mode_3() -> None:
    meta = PERK_BY_ID.get(int(PerkId.ALTERNATE_WEAPON))
    assert meta is not None

    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=int(GameMode.SURVIVAL), player_count=1) is False
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=int(GameMode.QUESTS), player_count=1) is True
