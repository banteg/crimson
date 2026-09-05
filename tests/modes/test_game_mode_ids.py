from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.perks import PERK_BY_ID, PerkFlags, PerkId
from crimson.perks.availability import perk_can_offer
from crimson.persistence.highscores import HighScoreRecord, rank_index, scores_path_for_config, sort_highscores
from crimson.quests.level import QuestLevel
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.geom import Vec2


def _record(*, mode: GameMode, time_ms: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = mode
    record.survival_elapsed_ms = int(time_ms)
    return record


def _record_xp(*, mode: GameMode, xp: int) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = mode
    record.score_xp = int(xp)
    return record


def _config(
    path: Path,
    *,
    game_mode: GameMode,
    player_count: int = 1,
    hardcore: bool = False,
    quest_level: QuestLevel | None = None,
) -> CrimsonConfig:
    config = default_crimson_cfg(path)
    config.gameplay.mode = game_mode
    config.gameplay.player_count = int(player_count)
    config.gameplay.hardcore = bool(hardcore)
    config.gameplay.quest_level = quest_level
    return config


@pytest.mark.parametrize(
    ("hardcore_flag", "expected_name"),
    [
        (0, "questhc1_2.hi"),
        (1, "quest1_2.hi"),
    ],
    ids=["default", "hardcore"],
)
def test_scores_path_for_config_quest_mode_explicit_stage_filename(
    tmp_path: Path,
    hardcore_flag: int,
    expected_name: str,
) -> None:
    config = _config(
        tmp_path / "crimson.cfg",
        game_mode=GameMode.QUESTS,
        hardcore=bool(hardcore_flag),
    )
    path = scores_path_for_config(tmp_path, config, quest_stage_major=1, quest_stage_minor=2)
    assert path == tmp_path / "scores5" / expected_name


@pytest.mark.parametrize(
    ("game_mode", "expected_name"),
    [
        (GameMode.SURVIVAL, "survival.hi"),
        (GameMode.RUSH, "rush.hi"),
        (GameMode.TYPO, "typo.hi"),
    ],
    ids=["survival", "rush", "typo"],
)
def test_scores_path_for_config_mode_uses_base_filename(
    tmp_path: Path,
    game_mode: GameMode,
    expected_name: str,
) -> None:
    config = _config(tmp_path / "crimson.cfg", game_mode=game_mode)
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / expected_name


@pytest.mark.parametrize(
    ("game_mode", "player_count", "expected_name"),
    [
        (GameMode.SURVIVAL, 3, "survival_3.hi"),
        (GameMode.RUSH, 4, "rush_4.hi"),
    ],
    ids=["survival", "rush"],
)
def test_scores_path_for_config_mode_uses_player_count_suffix(
    tmp_path: Path,
    game_mode: GameMode,
    player_count: int,
    expected_name: str,
) -> None:
    config = _config(tmp_path / "crimson.cfg", game_mode=game_mode, player_count=player_count)
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / expected_name


@pytest.mark.parametrize(
    ("player_count", "expected_name"),
    [
        (None, "questhc4_7.hi"),
        (2, "questhc4_7_2.hi"),
    ],
    ids=["no-player-count", "with-player-count"],
)
def test_scores_path_for_config_quest_mode_uses_config_stage_fields(
    tmp_path: Path,
    player_count: int | None,
    expected_name: str,
) -> None:
    config = _config(
        tmp_path / "crimson.cfg",
        game_mode=GameMode.QUESTS,
        player_count=1 if player_count is None else player_count,
        quest_level=QuestLevel(4, 7),
    )
    path = scores_path_for_config(tmp_path, config)
    assert path == tmp_path / "scores5" / expected_name


def test_quest_highscores_sort_by_time_ascending_with_zero_last() -> None:
    records = [
        _record(mode=GameMode.QUESTS, time_ms=5000),
        _record(mode=GameMode.QUESTS, time_ms=2000),
        _record(mode=GameMode.QUESTS, time_ms=0),
        _record(mode=GameMode.QUESTS, time_ms=1000),
    ]
    sorted_records = sort_highscores(records, game_mode_id=GameMode.QUESTS)
    assert [int(r.survival_elapsed_ms) for r in sorted_records] == [1000, 2000, 5000, 0]


def test_quest_rank_index_inserts_smaller_time_higher() -> None:
    records_sorted = sort_highscores(
        [
            _record(mode=GameMode.QUESTS, time_ms=1000),
            _record(mode=GameMode.QUESTS, time_ms=2000),
            _record(mode=GameMode.QUESTS, time_ms=5000),
        ],
        game_mode_id=GameMode.QUESTS,
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
    sorted_records = sort_highscores(records, game_mode_id=GameMode.RUSH)
    assert [int(r.survival_elapsed_ms) for r in sorted_records] == [5000, 2000, 1000, 0]


def test_rush_rank_index_inserts_larger_time_higher() -> None:
    records_sorted = sort_highscores(
        [
            _record(mode=GameMode.RUSH, time_ms=5000),
            _record(mode=GameMode.RUSH, time_ms=2000),
            _record(mode=GameMode.RUSH, time_ms=1000),
        ],
        game_mode_id=GameMode.RUSH,
    )
    record = _record(mode=GameMode.RUSH, time_ms=1500)
    assert rank_index(records_sorted, record) == 2


@pytest.mark.parametrize("game_mode", [GameMode.SURVIVAL, GameMode.TYPO], ids=["survival", "typo"])
def test_xp_highscores_sort_by_xp_descending(game_mode: GameMode) -> None:
    records = [
        _record_xp(mode=game_mode, xp=2500),
        _record_xp(mode=game_mode, xp=100),
        _record_xp(mode=game_mode, xp=5000),
        _record_xp(mode=game_mode, xp=0),
    ]
    sorted_records = sort_highscores(records, game_mode_id=game_mode)
    assert [int(r.score_xp) for r in sorted_records] == [5000, 2500, 100, 0]


@pytest.mark.parametrize("game_mode", [GameMode.SURVIVAL, GameMode.TYPO], ids=["survival", "typo"])
def test_xp_rank_index_inserts_larger_xp_higher(game_mode: GameMode) -> None:
    records_sorted = sort_highscores(
        [
            _record_xp(mode=game_mode, xp=5000),
            _record_xp(mode=game_mode, xp=2000),
            _record_xp(mode=game_mode, xp=1000),
        ],
        game_mode_id=game_mode,
    )
    record = _record_xp(mode=game_mode, xp=1500)
    assert rank_index(records_sorted, record) == 2


def test_perk_mode_3_flag_allows_perk_in_survival_and_quest_modes() -> None:
    meta = PERK_BY_ID.get(PerkId.ALTERNATE_WEAPON)
    assert meta is not None

    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=GameMode.SURVIVAL, player_count=1) is True
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=GameMode.QUESTS, player_count=1) is True
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=GameMode.SURVIVAL, player_count=2) is False
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=GameMode.QUESTS, player_count=2) is False
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=GameMode.SURVIVAL, player_count=4) is True
    assert perk_can_offer(state, player, PerkId.ALTERNATE_WEAPON, game_mode=GameMode.QUESTS, player_count=4) is True


def test_perk_without_mode_3_flag_is_rejected_in_quest_mode() -> None:
    meta = PERK_BY_ID.get(PerkId.GRIM_DEAL)
    assert meta is not None

    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    assert perk_can_offer(state, player, PerkId.GRIM_DEAL, game_mode=GameMode.SURVIVAL, player_count=1) is True
    assert perk_can_offer(state, player, PerkId.GRIM_DEAL, game_mode=GameMode.QUESTS, player_count=1) is False


@pytest.mark.parametrize(
    ("perk_id", "expected"),
    [
        (PerkId.RANDOM_WEAPON, (True, True, False, False, True, True)),
        (PerkId.BREATHING_ROOM, (True, False, True, False, True, False)),
    ],
    ids=["random-weapon", "breathing-room"],
)
def test_mode_flags_match_native_allowlist_behavior(
    perk_id: PerkId,
    expected: tuple[bool, bool, bool, bool, bool, bool],
) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    (
        expected_survival_1p,
        expected_quest_1p,
        expected_survival_2p,
        expected_quest_2p,
        expected_survival_4p,
        expected_quest_4p,
    ) = expected
    assert perk_can_offer(state, player, perk_id, game_mode=GameMode.SURVIVAL, player_count=1) is expected_survival_1p
    assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=1) is expected_quest_1p
    assert perk_can_offer(state, player, perk_id, game_mode=GameMode.SURVIVAL, player_count=2) is expected_survival_2p
    assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=2) is expected_quest_2p
    assert perk_can_offer(state, player, perk_id, game_mode=GameMode.SURVIVAL, player_count=4) is expected_survival_4p
    assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=4) is expected_quest_4p


def test_mode_flag_gated_perks_reject_quest_and_multiplayer() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    for perk_id in (PerkId.FATAL_LOTTERY, PerkId.FINAL_REVENGE, PerkId.HIGHLANDER):
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.SURVIVAL, player_count=1) is True
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=1) is False
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.SURVIVAL, player_count=2) is False
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=2) is False
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.SURVIVAL, player_count=4) is True
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=4) is False


def test_hardcore_quest_2_10_blocks_poison_related_perks() -> None:
    baseline = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    for perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER):
        assert perk_can_offer(baseline, player, perk_id, game_mode=GameMode.QUESTS, player_count=1) is True

    state = GameplayState()
    state.hardcore = True
    state.quest_level = QuestLevel(2, 10)

    for perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER):
        assert perk_can_offer(state, player, perk_id, game_mode=GameMode.QUESTS, player_count=1) is False


def test_perk_flags_match_native_ctor_defaults_and_known_overrides() -> None:
    assert PERK_BY_ID[PerkId.SHARPSHOOTER].flags == (
        PerkFlags.QUEST_MODE_ALLOWED | PerkFlags.MULTIPLAYER_ALLOWED
    )
    assert PERK_BY_ID[PerkId.INSTANT_WINNER].flags == (
        PerkFlags.QUEST_MODE_ALLOWED | PerkFlags.MULTIPLAYER_ALLOWED | PerkFlags.STACKABLE
    )
    assert PERK_BY_ID[PerkId.RANDOM_WEAPON].flags == (
        PerkFlags.QUEST_MODE_ALLOWED | PerkFlags.STACKABLE
    )
    assert PERK_BY_ID[PerkId.BREATHING_ROOM].flags == PerkFlags.MULTIPLAYER_ALLOWED
    assert PERK_BY_ID[PerkId.GRIM_DEAL].flags == PerkFlags(0)
