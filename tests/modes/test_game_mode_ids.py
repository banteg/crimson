from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.availability import perk_can_offer
from crimson.persistence.highscores import scores_path_for_config
from crimson.quests.level import QuestLevel
from crimson.sim.gameplay_state import GameplayState
from grim.config import CrimsonConfig, default_crimson_cfg


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
    (
        expected_survival_1p,
        expected_quest_1p,
        expected_survival_2p,
        expected_quest_2p,
        expected_survival_4p,
        expected_quest_4p,
    ) = expected
    assert perk_can_offer(state, perk_id, game_mode=GameMode.SURVIVAL, player_count=1) is expected_survival_1p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=1) is expected_quest_1p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.SURVIVAL, player_count=2) is expected_survival_2p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=2) is expected_quest_2p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.SURVIVAL, player_count=4) is expected_survival_4p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=4) is expected_quest_4p


def test_hardcore_quest_2_10_blocks_poison_related_perks() -> None:
    baseline = GameplayState()
    for perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER):
        assert perk_can_offer(baseline, perk_id, game_mode=GameMode.QUESTS, player_count=1) is True

    state = GameplayState()
    state.hardcore = True
    state.quest_level = QuestLevel(2, 10)

    for perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER):
        assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=1) is False
