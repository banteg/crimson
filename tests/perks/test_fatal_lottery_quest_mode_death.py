from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.quests.level import QuestLevel
from grim.rand import Crand
from grim.view import ViewContext


def _make_quest_mode(mocker, *, config, assets_dir: Path) -> QuestMode:
    mode = QuestMode(ViewContext(assets_dir=assets_dir), config=config, audio_rng=Crand(0xBEEF))
    mode.open()
    mode.start_run(QuestLevel(1, 1), status=None)
    return mode


@pytest.mark.usefixtures("headless_resources")
def test_quest_mode_closes_run_when_player_dies_during_perk_menu_transition(mocker, make_mode_config, assets_dir: Path) -> None:
    mode = _make_quest_mode(mocker, config=make_mode_config(game_mode=GameMode.QUESTS), assets_dir=assets_dir)

    # Simulate Fatal Lottery killing the player while the perk menu is closing.
    # Quest mode should still produce a failure outcome after the native death-timer
    # delay instead of freezing.
    mode.player.health = -1.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = False
    mode._perk_menu.timeline_ms = 100.0

    mode.update(1.0 / 60.0)

    assert mode.close_requested is False
    for _ in range(120):
        mode.update(1.0 / 60.0)
        if mode.close_requested:
            break
    assert mode.close_requested is True
    outcome = mode.consume_outcome()
    assert outcome is not None
    assert outcome.kind == "failed"
