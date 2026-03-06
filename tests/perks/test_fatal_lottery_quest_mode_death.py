from __future__ import annotations

from pathlib import Path

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.quest_mode as quest_mode_module
from crimson.modes.quest_mode import QuestMode
from grim.raylib_api import rl
from grim.view import ViewContext


def _make_quest_mode() -> QuestMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    return QuestMode(ctx)


def test_quest_mode_closes_run_when_player_dies_during_perk_menu_transition(monkeypatch, mocker) -> None:
    mode = _make_quest_mode()

    # Simulate Fatal Lottery killing the player while the perk menu is closing.
    # Quest mode should still produce a failure outcome after the native death-timer
    # delay instead of freezing.
    mode.player.health = -1.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = False
    mode._perk_menu.timeline_ms = 100.0

    mocker.patch.object(base_gameplay_mode_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(quest_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)

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
