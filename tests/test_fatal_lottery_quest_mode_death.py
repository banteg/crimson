from __future__ import annotations

from pathlib import Path

import pyray as rl

from crimson.modes.quest_mode import QuestMode
from grim.view import ViewContext


def _make_quest_mode() -> QuestMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    return QuestMode(ctx)


def test_quest_mode_closes_run_when_player_dies_during_perk_menu_transition(monkeypatch) -> None:
    mode = _make_quest_mode()

    # Simulate Fatal Lottery killing the player while the perk menu is closing. Quest mode
    # should still produce a failure outcome and close the run instead of freezing.
    mode._player.health = -1.0
    mode._perk_menu_open = False
    mode._perk_menu_timeline_ms = 100.0

    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_mouse_position", lambda: rl.Vector2(0.0, 0.0))
    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.quest_mode.rl.is_key_pressed", lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode.close_requested is True
    outcome = mode.consume_outcome()
    assert outcome is not None
    assert outcome.kind == "failed"
