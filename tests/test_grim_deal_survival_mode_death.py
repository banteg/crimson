from __future__ import annotations

from pathlib import Path

import pyray as rl

from crimson.gameplay import perk_apply
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from grim.view import ViewContext


def _make_survival_mode() -> SurvivalMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    return SurvivalMode(ctx)


def test_survival_mode_enters_game_over_when_grim_deal_kills_player_during_perk_menu_transition(monkeypatch) -> None:
    mode = _make_survival_mode()
    monkeypatch.setattr("crimson.ui.game_over.GameOverUi.open", lambda self: None)  # noqa: ARG005

    assert mode._player.health > 0.0
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, *, dt_frame: float, dt_ui_ms: float) -> None:
        perk_apply(mode._state, mode._world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    monkeypatch.setattr(mode._perk_menu, "handle_input", _apply_grim_deal_and_close)

    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_mouse_position", lambda: rl.Vector2(0.0, 0.0))
    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.base_gameplay_mode.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.survival_mode.rl.is_key_pressed", lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode._player.health < 0.0
    assert mode._game_over_active is True
