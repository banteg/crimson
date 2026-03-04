from __future__ import annotations

from pathlib import Path

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.quest_mode as quest_mode_module
from crimson.modes.quest_mode import QuestMode
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from grim.raylib_api import rl
from grim.view import ViewContext


def _make_quest_mode() -> QuestMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    return QuestMode(ctx)


def test_quest_mode_closes_run_when_grim_deal_kills_player_during_perk_menu_transition(mocker) -> None:
    mode = _make_quest_mode()

    # Simulate picking Grim Deal while the perk menu is visible and in transition.
    # The perk kills the player immediately, but QuestMode must still close the run
    # as failed after the native death-timer gate, even while world updates are
    # paused during the perk-menu transition.
    assert mode.player.health > 0.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, *, dt: float, dt_ui_ms: float) -> None:
        perk_apply(mode.state, mode.world.sim_world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_apply_grim_deal_and_close)

    mocker.patch.object(base_gameplay_mode_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(quest_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode.player.health < 0.0
    assert mode.close_requested is False
    for _ in range(120):
        mode.update(1.0 / 60.0)
        if mode.close_requested:
            break
    assert mode.close_requested is True
    outcome = mode.consume_outcome()
    assert outcome is not None
    assert outcome.kind == "failed"
