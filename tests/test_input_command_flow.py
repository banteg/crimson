from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_survival_mode_applies_queued_perk_pick_commands_during_tick_consumption(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    fake_ctx = SimpleNamespace(
        state=mode.state,
        players=mode.world.players,
        perk_state=mode.state.perk_selection,
        player_count=len(mode.world.players),
        creatures=mode.creatures.entries,
    )
    mocker.patch.object(mode, "_perk_menu_context", return_value=fake_ctx)
    pick_apply = mocker.patch.object(base_gameplay_mode_module, "perk_selection_pick", return_value=object())

    assert mode._record_perk_pick(2) is True
    mode._consume_pending_input_commands(dt_tick=1.0 / 60.0)

    pick_apply.assert_called_once()
    assert pick_apply.call_args.args[3] == 2


def test_quest_mode_applies_queued_perk_pick_commands_during_tick_consumption(mocker) -> None:
    mode = QuestMode(ViewContext(assets_dir=_assets_dir()))
    fake_ctx = SimpleNamespace(
        state=mode.state,
        players=mode.world.players,
        perk_state=mode.state.perk_selection,
        player_count=len(mode.world.players),
        creatures=mode.creatures.entries,
    )
    mocker.patch.object(mode, "_perk_menu_context", return_value=fake_ctx)
    pick_apply = mocker.patch.object(base_gameplay_mode_module, "perk_selection_pick", return_value=object())

    assert mode._record_perk_pick(1) is True
    mode._consume_pending_input_commands(dt_tick=1.0 / 60.0)

    pick_apply.assert_called_once()
    assert pick_apply.call_args.args[3] == 1
