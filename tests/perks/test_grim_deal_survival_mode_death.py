from __future__ import annotations

from pathlib import Path

import pytest

import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.quest_mode as quest_mode_module
import crimson.modes.survival_mode as survival_mode_module
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.quests.level import QuestLevel
from crimson.screens.results.game_over import GameOverUi
from crimson.ui.perk_menu import PerkMenuAssets
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def _is_dead(mode: SurvivalMode | QuestMode) -> bool:
    if isinstance(mode, SurvivalMode):
        return mode._game_over_active
    return mode._outcome is not None and mode._outcome.kind == "failed"


@pytest.mark.parametrize("mode_cls", [SurvivalMode, QuestMode])
def test_grim_deal_kills_player_during_perk_menu_transition(mocker, mode_cls: type[SurvivalMode] | type[QuestMode]) -> None:
    ctx = ViewContext(assets_dir=_assets_dir())
    mode = mode_cls(ctx, audio_rng=Crand(0xBEEF))
    if isinstance(mode, QuestMode):
        mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
        mode.start_run(QuestLevel(1, 1), status=None)
        mode._perk_menu_assets = PerkMenuAssets(*(rl.Texture() for _ in range(8)))
    else:
        mode._perk_menu_assets = PerkMenuAssets(*(rl.Texture() for _ in range(8)))
    mocker.patch.object(GameOverUi, "open", return_value=None)

    assert mode.player.health > 0.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, *, dt: float, dt_ui_ms: float) -> None:
        perk_apply(mode.state, mode.sim_world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_apply_grim_deal_and_close)

    mocker.patch.object(base_gameplay_mode_module.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(survival_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    mocker.patch.object(quest_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    mode.update(1.0 / 60.0)

    assert mode.player.health < 0.0
    assert not _is_dead(mode)
    for _ in range(10):
        mode.update(1.0 / 60.0)
    assert _is_dead(mode)
