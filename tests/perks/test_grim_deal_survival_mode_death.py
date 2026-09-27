from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.quests.level import QuestLevel
from grim.rand import Crand
from grim.view import ViewContext


def _is_dead(mode: SurvivalMode | QuestMode) -> bool:
    if isinstance(mode, SurvivalMode):
        return mode._game_over_active
    return mode._outcome is not None and mode._outcome.kind == "failed"


@pytest.mark.usefixtures("headless_resources")
@pytest.mark.parametrize("mode_cls", [SurvivalMode, QuestMode])
def test_grim_deal_kills_player_during_perk_menu_transition(
    mocker,
    make_mode_config,
    assets_dir,
    mode_cls: type[SurvivalMode | QuestMode],
) -> None:
    ctx = ViewContext(assets_dir=assets_dir)
    game_mode = GameMode.SURVIVAL if mode_cls is SurvivalMode else GameMode.QUESTS
    mode = mode_cls(ctx, config=make_mode_config(game_mode=game_mode), audio_rng=Crand(0xBEEF))
    mode.open()
    if isinstance(mode, QuestMode):
        mode.start_run(QuestLevel(1, 1), status=None)

    assert mode.player.health > 0.0
    mode.player.death_timer = 0.3
    mode._perk_menu.open = True
    mode._perk_menu.timeline_ms = 100.0

    def _apply_grim_deal_and_close(_ctx, _choices, *, dt_ui_ms: float) -> None:
        perk_apply(mode.state, mode.world.players, PerkId.GRIM_DEAL)
        mode._perk_menu.close()

    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_apply_grim_deal_and_close)

    mode.update(1.0 / 60.0)

    assert mode.player.health < 0.0
    assert not _is_dead(mode)
    for _ in range(10):
        mode.update(1.0 / 60.0)
    assert _is_dead(mode)
