from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from grim.rand import Crand
from grim.view import ViewContext

pytestmark = pytest.mark.usefixtures("headless_resources")


@pytest.mark.parametrize(
    ("mode_type", "game_mode"),
    [
        (SurvivalMode, GameMode.SURVIVAL),
        (QuestMode, GameMode.QUESTS),
        (TutorialMode, GameMode.TUTORIAL),
    ],
)
def test_hud_draws_over_the_perk_prompt_and_aim_indicators(
    mocker,
    make_mode_config,
    assets_dir,
    mode_type,
    game_mode,
) -> None:
    # Native gameplay_update_and_render: world, perk prompt, aim indicators, HUD, then UI elements.
    mode = mode_type(ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=game_mode), audio_rng=Crand(0xBEEF))
    mode.open()
    order = mocker.Mock()
    for name in ("_draw_world", "_draw_perk_prompt", "_draw_aim_indicators"):
        order.attach_mock(mocker.patch.object(mode, name), name)
    order.attach_mock(mocker.patch.object(mode, "_draw_hud", return_value=0.0), "_draw_hud")
    order.attach_mock(mocker.patch.object(mode._perk_menu, "draw"), "perk_menu")

    mode.draw()

    assert [call[0] for call in order.mock_calls] == [
        "_draw_world",
        "_draw_perk_prompt",
        "_draw_aim_indicators",
        "_draw_hud",
        "perk_menu",
    ]
