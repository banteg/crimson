from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.screens.actions import Route
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.view import ViewContext

pytestmark = pytest.mark.usefixtures("headless_resources")


@pytest.mark.parametrize(
    ("mode_type", "game_mode"),
    [(SurvivalMode, GameMode.SURVIVAL), (QuestMode, GameMode.QUESTS), (TutorialMode, GameMode.TUTORIAL)],
)
def test_escape_backs_out_of_the_perk_menu_with_a_click_and_does_not_pause(
    mocker, make_mode_config, assets_dir, mode_type, game_mode,
) -> None:
    mode = mode_type(ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=game_mode), audio_rng=Crand(0xBEEF))
    mode.open()
    mode._perk_menu.open_menu()
    played = mocker.spy(mode.audio_bridge, "play_sfx")
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)

    mode.update(1.0 / 60.0)

    assert not mode._perk_menu.open
    assert played.call_args_list[0].args == (SfxId.UI_BUTTONCLICK,)
    assert mode._action != Route.PAUSE
