from __future__ import annotations

import pytest

import crimson.modes.components.perk_menu_controller as perk_menu_controller_module
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.perks.selection import perk_selection_open_choices, perk_selection_prepared_choices
from crimson.screens.actions import Route
from crimson.ui.menu_panel import ui_panel_rect
from crimson.ui.perk_menu import perk_menu_compute_layout
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")


@pytest.mark.parametrize(
    ("mode_type", "game_mode"),
    [(SurvivalMode, GameMode.SURVIVAL), (QuestMode, GameMode.QUESTS), (TutorialMode, GameMode.TUTORIAL)],
)
@pytest.mark.parametrize("dismiss", ["cancel", "escape"])
def test_dismissed_perk_panel_stays_hidden_when_the_hud_timeline_restarts(
    mocker,
    make_mode_config,
    assets_dir,
    mode_type,
    game_mode,
    dismiss,
) -> None:
    mode = mode_type(
        ViewContext(assets_dir=assets_dir),
        config=make_mode_config(game_mode=game_mode),
        audio_rng=Crand(0xBEEF),
    )
    mode.open()
    mocker.patch.object(mode, "_draw_world")
    panel = mocker.spy(perk_menu_controller_module, "draw_ui_panel")
    mode.state.perk_selection.pending_count = 1
    choices = perk_selection_open_choices(mode.state, mode.world.players, game_mode=game_mode)
    mode._perk_menu.open_menu()
    for _ in range(4):
        mode.update(0.1)
    mode.draw()
    assert panel.call_count == 1

    if dismiss == "escape":
        key = mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
        mode.update(0.1)
        key.side_effect = lambda _key: False
    else:
        layout = perk_menu_compute_layout(
            ui_panel_rect(27, mode._ui_timeline.timeline_ms, 640),
            choice_count=len(choices),
            expert_owned=False,
            master_owned=False,
        )
        mocker.patch.object(rl, "get_mouse_position", return_value=layout.cancel_pos.offset(dx=20.0, dy=10.0).to_rl())
        click = mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
        mode.update(0.1)
        click.return_value = False

    assert not mode._perk_menu.open
    assert mode._perk_menu.active
    # Closing still draws the panel as it slides out.
    panel.reset_mock()
    mode.update(0.1)
    mode.draw()
    assert panel.call_count == 1

    for _ in range(4):
        mode.update(0.1)
    assert not mode._perk_menu.active
    assert mode.game_state_id == GameStateId.GAMEPLAY
    assert mode._action != Route.PAUSE

    panel.reset_mock()
    for _ in range(6):
        mode.update(0.1)
        mode.draw()
    assert mode._hud_alpha() == 1.0
    assert mode.state.perk_selection.pending_count == 1
    assert perk_selection_prepared_choices(mode.state) == choices
    assert panel.call_count == 0

    # Cancelling preserves the choices for the next explicit open.
    mode._perk_menu.open_menu()
    for _ in range(4):
        mode.update(0.1)
    mode.draw()
    assert panel.call_count == 1
