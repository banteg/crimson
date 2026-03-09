from __future__ import annotations

from crimson.screens.panels.play_game import PlayGameMenuView
from crimson.ui.perk_menu import UiButtonState


def test_play_game_resume_from_child_resets_ephemeral_state_only(make_game_state, mocker) -> None:
    state = make_game_state()
    view = PlayGameMenuView(state)
    restart = mocker.patch.object(view, "_restart_open_timeline")
    view._dirty = True
    view._player_list_open = True
    view._tooltip_ms["quests"] = 250
    view._mode_buttons["quests"] = UiButtonState(" Quests ")

    view.resume_from_child()

    restart.assert_called_once_with(play_open_sfx=True)
    assert view._dirty is True
    assert view._player_list_open is False
    assert view._tooltip_ms == {}
    assert view._mode_buttons == {}
