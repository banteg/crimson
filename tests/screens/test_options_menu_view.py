from __future__ import annotations

import crimson.screens.panels.options as options_module
from crimson.game.types import BackToPrevious
from crimson.screens.panels.options import OptionsMenuView


def test_options_menu_close_hook_saves_once(make_game_state, mocker) -> None:
    state = make_game_state()
    state.pause_background = mocker.Mock()
    save_dirty_config = mocker.patch.object(options_module, "save_dirty_config", return_value=True)

    view = OptionsMenuView(state)
    view.open()
    view._dirty = True

    view._begin_close_transition(BackToPrevious())
    view._begin_close_transition(BackToPrevious())

    save_dirty_config.assert_called_once_with(state)
    assert view._dirty is False
    assert view._chrome_state.closing is True
    assert view._chrome_state.close_action == BackToPrevious()
