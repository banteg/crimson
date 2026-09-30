from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.persistence.save_status import GameStatusData, ensure_game_status, save_status
from crimson.quests.level import QuestLevel
from crimson.screens.actions import Route, StartRun
from crimson.screens.quest_views import QuestsMenuView
from grim.config import CRIMSON_CFG_NAME, load_crimson_cfg
from grim.raylib_api import rl
from tests.support.screens import finish_transition


def press(loop: GameLoopView, mocker, *keys: int) -> None:
    """One loop frame with `keys` pressed on the keyboard, and nothing else."""
    pressed = {int(key) for key in keys}
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: int(key) in pressed)
    loop.update(0.016)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)


def open_quest_select(loop: GameLoopView, *, unlock_index: int, unlock_index_full: int) -> QuestsMenuView:
    """The quest menu over a game.cfg that unlocks quests up to the given global indices."""
    state = loop.state
    save_status(state.status.path, GameStatusData(quest_unlock_index=unlock_index, quest_unlock_index_full=unlock_index_full))
    state.status = ensure_game_status(state.base_dir)
    loop.navigation.navigate(Route.QUESTS)
    finish_transition(loop)
    menu = state.screens.active
    assert isinstance(menu, QuestsMenuView)
    return menu


def test_number_keys_start_only_unlocked_quests_of_the_stage(loop, mocker) -> None:
    open_quest_select(loop, unlock_index=QuestLevel(2, 3).global_index, unlock_index_full=0)
    press(loop, mocker, rl.KeyboardKey.KEY_RIGHT)

    # 2.4 is past the unlock index; the key does nothing.
    press(loop, mocker, rl.KeyboardKey.KEY_FOUR)
    assert loop.state.ui.pending is None
    assert not loop.state.ui.closing

    press(loop, mocker, rl.KeyboardKey.KEY_THREE)
    assert loop.state.ui.pending == StartRun(GameMode.QUESTS, QuestLevel(2, 3))
    assert loop.state.config.gameplay.quest_level == QuestLevel(2, 3)


def test_zero_key_picks_the_tenth_row(loop, mocker) -> None:
    open_quest_select(loop, unlock_index=QuestLevel(1, 10).global_index, unlock_index_full=0)

    press(loop, mocker, rl.KeyboardKey.KEY_ZERO)

    assert loop.state.ui.pending == StartRun(GameMode.QUESTS, QuestLevel(1, 10))


def tab_to_hardcore(loop: GameLoopView, mocker, menu: QuestsMenuView) -> None:
    for _ in range(20):
        if menu._hardcore_checkbox.focused:
            return
        press(loop, mocker, rl.KeyboardKey.KEY_TAB)
    raise AssertionError("Tab never reached the Hardcore checkbox")


def test_hardcore_gates_quests_by_the_full_unlock_index(loop, mocker) -> None:
    menu = open_quest_select(loop, unlock_index=QuestLevel(5, 1).global_index, unlock_index_full=QuestLevel(1, 4).global_index)
    tab_to_hardcore(loop, mocker, menu)

    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert loop.state.config.gameplay.hardcore

    # 1.5 is open in normal mode but not yet in hardcore.
    press(loop, mocker, rl.KeyboardKey.KEY_FIVE)
    assert loop.state.ui.pending is None
    press(loop, mocker, rl.KeyboardKey.KEY_FOUR)
    assert loop.state.ui.pending == StartRun(GameMode.QUESTS, QuestLevel(1, 4))


def test_hardcore_toggle_is_saved_when_leaving_the_menu(loop, mocker) -> None:
    menu = open_quest_select(loop, unlock_index=QuestLevel(5, 1).global_index, unlock_index_full=0)
    tab_to_hardcore(loop, mocker, menu)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)

    press(loop, mocker, rl.KeyboardKey.KEY_ESCAPE)
    finish_transition(loop)

    assert load_crimson_cfg(loop.state.base_dir / CRIMSON_CFG_NAME).gameplay.hardcore

