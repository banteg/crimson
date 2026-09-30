from __future__ import annotations

from collections.abc import Callable

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.persistence.highscores import HighScoreRecord, scores_path_for_mode, write_highscore_records
from crimson.screens.actions import Route, ScoreQuery, ShowScores
from crimson.screens.high_scores_view.view import HighScoresView
from crimson.screens.menu import MenuView
from crimson.screens.panels.alien_zookeeper import AlienZooKeeperView
from crimson.screens.panels.credits import CreditsView
from crimson.screens.panels.databases_perks import UnlockedPerksDatabaseView
from crimson.screens.panels.options import OptionsMenuView
from crimson.screens.panels.stats import StatisticsMenuView
from crimson.ui.menu_layout import MENU_LABEL_ROW_OPTIONS
from grim.raylib_api import rl
from tests.support.screens import finish_transition


def press(loop: GameLoopView, mocker, *keys: int) -> None:
    """One loop frame with `keys` pressed on the keyboard, and nothing else."""
    pressed = {int(key) for key in keys}
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: int(key) in pressed)
    loop.update(0.016)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)


def tab_to(loop: GameLoopView, mocker, focused: Callable[[], bool]) -> None:
    """Tab until the widget reports the focus."""
    for _ in range(40):
        if focused():
            return
        press(loop, mocker, rl.KeyboardKey.KEY_TAB)
    raise AssertionError("Tab never reached the widget")


def test_main_menu_to_an_options_slider_by_keyboard(loop, mocker) -> None:
    finish_transition(loop)
    main = loop.state.screens.active
    assert isinstance(main, MenuView)
    options_entry = next(entry for entry in main._menu_entries if entry.row == MENU_LABEL_ROW_OPTIONS)
    tab_to(loop, mocker, lambda: options_entry.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    finish_transition(loop)

    options = loop.state.screens.active
    assert isinstance(options, OptionsMenuView)
    volume = options._slider_sfx.value
    tab_to(loop, mocker, lambda: options._slider_sfx.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_LEFT)
    assert options._slider_sfx.value == volume - 1
    assert loop.state.config.audio.sfx_volume == (volume - 1) * 0.1

    press(loop, mocker, rl.KeyboardKey.KEY_ESCAPE)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, MenuView)


def test_high_score_game_mode_list_by_keyboard(loop, mocker) -> None:
    loop.state.config.gameplay.mode = GameMode.SURVIVAL
    loop.navigation.navigate(ShowScores(ScoreQuery(GameMode.SURVIVAL)))
    finish_transition(loop)
    scores = loop.state.screens.active
    assert isinstance(scores, HighScoresView)
    widget = scores.game_mode_list

    tab_to(loop, mocker, lambda: widget.focused)
    # Down opens the focused list, then walks its rows; Enter takes the row.
    press(loop, mocker, rl.KeyboardKey.KEY_DOWN)
    assert widget.open
    widget_row = widget.active_index
    press(loop, mocker, rl.KeyboardKey.KEY_UP)
    assert widget.active_index == max(0, widget_row - 1)
    press(loop, mocker, rl.KeyboardKey.KEY_DOWN)
    press(loop, mocker, rl.KeyboardKey.KEY_DOWN)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert not widget.open
    assert scores._request.game_mode_id == scores._mode_items()[widget.active_index][1]

    # Enter also opens a focused list again.
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert widget.open
    press(loop, mocker, rl.KeyboardKey.KEY_ESCAPE)
    assert not widget.open
    assert not loop.state.ui.closing


def test_credits_lines_click_from_the_keyboard(loop, mocker) -> None:
    loop.navigation.navigate(Route.CREDITS)
    finish_transition(loop)
    credits = loop.state.screens.active
    assert isinstance(credits, CreditsView)
    tab_to(loop, mocker, lambda: credits._text_focus.focused)

    def reading_line():
        return credits._lines[credits._scroll_line_start_index + credits._reading_row()]

    for _ in range(600):
        line = reading_line()
        if "o" in line.text and not line.flags & 0x4:
            break
        loop.update(0.05)
    else:
        raise AssertionError("no round line reached the reading row")
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert line.flags & 0x4


def test_secret_board_plays_from_the_keyboard(loop, mocker) -> None:
    loop.navigation.navigate(Route.ALIEN_ZOOKEEPER)
    finish_transition(loop)
    board = loop.state.screens.active
    assert isinstance(board, AlienZooKeeperView)
    tab_to(loop, mocker, lambda: board._reset_button.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert board._timer_ms > 0

    tab_to(loop, mocker, lambda: board._board_focus.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_RIGHT)
    press(loop, mocker, rl.KeyboardKey.KEY_DOWN)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert board._selected_index == 1 * 6 + 1


def test_secret_board_escape_returns_to_the_statistics(loop, mocker) -> None:
    # `credits_secret_alien_zookeeper_update` backs out to the statistics menu, which the board replaced credits over.
    for route in (Route.STATISTICS, Route.CREDITS, Route.ALIEN_ZOOKEEPER):
        loop.navigation.navigate(route)
    finish_transition(loop)
    press(loop, mocker, rl.KeyboardKey.KEY_ESCAPE)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, StatisticsMenuView)


def test_perk_database_details_follow_the_keyboard(loop, mocker) -> None:
    loop.navigation.navigate(Route.PERKS)
    finish_transition(loop)
    database = loop.state.screens.active
    assert isinstance(database, UnlockedPerksDatabaseView)
    tab_to(loop, mocker, lambda: database.list_scroll.focused)
    # Native details only the row under the mouse; the keys move a row cursor the details follow.
    assert database._detail_perk_id() is None
    for _ in range(12):
        press(loop, mocker, rl.KeyboardKey.KEY_DOWN)
    assert database._detail_perk_id() == database._perk_ids[12]
    assert database.list_scroll.scroll_offset == 3


def test_named_score_list_added_and_deleted_by_keyboard(loop, mocker) -> None:
    config = loop.state.config
    config.gameplay.mode = GameMode.SURVIVAL
    record = HighScoreRecord.blank(rand_value=1)
    record.game_mode_id = GameMode.SURVIVAL
    record.set_name("ace")
    record.score_xp = 500
    write_highscore_records(scores_path_for_mode(loop.state.base_dir, GameMode.SURVIVAL, named_list="Bob"), [record])
    loop.navigation.navigate(ShowScores(ScoreQuery(GameMode.SURVIVAL)))
    finish_transition(loop)
    scores = loop.state.screens.active
    assert isinstance(scores, HighScoresView)
    assert scores._records == []
    widget = scores.score_list

    # Open the list and take its last entry, "<add new named list>".
    tab_to(loop, mocker, lambda: widget.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert widget.open
    while widget.active_index < len(widget.items) - 1:
        press(loop, mocker, rl.KeyboardKey.KEY_DOWN)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert scores._profile_add_mode

    typed = [ord(char) for char in "Bob"]
    mocker.patch.object(rl, "get_char_pressed", side_effect=lambda: typed.pop(0) if typed else 0)
    press(loop, mocker)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    # The new list is selected and reads its own score file.
    assert config.profile.named_score_list == "Bob"
    assert [entry.name() for entry in scores._records] == ["ace"]

    tab_to(loop, mocker, lambda: scores._profile_delete_button.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)
    assert config.profile.saved_name_labels() == ("default",)
    assert scores._records == []
