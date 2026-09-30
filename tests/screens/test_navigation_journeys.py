from __future__ import annotations

from typing import NamedTuple
from unittest.mock import MagicMock

import pytest

from crimson.game import resources as resources_module
from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.quests.level import QuestLevel
from crimson.screens import menu
from crimson.screens.actions import (
    ResultAction,
    Route,
    StartRun,
)
from crimson.screens.high_scores_layout import HS_RIGHT_GAME_MODE_WIDGET, hs_right_options_x_shift
from crimson.screens.high_scores_view import view as scores_module
from crimson.screens.panels import alien_zookeeper, stats
from crimson.screens.panels.controls import ControlsMenuView
from crimson.screens.panels.options import OptionsMenuView
from crimson.screens.pause_menu import PauseMenuView
from crimson.screens.quest_views.quest_results import QuestResultsView
from crimson.screens.stack import ScreenEntry, ScreenStack
from crimson.sim.run_result import RunOutcome
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.screens import ScreenStub, finish_transition


def test_menu_options_controls_back_preserves_parent_and_config(loop, mocker) -> None:
    navigation = loop.navigation
    navigation.navigate(Route.OPTIONS)
    options = loop.state.screens.active
    assert isinstance(options, OptionsMenuView)
    options._slider_sfx.value = 3
    options._begin_close_transition(Route.CONTROLS)
    finish_transition(loop)
    controls = loop.state.screens.active
    assert isinstance(controls, ControlsMenuView)
    controls_close = mocker.spy(controls, "close")
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    loop.update(0.016)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    finish_transition(loop)
    assert loop.state.screens.active is options
    assert options._slider_sfx.value == 3
    assert not options.state.ui.closing
    controls_close.assert_called_once()
    options._begin_close_transition(Route.BACK)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, menu.MenuView)
    assert loop.state.pause_background is None


class _RunSpies(NamedTuple):
    open: MagicMock
    close: MagicMock
    resume: MagicMock


def _start_run(loop: GameLoopView, mocker, request: StartRun) -> tuple[BaseGameplayMode, _RunSpies]:
    """Start `request` from the loop's main menu, spying the run's lifecycle calls before the stack binds them."""
    run = loop.navigation._mode(request.mode)
    spies = _RunSpies(*(mocker.spy(run, name) for name in _RunSpies._fields))
    loop.navigation.navigate(request)
    assert loop.state.screens.gameplay is run
    return run, spies


def _update_until(loop: GameLoopView, screen_type: type, *, dt: float = 0.1) -> None:
    for _ in range(30):
        if isinstance(loop.state.screens.active, screen_type):
            return
        loop.update(dt)
    raise AssertionError(f"the loop never reached {screen_type.__name__}")


def test_pause_options_controls_return_resumes_exact_run_once(loop, mocker) -> None:
    state = loop.state
    run, spies = _start_run(loop, mocker, StartRun(GameMode.SURVIVAL))
    # Escape runs the HUD out, then the run asks the loop for the pause menu.
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    loop.update(0.016)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    _update_until(loop, PauseMenuView)
    assert state.pause_background is run
    loop.navigation.navigate(Route.OPTIONS)
    loop.navigation.navigate(Route.CONTROLS)
    for _ in range(3):
        loop.navigation.navigate(Route.BACK)
    assert state.screens.active is run
    assert state.pause_background is None
    spies.open.assert_called_once_with()
    spies.close.assert_not_called()
    spies.resume.assert_called_once_with()
    state.screens.close()
    spies.close.assert_called_once_with()


def test_scores_back_restores_original_run_context_through_loop(loop, headless_resources, mocker) -> None:
    state = loop.state
    state.config.gameplay.mode = GameMode.SURVIVAL
    run, spies = _start_run(loop, mocker, StartRun(GameMode.SURVIVAL))
    # The game over's High scores button closes its panel, then the run asks the loop for the scores.
    run._enter_game_over()
    run._game_over_ui._begin_close_transition(ResultAction.HIGH_SCORES)
    _update_until(loop, scores_module.HighScoresView)
    scores = state.screens.active
    assert isinstance(scores, scores_module.HighScoresView)
    # Take "Rush", the second row of the open game mode list.
    scores.game_mode_list.open = True
    row = Vec2(hs_right_options_x_shift(float(state.config.display.width)), 0.0) + HS_RIGHT_GAME_MODE_WIDGET
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(row.x + 5.0, row.y + 16.0 * 2 + 5.0))
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    scores._update_right_panel_widgets(
        right_top_left=Vec2(),
        resources=headless_resources,
    )
    assert state.config.gameplay.mode == GameMode.RUSH
    assert not scores.game_mode_list.open
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)
    scores._begin_close_transition(Route.BACK)
    # The closing branch does not poll any dropdowns.
    for _ in range(4):
        loop.update(0.1)
    assert state.screens.active is run
    assert state.config.gameplay.mode == GameMode.SURVIVAL
    spies.resume.assert_called_once_with()
    assert state.pause_background is None


def test_secret_puzzle_retains_process_lifetime_state_across_visits(loop) -> None:
    navigation = loop.navigation
    navigation.navigate(Route.STATISTICS)
    for index in range(2):
        navigation.navigate(Route.CREDITS)
        navigation.navigate(Route.ALIEN_ZOOKEEPER)
        puzzle = loop.state.screens.active
        assert isinstance(puzzle, alien_zookeeper.AlienZooKeeperView)
        if index == 0:
            puzzle._score = 123
            puzzle._board[4] = 3
        else:
            assert puzzle._score == 123
            assert puzzle._board[4] == 3
        navigation.navigate(Route.BACK)
        assert isinstance(loop.state.screens.active, stats.StatisticsMenuView)


def test_stack_closes_replaced_and_retained_screens_once() -> None:
    stack = ScreenStack()
    parent, child, replacement, root = (ScreenStub() for _ in range(4))
    stack.push(ScreenEntry(parent, resume=parent.resume))
    stack.push(ScreenEntry(child))
    stack.replace(ScreenEntry(replacement))
    assert child.close_calls == 1
    assert stack.back()
    assert replacement.close_calls == 1
    assert parent.resume_calls == 1
    stack.reset(ScreenEntry(root))
    assert parent.close_calls == 1
    stack.close()
    stack.close()
    assert root.close_calls == 1


def test_results_scores_back_preserves_result_and_applies_completion_once(loop, mocker) -> None:
    state = loop.state
    state.config.gameplay.mode = GameMode.QUESTS
    state.config.gameplay.quest_level = QuestLevel(1, 1)
    run, _spies = _start_run(loop, mocker, StartRun(GameMode.QUESTS, QuestLevel(1, 1)))
    increment = mocker.spy(type(state.status), "increment_quest_play_count")
    run._finish_run(RunOutcome.QUEST_COMPLETED)
    loop.update(0.016)
    results = state.screens.active
    assert isinstance(results, QuestResultsView)
    result_ui = results._ui
    assert result_ui is not None
    update_ui = mocker.patch.object(type(result_ui), "update", return_value=ResultAction.HIGH_SCORES)
    loop.update(0.016)
    update_ui.return_value = None
    scores = state.screens.active
    assert isinstance(scores, scores_module.HighScoresView)
    scores._request.quest_level = QuestLevel(1, 2)
    state.config.gameplay.quest_level = QuestLevel(1, 2)
    scores._begin_close_transition(Route.BACK)
    for _ in range(4):
        loop.update(0.1)
    assert state.screens.active is results
    assert results._ui is result_ui
    assert state.config.gameplay.quest_level == QuestLevel(1, 1)
    assert state.pause_background is run
    increment.assert_called_once()


def test_launch_payload_mode_survives_later_config_changes(loop, mocker) -> None:
    state = loop.state
    request = StartRun(GameMode.RUSH)
    state.config.gameplay.mode = GameMode.SURVIVAL
    mode = loop.navigation._mode(GameMode.RUSH)
    mocker.patch.object(mode, "open")
    loop.navigation.navigate(request)
    assert state.config.gameplay.mode == GameMode.RUSH
    assert state.screens.active is mode


def test_resources_outlive_boot_and_dispose_after_screens(make_game_state, headless_resources, mocker) -> None:
    state = make_game_state()
    view = GameLoopView(state)
    mocker.patch.object(rl, "hide_cursor")
    mocker.patch.object(rl, "show_cursor")
    mocker.patch.object(resources_module, "load_runtime_resources", return_value=headless_resources)
    mocker.patch.object(resources_module, "init_audio_state", return_value=None)
    mocker.patch.object(type(state.console), "exec_line")
    disposal = mocker.Mock()
    unload = mocker.patch.object(resources_module, "unload_runtime_resources")
    disposal.attach_mock(unload, "assets")
    view.open()
    boot_close = mocker.spy(state.screens.active, "close")
    panel = ScreenStub()
    disposal.attach_mock(mocker.patch.object(panel, "close"), "screen")
    state.screens.replace(ScreenEntry(panel))
    boot_close.assert_called_once()
    assert state.resources is headless_resources
    unload.assert_not_called()
    view.close()
    assert disposal.mock_calls == [mocker.call.screen(), mocker.call.assets(headless_resources)]
    assert state.resources is None


def test_failed_screen_entry_is_disposed_at_shutdown(mocker) -> None:
    stack = ScreenStack()
    view = ScreenStub()
    mocker.patch.object(view, "open", side_effect=RuntimeError("load failed"))
    with pytest.raises(RuntimeError, match="load failed"):
        stack.push(ScreenEntry(view))
    stack.close()
    assert view.close_calls == 1




def test_alt_q_quits_from_any_screen(loop, mocker) -> None:
    held = {int(rl.KeyboardKey.KEY_Q), int(rl.KeyboardKey.KEY_LEFT_ALT)}
    mocker.patch.object(rl, "is_key_down", side_effect=lambda key: int(key) in held)
    loop.update(0.016)
    assert loop.should_close()
