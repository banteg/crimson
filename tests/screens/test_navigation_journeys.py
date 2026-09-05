from __future__ import annotations

import pytest

from crimson.game import loop_view as loop_module
from crimson.game import navigation as navigation_module
from crimson.game import resources as resources_module
from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestRunOutcome
from crimson.quests.level import QuestLevel
from crimson.screens import menu
from crimson.screens.actions import (
    ResultAction,
    Route,
    ScoreQuery,
    ScoreReturnContext,
    ShowQuestOutcome,
    ShowScores,
    StartRun,
)
from crimson.screens.high_scores_view import view as scores_module
from crimson.screens.panels import alien_zookeeper, credits, stats
from crimson.screens.panels.controls import ControlsMenuView
from crimson.screens.panels.options import OptionsMenuView
from crimson.screens.pause_menu import PauseMenuView
from crimson.screens.quest_views.quest_results import QuestResultsView
from crimson.screens.stack import ScreenEntry, ScreenStack
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.gameplay_screen import GameplayScreenStub
from tests.support.screens import ScreenStub


@pytest.fixture
def loop(make_game_state, screen_resources, screen_io, mocker) -> GameLoopView:
    state = make_game_state(resources=screen_resources)
    for module in (menu, navigation_module, scores_module, stats, credits, alien_zookeeper):
        mocker.patch.object(module, "ensure_menu_ground", return_value=None)
    mocker.patch.object(type(state.console), "handle_hotkey")
    mocker.patch.object(type(state.console), "update")
    mocker.patch.object(loop_module, "debug_enabled", return_value=False)
    view = GameLoopView(state)
    view.navigation.open()
    view.navigation.navigate(Route.MENU)
    return view


def finish_transition(loop: GameLoopView) -> None:
    for _ in range(12):
        loop.update(0.1)


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
    assert not options._transition.closing
    controls_close.assert_called_once()
    options._begin_close_transition(Route.BACK)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, menu.MenuView)
    assert loop.state.pause_background is None


def test_pause_options_controls_return_resumes_exact_run_once(loop) -> None:
    state = loop.state
    gameplay = GameplayScreenStub()
    state.screens.reset(ScreenEntry(gameplay, resume=gameplay.resume, gameplay=gameplay))
    gameplay._action = Route.PAUSE
    loop.update(0.016)
    pause = state.screens.active
    assert isinstance(pause, PauseMenuView)
    assert state.pause_background is gameplay
    loop.navigation.navigate(Route.OPTIONS)
    loop.navigation.navigate(Route.CONTROLS)
    for _ in range(3):
        loop.navigation.navigate(Route.BACK)
    assert state.screens.active is gameplay
    assert state.pause_background is None
    assert gameplay.open_calls == 1
    assert gameplay.close_calls == 0
    assert gameplay.resume_calls == 1
    state.screens.close()
    assert gameplay.close_calls == 1


def test_scores_back_restores_original_run_context_through_loop(loop, screen_resources, mocker) -> None:
    state = loop.state
    state.config.gameplay.mode = GameMode.SURVIVAL
    gameplay = GameplayScreenStub(
        action=ShowScores(
            ScoreQuery(GameMode.SURVIVAL),
            ScoreReturnContext.capture(state.config),
        ),
    )
    state.screens.reset(ScreenEntry(gameplay, resume=gameplay.resume, gameplay=gameplay))
    loop.update(0.016)
    scores = state.screens.active
    assert isinstance(scores, scores_module.HighScoresView)
    mocker.patch.object(
        scores,
        "_update_dropdown",
        side_effect=[
            (False, None, False),
            (False, None, False),
            (False, 1, True),
        ],
    )
    scores._update_right_panel_widgets(
        right_top_left=Vec2(),
        scale=1,
        resources=screen_resources,
        font=screen_resources.small_font,
    )
    assert state.config.gameplay.mode == GameMode.RUSH
    scores._begin_close_transition(Route.BACK)
    # The closing branch does not poll any dropdowns.
    for _ in range(4):
        loop.update(0.1)
    assert state.screens.active is gameplay
    assert state.config.gameplay.mode == GameMode.SURVIVAL
    assert gameplay.resume_calls == 1
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
    outcome = QuestRunOutcome(
        kind="completed",
        level=QuestLevel(1, 1),
        base_time_ms=60000,
        player_health=100,
        player2_health=None,
        pending_perk_count=0,
        experience=1234,
        kill_count=42,
        weapon_id=WeaponId.PISTOL,
        shots_fired=50,
        shots_hit=40,
        most_used_weapon_id=WeaponId.PISTOL,
        highscore_random_tag=123,
    )
    gameplay = GameplayScreenStub(action=ShowQuestOutcome(outcome))
    state.screens.reset(ScreenEntry(gameplay, resume=gameplay.resume, gameplay=gameplay))
    increment = mocker.spy(type(state.status), "increment_quest_play_count")
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
    assert state.pause_background is gameplay
    increment.assert_called_once()


def test_launch_payload_survives_later_config_changes(loop, mocker) -> None:
    state = loop.state
    request = StartRun(GameMode.RUSH, player_count=2, hardcore=False)
    state.config.gameplay.mode = GameMode.SURVIVAL
    state.config.gameplay.player_count = 1
    mode = loop.navigation._mode(GameMode.RUSH)
    mocker.patch.object(mode, "open")
    loop.navigation.navigate(request)
    assert state.config.gameplay.mode == GameMode.RUSH
    assert state.config.gameplay.player_count == 2
    assert state.screens.active is mode


def test_resources_outlive_boot_and_dispose_after_screens(make_game_state, screen_resources, mocker) -> None:
    state = make_game_state()
    view = GameLoopView(state)
    mocker.patch.object(rl, "hide_cursor")
    mocker.patch.object(rl, "show_cursor")
    mocker.patch.object(resources_module, "load_runtime_resources", return_value=screen_resources)
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
    assert state.resources is screen_resources
    unload.assert_not_called()
    view.close()
    assert disposal.mock_calls == [mocker.call.screen(), mocker.call.assets(screen_resources)]
    assert state.resources is None


def test_failed_screen_entry_is_disposed_at_shutdown(mocker) -> None:
    stack = ScreenStack()
    view = ScreenStub()
    mocker.patch.object(view, "open", side_effect=RuntimeError("load failed"))
    with pytest.raises(RuntimeError, match="load failed"):
        stack.push(ScreenEntry(view))
    stack.close()
    assert view.close_calls == 1
