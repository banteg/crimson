from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.screens.actions import Route, ScoreQuery, ScoreReturnContext, ShowScores, StartRun
from crimson.screens.high_scores_layout import (
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_LEFT_PANEL_POS_Y,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_RIGHT_GAME_MODE_WIDGET,
    HS_RIGHT_PANEL_POS_Y,
    hs_left_panel_pos_x,
    hs_right_options_x_shift,
    hs_right_panel_pos_x,
)
from crimson.screens.high_scores_view import view as scores_module
from crimson.screens.high_scores_view.view import HighScoresView
from crimson.ui import perk_menu
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.screens import update_frame

LISTS = ("score_list", "date_filter_list", "player_count_list", "game_mode_list")


@pytest.mark.parametrize("name", LISTS)
def test_open_list_consumes_escape_before_back(scores_view, name, mocker) -> None:
    view = scores_view
    view.open()
    view.state.ui.timeline_ms = view.state.ui.max_timeline_ms
    getattr(view, name).open = True
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    update_frame(view, view.state)
    assert not getattr(view, name).open
    assert not view.state.ui.closing
    update_frame(view, view.state)
    assert view.state.ui.pending is Route.BACK


def test_open_list_keeps_focus_until_a_press_closes_it(scores_view, mocker) -> None:
    view = scores_view
    # A highlighted score's card covers the right panel; its lists only run without one.
    view._request.highlight_rank = None
    view.open()
    view.state.ui.timeline_ms = view.state.ui.max_timeline_ms
    mocker.patch.object(scores_module, "button_update", perk_menu.button_update)
    width = float(view.state.config.display.width)
    right_top_left = view._panel_top_left(pos=Vec2(hs_right_panel_pos_x(width), HS_RIGHT_PANEL_POS_Y))
    header = right_top_left + Vec2(hs_right_options_x_shift(width), 0.0) + HS_RIGHT_GAME_MODE_WIDGET
    left_top_left = view._panel_top_left(pos=Vec2(hs_left_panel_pos_x(width), HS_LEFT_PANEL_POS_Y))
    play = left_top_left + Vec2(HS_BUTTON_X, HS_BUTTON_Y0 + HS_BUTTON_STEP_Y)

    def frame(mouse: Vec2, *, click: bool) -> None:
        mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(mouse.x, mouse.y))
        mocker.patch.object(rl, "is_mouse_button_pressed", return_value=click)
        update_frame(view, view.state)

    frame(header + Vec2(5.0, 5.0), click=True)
    assert view.game_mode_list.open
    # Hovering the open list focuses it, so it stays open once the mouse leaves, as native.
    frame(header + Vec2(5.0, 5.0), click=False)
    frame(Vec2(-1000.0, -1000.0), click=False)
    assert view.game_mode_list.open
    # The next press closes it without taking a row (native takes the last hovered one), and reaches nothing else.
    mode = view.state.config.gameplay.mode
    frame(Vec2(-1000.0, -1000.0), click=True)
    assert not view.game_mode_list.open
    assert view.state.config.gameplay.mode == mode
    assert not view.state.ui.closing
    frame(play + Vec2(20.0, 10.0), click=True)
    assert isinstance(view.state.ui.pending, StartRun)


@pytest.fixture
def scores_view(make_game_state, screen_resources, screen_io, mocker) -> HighScoresView:
    mocker.patch.object(scores_module, "ensure_menu_ground", return_value=None)
    mocker.patch.object(scores_module, "button_update", return_value=False)
    state = make_game_state(resources=screen_resources)
    state.config.gameplay.mode = GameMode.QUESTS
    state.config.gameplay.quest_level = QuestLevel(1, 1)
    return HighScoresView(state, ShowScores(ScoreQuery(GameMode.QUESTS, QuestLevel(1, 1), highlight_rank=4)))


def click_button(view: HighScoresView, label: str, mocker) -> None:
    view.state.ui.timeline_ms = view.state.ui.max_timeline_ms
    mocker.patch.object(scores_module, "button_update", side_effect=lambda _resources, button, **_k: button.label == label)
    update_frame(view, view.state)


def test_refresh_keeps_query_and_saves_changed_preferences(scores_view, screen_resources, mocker) -> None:
    view = scores_view
    view.open()
    view.state.status.quest_unlock_index = 2
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(HS_QUEST_ARROW_X + 1, HS_QUEST_ARROW_Y + 1))
    # The arrow handler applies the same query/config mutation as an actual click.
    view._update_quest_arrows(left_panel_top_left=Vec2(), resources=screen_resources, click=True)
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(-1000, -1000))
    query = view._request
    click_button(view, "Update scores", mocker)
    assert view._request is query
    assert query.quest_level == QuestLevel(1, 2)
    assert query.highlight_rank == 4
    assert view._dirty
    save = mocker.patch.object(type(view.state.config), "save")
    view._begin_close_transition(Route.BACK)
    save.assert_called_once()


@pytest.mark.parametrize("from_run", [False, True])
def test_back_restores_run_context_only_when_returning_to_run(scores_view, from_run, mocker) -> None:
    view = scores_view
    state = view.state
    if from_run:
        view._return_context = ScoreReturnContext.capture(state.config)
    view.open()
    state.config.gameplay.mode = GameMode.RUSH
    state.config.gameplay.quest_level = QuestLevel(2, 3)
    state.config.gameplay.hardcore = True
    state.config.gameplay.player_count = 2
    view._dirty = True
    view._begin_close_transition(Route.BACK)
    assert state.config.gameplay.mode == (GameMode.QUESTS if from_run else GameMode.RUSH)
    assert state.config.gameplay.quest_level == (QuestLevel(1, 1) if from_run else QuestLevel(2, 3))
    assert state.config.gameplay.hardcore is (not from_run)
    assert state.config.gameplay.player_count == 2


@pytest.mark.parametrize("mode", [GameMode.SURVIVAL, GameMode.RUSH, GameMode.TYPO, GameMode.QUESTS])
def test_play_starts_selected_mode(scores_view, mode, mocker) -> None:
    view = scores_view
    view._request.game_mode_id = mode
    view.open()
    click_button(view, "Play a game", mocker)
    assert view.state.ui.pending == StartRun(mode, view._request.quest_level)
    assert view.state.screen_fade_ramp


@pytest.mark.parametrize("hardcore", [False, True])
def test_play_locked_quest_does_not_transition(scores_view, hardcore, mocker) -> None:
    view = scores_view
    view.state.config.gameplay.hardcore = hardcore
    view._request.quest_level = QuestLevel(5, 10)
    view.open()
    click_button(view, "Play a game", mocker)
    assert view.state.ui.pending is None
    assert not view.state.screen_fade_ramp
