from __future__ import annotations

import pytest

from crimson.game.types import HighScoresRequest
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.screens.high_scores_layout import HS_QUEST_ARROW_X, HS_QUEST_ARROW_Y
from crimson.screens.high_scores_view import view as scores_module
from crimson.screens.high_scores_view.view import HighScoresView
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.gameplay_screen import GameplayScreenStub


@pytest.fixture
def scores_view(make_game_state, screen_resources, screen_io, mocker) -> HighScoresView:
    mocker.patch.object(scores_module, "ensure_menu_ground", return_value=None)
    mocker.patch.object(scores_module, "button_width", return_value=100.0)
    mocker.patch.object(scores_module, "button_update", return_value=False)
    state = make_game_state(resources=screen_resources)
    state.config.gameplay.mode = GameMode.QUESTS
    state.config.gameplay.quest_level = QuestLevel(1, 1)
    state.pending_quest_level = QuestLevel(1, 1)
    state.pending_high_scores = HighScoresRequest(GameMode.QUESTS, QuestLevel(1, 1), highlight_rank=4)
    return HighScoresView(state)


def click_button(view: HighScoresView, label: str, mocker) -> None:
    view._timeline_ms = view._timeline_max_ms
    mocker.patch.object(scores_module, "button_update", side_effect=lambda button, **_k: button.label == label)
    view.update(0.016)


def test_refresh_keeps_query_and_saves_changed_preferences(scores_view, screen_resources, mocker) -> None:
    view = scores_view
    view.open()
    view.state.status.quest_unlock_index = 2
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(HS_QUEST_ARROW_X + 1, HS_QUEST_ARROW_Y + 1))
    # The arrow handler applies the same query/config mutation as an actual click.
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    assert view._update_quest_arrows(left_panel_top_left=Vec2(), scale=1.0, resources=screen_resources)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)
    mocker.patch.object(rl, "get_mouse_position", return_value=rl.Vector2(-1000, -1000))
    query = view._request
    click_button(view, "Update scores", mocker)
    assert view._request is query
    assert query.quest_level == QuestLevel(1, 2)
    assert query.highlight_rank == 4
    assert view._dirty
    save = mocker.patch.object(type(view.state.config), "save")
    view._begin_close_transition("back_to_previous")
    save.assert_called_once()


@pytest.mark.parametrize("from_run", [False, True])
def test_back_restores_run_context_only_when_returning_to_run(scores_view, from_run, mocker) -> None:
    view = scores_view
    state = view.state
    if from_run:
        state.pause_background = GameplayScreenStub()
    view.open()
    state.config.gameplay.mode = GameMode.RUSH
    state.config.gameplay.quest_level = QuestLevel(2, 3)
    state.config.gameplay.hardcore = True
    state.config.gameplay.player_count = 2
    view._dirty = True
    view._begin_close_transition("back_to_previous")
    assert state.config.gameplay.mode == (GameMode.QUESTS if from_run else GameMode.RUSH)
    assert state.config.gameplay.quest_level == (QuestLevel(1, 1) if from_run else QuestLevel(2, 3))
    assert state.config.gameplay.hardcore is (not from_run)
    assert state.config.gameplay.player_count == 2


@pytest.mark.parametrize(("mode", "expected"), [
    (GameMode.SURVIVAL, "start_survival"), (GameMode.RUSH, "start_rush"),
    (GameMode.TYPO, "start_typo"), (GameMode.QUESTS, "start_quest"),
])
def test_play_starts_selected_mode(scores_view, mode, expected, mocker) -> None:
    view = scores_view
    view.state.pending_high_scores.game_mode_id = mode
    view.open()
    click_button(view, "Play a game", mocker)
    assert view._close_action == expected
    assert view.state.screen_fade_ramp
    assert view.state.config.gameplay.mode == mode


@pytest.mark.parametrize("hardcore", [False, True])
def test_play_locked_quest_does_not_transition(scores_view, hardcore, mocker) -> None:
    view = scores_view
    view.state.config.gameplay.hardcore = hardcore
    view.state.pending_high_scores.quest_level = QuestLevel(5, 10)
    view.open()
    click_button(view, "Play a game", mocker)
    assert view._close_action is None
    assert not view.state.screen_fade_ramp
