from __future__ import annotations

from collections.abc import Callable
from typing import NamedTuple

import pytest

import crimson.screens.quest_views.quest_failed as quest_failed_module
from crimson.game.types import GameState
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.modes.quest_mode import QuestMode
from crimson.quests.level import QuestLevel
from crimson.screens.actions import Route, ScreenAction, ShowQuestOutcome, StartRun
from crimson.screens.quest_views import QUEST_FAILED_PANEL_W, QuestFailedView
from crimson.screens.quest_views.shared import QUEST_FAILED_MESSAGE_X_OFFSET, QUEST_FAILED_MESSAGE_Y_OFFSET
from crimson.sim.run_result import RunOutcome
from crimson.ui.animation import ui_element_timeline_window
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

LEVEL = QuestLevel(1, 1)
# At 640x480: panel left = geom x0 -63 + pos x -45, top = geom y0 -81 + pos y 110.
PANEL_TOP_LEFT = Vec2(-108.0, 29.0)


class _FailedQuest(NamedTuple):
    state: GameState
    run: QuestMode
    view: QuestFailedView
    sfx: Callable[[], list[SfxId]]


@pytest.fixture
def failed(make_game_state, headless_resources, mocker) -> _FailedQuest:
    """A quest run that just failed, retained under its quest-failed screen as the game navigates it."""
    audio = HeadlessAudio(mocker)
    state = make_game_state(resources=headless_resources, audio=audio.state)
    navigator, run = start_run(state, StartRun.from_config(state.config, GameMode.QUESTS, quest_level=LEVEL))
    assert isinstance(run, QuestMode)
    run._finish_run(RunOutcome.DEATH)
    outcome = run.consume_outcome()
    assert outcome is not None
    navigator.navigate(ShowQuestOutcome(outcome))
    view = state.screens.active
    assert isinstance(view, QuestFailedView)
    return _FailedQuest(state, run, view, audio.played)


def _press(mocker, key: int) -> None:
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda pressed: pressed == key)


def _finish_close(view: QuestFailedView, mocker) -> ScreenAction | None:
    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    action = None
    for _ in range(120):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    return action


def test_quest_failed_preserves_start_random_tag(failed: _FailedQuest) -> None:
    assert failed.view._record is not None
    assert failed.view._record.uni_num == failed.run._quest_highscore_random_tag


def test_quest_failed_panel_layout_uses_native_anchor(failed: _FailedQuest, mocker) -> None:
    assert failed.view._panel_origin() == PANEL_TOP_LEFT

    # The widescreen shift moves the panel down at 1024 wide.
    mocker.patch.object(rl, "get_screen_width", return_value=1024)
    assert failed.view._panel_origin() == PANEL_TOP_LEFT.offset(dy=90.0)


def test_quest_failed_panel_slides_in_from_left(failed: _FailedQuest) -> None:
    view = failed.view
    base = view._panel_origin()

    view.state.ui.timeline_ms = 0
    assert view._panel_top_left().x == base.x - QUEST_FAILED_PANEL_W

    view.state.ui.timeline_ms = 250
    assert view._panel_top_left().x == base.x - QUEST_FAILED_PANEL_W * 0.5

    view.state.ui.timeline_ms = 400
    assert view._panel_top_left().x == base.x


def test_quest_failed_enter_retries_current_quest(failed: _FailedQuest, mocker) -> None:
    state = failed.state
    state.quest_fail_retry_count = 2
    state.config.gameplay.quest_level = None
    _press(mocker, rl.KeyboardKey.KEY_ENTER)

    failed.view.update(0.016)

    assert state.quest_fail_retry_count == 3
    assert state.config.gameplay.quest_level == LEVEL
    assert failed.sfx() == [SfxId.UI_BUTTONCLICK]
    assert failed.view.take_action() is None
    assert _finish_close(failed.view, mocker) == StartRun.from_config(state.config, GameMode.QUESTS, quest_level=LEVEL)


def test_quest_failed_q_opens_quest_list(failed: _FailedQuest, mocker) -> None:
    failed.state.quest_fail_retry_count = 4
    _press(mocker, rl.KeyboardKey.KEY_Q)

    failed.view.update(0.016)

    assert failed.state.quest_fail_retry_count == 0
    assert failed.sfx() == [SfxId.UI_BUTTONCLICK]
    assert failed.view.take_action() is None
    assert _finish_close(failed.view, mocker) == Route.QUESTS


def test_quest_failed_main_menu_waits_for_exit_transition(failed: _FailedQuest, mocker) -> None:
    failed.state.quest_fail_retry_count = 4
    play_music = mocker.spy(quest_failed_module, "play_music")
    _press(mocker, rl.KeyboardKey.KEY_ESCAPE)

    failed.view.update(0.016)

    assert failed.state.quest_fail_retry_count == 0
    assert failed.sfx() == [SfxId.UI_BUTTONCLICK]
    assert failed.view.take_action() is None
    assert _finish_close(failed.view, mocker) == Route.MENU
    # The screen asks for its tune only while it is not closing.
    play_music.assert_called_once_with(failed.state.audio, "shortie_monk")


def test_quest_failed_panel_open_clicks_once(failed: _FailedQuest) -> None:
    for _ in range(8):
        failed.view.update(0.1)

    assert failed.state.ui.opened
    assert failed.sfx() == [SfxId.UI_PANELCLICK]


def test_quest_failed_card_sits_at_the_native_input_xy(failed: _FailedQuest, mocker) -> None:
    for _ in range(8):
        failed.view.update(0.1)
    mocker.patch.object(failed.run, "_draw_world")
    score_card = mocker.spy(quest_failed_module, "ui_text_input_render")

    failed.view.draw()

    # `quest_failed_screen_update`: message xy + (6, 16), then + (4, 10).
    message = PANEL_TOP_LEFT + Vec2(QUEST_FAILED_MESSAGE_X_OFFSET, QUEST_FAILED_MESSAGE_Y_OFFSET)
    assert score_card.call_args.args[0] == message + Vec2(10.0, 26.0)
    assert score_card.call_args.args[1] is failed.view._record
    assert score_card.call_args.kwargs["game_state"] == GameStateId.QUEST_FAILED


def test_quest_failed_draw_fades_the_retained_run_during_close(failed: _FailedQuest, mocker) -> None:
    draw_world = mocker.patch.object(failed.run, "_draw_world")
    background = mocker.spy(failed.run, "draw_pause_background")
    failed.state.ui.closing = True
    failed.state.ui.timeline_ms = int(ui_element_timeline_window(28)[1] * 0.5)

    failed.view.draw()

    background.assert_called_once_with(entity_alpha=0.5)
    draw_world.assert_called_once()
