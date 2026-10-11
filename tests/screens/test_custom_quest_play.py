from __future__ import annotations

from importlib.resources import files

import pytest

from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.quests.custom import CustomQuest
from crimson.quests.dsl import build_custom_quest
from crimson.screens.actions import Route, ScreenAction, ShowQuestOutcome, StartRun
from crimson.screens.boot import BootView
from crimson.screens.quest_views import QuestFailedView
from crimson.sim.run_result import RunOutcome
from grim.raylib_api import rl
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run, update_frame

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")


@pytest.fixture
def quest() -> CustomQuest:
    return build_custom_quest(files("crimson.quests.dsl").joinpath("examples", "crosswind.quest").read_text())


def _ended(make_game_state, headless_resources, mocker, quest: CustomQuest, outcome: RunOutcome):
    state = make_game_state(resources=headless_resources, audio=HeadlessAudio(mocker).state)
    state.ranked = True
    navigator, run = start_run(state, StartRun(GameMode.QUESTS, custom_quest=quest))
    assert isinstance(run, QuestMode)
    # The Ranked box is on, but a custom quest records an unranked run of itself.
    recorder = run._replay_recorder
    assert recorder is not None
    assert (recorder.run.custom_quest, recorder.run.quest_level, run.ranked_run) == (quest, None, False)
    run._finish_run(outcome)
    ended = run.consume_outcome()
    assert ended is not None
    assert (ended.level, ended.custom_quest) == (None, quest)
    navigator.navigate(ShowQuestOutcome(ended))
    view = state.screens.active
    assert isinstance(view, QuestFailedView)
    return state, view


def _settle(view: QuestFailedView, mocker) -> ScreenAction | None:
    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    for _ in range(120):
        view.update(1.0 / 60.0)
        if (action := view.take_action()) is not None:
            return action
    return None


def test_boot_starts_the_custom_quest_instead_of_the_menu(make_game_state, headless_resources, quest):
    state = make_game_state(resources=headless_resources)
    state.custom_quest = quest
    boot = BootView(state)
    boot._theme_started = True
    assert boot.take_action() == StartRun(GameMode.QUESTS, custom_quest=quest)


@pytest.mark.parametrize(("outcome", "retries"), [(RunOutcome.QUEST_COMPLETED, 0), (RunOutcome.DEATH, 1)])
def test_a_custom_quest_ends_with_play_again_and_no_quest_list(
    make_game_state,
    headless_resources,
    mocker,
    quest,
    outcome,
    retries,
):
    state, view = _ended(make_game_state, headless_resources, mocker, quest, outcome)
    assert view._quest_title == quest.title
    assert [button for button, _ in view._buttons()] == [view._retry_button, view._main_menu_button]

    update_frame(view, state)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_Q)
    update_frame(view, state)
    assert view.take_action() is None

    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)
    update_frame(view, state)
    assert state.quest_fail_retry_count == retries
    assert _settle(view, mocker) == StartRun(GameMode.QUESTS, custom_quest=quest)


def test_escape_leaves_a_custom_quest_for_the_menu(make_game_state, headless_resources, mocker, quest):
    state, view = _ended(make_game_state, headless_resources, mocker, quest, RunOutcome.DEATH)
    update_frame(view, state)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    update_frame(view, state)
    assert _settle(view, mocker) == Route.MENU
