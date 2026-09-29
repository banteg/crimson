from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.quests.level import QuestLevel
from crimson.screens.actions import Route, ShowQuestOutcome, StartRun
from crimson.screens.quest_views import EndNoteView, QuestResultsView
from crimson.sim.run_result import RunOutcome
from crimson.ui.animation import ui_element_timeline_window
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run, update_frame

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

FINAL_QUEST = QuestLevel(5, 10)


@pytest.fixture
def end_note(make_game_state, headless_resources, mocker):
    """The end note reached from the final quest's results, the finished run retained underneath."""
    audio = HeadlessAudio(mocker)
    state = make_game_state(resources=headless_resources, audio=audio.state)
    state.status.quest_unlock_index = FINAL_QUEST.global_index
    navigator, run = start_run(state, StartRun(GameMode.QUESTS, FINAL_QUEST))
    assert isinstance(run, QuestMode)
    run._finish_run(RunOutcome.QUEST_COMPLETED)
    outcome = run.consume_outcome()
    assert outcome is not None
    navigator.navigate(ShowQuestOutcome(outcome))
    assert isinstance(state.screens.active, QuestResultsView)
    audio.backend.reset_mock()
    navigator.navigate(Route.END_NOTE)
    view = state.screens.active
    assert isinstance(view, EndNoteView)
    return view, run, audio


def test_end_note_escape_waits_for_close_transition(end_note, mocker) -> None:
    view, _run, audio = end_note
    for _ in range(4):
        view.update(0.1)

    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    update_frame(view, view.state, 0.1)

    assert audio.played() == [SfxId.UI_PANELCLICK, SfxId.UI_BUTTONCLICK]
    assert view.take_action() is None

    mocker.patch.object(rl, "is_key_pressed", return_value=False)
    action = None
    for _ in range(30):
        view.update(1.0 / 60.0)
        action = view.take_action()
        if action is not None:
            break
    assert action == Route.MENU


def test_end_note_draw_fades_the_retained_run_during_close(end_note, mocker) -> None:
    view, run, _audio = end_note
    mocker.patch.object(run, "_draw_world")
    background = mocker.spy(run, "draw_pause_background")
    view.state.ui.closing = True
    view.state.ui.timeline_ms = ui_element_timeline_window(28)[1] // 2

    view.draw()

    background.assert_called_once_with(entity_alpha=0.5)
