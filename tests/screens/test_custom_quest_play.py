from __future__ import annotations

from importlib.resources import files

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode, quest_mode
from crimson.modes.quest_mode import QuestMode
from crimson.quests.custom import CustomQuest
from crimson.quests.dsl import build_custom_quest
from crimson.screens.actions import Route, ScreenAction, ShowQuestOutcome, StartRun
from crimson.screens.boot import BootView
from crimson.screens.quest_views import QuestFailedView
from crimson.screens.quest_views.shared import (
    QUEST_FAILED_BANNER_H,
    QUEST_FAILED_BANNER_W,
    QUEST_FAILED_BANNER_X_OFFSET,
    QUEST_FAILED_BANNER_Y_OFFSET,
)
from crimson.sim.run_result import RunOutcome
from crimson.ui.overlays.quest_title import layout_quest_title_overlay
from grim.assets import TextureId
from grim.geom import Rect, Vec2
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


def test_the_clear_banner_fits_the_banner_slot(make_game_state, headless_resources, mocker, quest):
    state, view = _ended(make_game_state, headless_resources, mocker, quest, RunOutcome.QUEST_COMPLETED)
    update_frame(view, state)
    draw = mocker.patch.object(rl, "draw_texture_pro")
    view.draw()
    slot = Rect.from_top_left(
        view._panel_rect().top_left + Vec2(QUEST_FAILED_BANNER_X_OFFSET, QUEST_FAILED_BANNER_Y_OFFSET),
        QUEST_FAILED_BANNER_W,
        QUEST_FAILED_BANNER_H,
    )
    texture = headless_resources.texture(TextureId.UI_TEXT_LEVEL_COMPLETE)
    [banner] = [call.args[2] for call in draw.call_args_list if call.args[0] is texture]
    assert slot.left <= banner.x and banner.x + banner.width <= slot.left + slot.width
    assert slot.top <= banner.y and banner.y + banner.height <= slot.top + slot.height


def test_the_ranked_box_leaves_a_custom_co_op_run_alone(make_game_state, headless_resources, mocker, quest):
    state = make_game_state(resources=headless_resources, audio=HeadlessAudio(mocker).state)
    state.ranked = True
    state.config.gameplay.player_count = 2
    # An unranked run carries the session's seed on rather than a ranked draw.
    ranked_seed = 0xDEADBEEF
    mocker.patch.object(base_gameplay_mode, "ranked_run_seed", return_value=ranked_seed)
    _navigator, run = start_run(state, StartRun(GameMode.QUESTS, custom_quest=quest))
    recorder = run._replay_recorder
    assert recorder is not None
    assert (recorder.run.player_count, len(run.world.players), run.ranked_run) == (2, 2, False)
    assert recorder.run.seed != ranked_seed


def test_a_custom_quest_title_carries_its_authors_byline(make_game_state, headless_resources, mocker, quest):
    quest = msgspec.structs.replace(quest, author="banteg")
    state = make_game_state(resources=headless_resources, audio=HeadlessAudio(mocker).state)
    _navigator, run = start_run(state, StartRun(GameMode.QUESTS, custom_quest=quest))
    assert isinstance(run, QuestMode)
    draw = mocker.patch.object(quest_mode, "draw_quest_title_timer_overlay")
    run._grim_mono = mocker.sentinel.font
    run._draw_quest_title()
    assert draw.call_args.args[1:3] == (quest.title, "")
    assert draw.call_args.kwargs["subtitle"] == "by banteg"


def test_the_byline_centres_a_line_under_the_title():
    layout = layout_quest_title_overlay(
        screen_width=800,
        screen_height=600,
        title="Crosswind",
        number="",
        font_advance=16.0,
        subtitle="by banteg",
    )
    width = len("by banteg") * 16.0 * layout.number_scale
    assert layout.subtitle_pos.x + width / 2.0 == 400.0
    assert layout.subtitle_pos.y > layout.title_pos.y
