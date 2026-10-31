from __future__ import annotations

import msgspec
import pytest

import crimson.screens.quest_views.quest_results as quest_results_module
from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestRunOutcome
from crimson.persistence.highscores import (
    TABLE_MAX,
    HighScoreRecord,
    ScoreTable,
    append_highscore_records,
    read_highscore_records,
    read_highscore_table,
    scores_path,
)
from crimson.quests.level import QuestLevel
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.actions import Route, StartRun
from crimson.screens.quest_views.quest_results import QuestResultsView
from crimson.ui.animation import ui_element_timeline_window
from crimson.weapons import WeaponId
from grim import canvas
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.audio import HeadlessAudio

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

# At 640x480 with the panel slid in: panel left = geom x0 -63 + pos x -45, top = geom y0 -81 + pos y 110.
PANEL_TOP_LEFT = Vec2(-108.0, 29.0)
# `quest_results_screen_update`: content x = panel left + 180 + 40.
CONTENT = PANEL_TOP_LEFT.offset(dx=220.0)
# The name input box sits 150 below the content anchor.
INPUT = CONTENT.offset(dy=150.0)


def _record() -> HighScoreRecord:
    record = HighScoreRecord()
    record.game_mode_id = GameMode.QUESTS
    record.run_elapsed_ms = 17_610
    record.score_xp = 1750
    record.creature_kill_count = 10
    record.shots_fired = 43
    record.shots_hit = 10
    record.most_used_weapon_id = WeaponId.SHOTGUN
    return record


def _open_view(
    make_game_state,
    headless_resources,
    mocker,
    *,
    phase: int,
    faded_in: bool = True,
    cl_build: ClBuild = ClBuild.V1_9_93,
) -> tuple[QuestResultsView, HeadlessAudio]:
    """Open the results for a first-place quest time, then jump to `phase` with the panel slid in."""
    audio = HeadlessAudio(mocker)
    state = make_game_state(
        resources=headless_resources,
        audio=audio.state,
        config_updates={"game_mode": GameMode.QUESTS, "player_name": "banteg"},
    )
    state.config.display.shadows_enabled = False
    mocker.patch.object(canvas, "mouse_position", return_value=rl.Vector2(0.0, 0.0))
    record = _record()
    record.cl_build = cl_build
    outcome = QuestRunOutcome(
        kind="completed",
        level=QuestLevel(1, 1),
        base_time_ms=17_610,
        player_health_values=(0.0,),
        pending_perk_count=0,
        record=record,
    )
    view = QuestResultsView(state, outcome)
    view.open()
    view._ground = None
    audio.backend.reset_mock()
    if phase == 1:
        view._enter_rank_phase(qualifies=True)
        view.name_entry.waiting_for_release = False
    view.phase = phase
    state.ui.timeline_ms = state.ui.max_timeline_ms
    if faded_in:
        view._anim_timer = 500
    view._consume_enter = False
    return view, audio


def _type_chars(mocker, pending: list[int]) -> None:
    mocker.patch.object(rl, "get_char_pressed", side_effect=lambda: pending.pop(0) if pending else 0)


def test_quest_results_name_entry_uses_native_offsets_and_colors(make_game_state, headless_resources, mocker) -> None:
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=1)
    draw_text = mocker.spy(quest_results_module, "draw_small_text")
    score_card = mocker.spy(quest_results_module, "ui_text_input_render")

    view.draw(mouse=rl.Vector2(0.0, 0.0))

    (prompt,) = [call.args for call in draw_text.call_args_list if call.args[1] == "State your name trooper!"]
    _font, _text, pos, color = prompt
    assert pos == Vec2(CONTENT.x + 42.0, PANEL_TOP_LEFT.y + 118.0)
    assert (color.r, color.g, color.b, color.a) == (149, 175, 198, 255)
    xy, record, _alpha, rank = score_card.call_args.args
    assert (xy, record, rank) == (INPUT + Vec2(26.0, 46.0), view.record, 1)
    assert score_card.call_args.kwargs["ui_phase"] == 1


def test_quest_results_fade_in_over_half_a_second(make_game_state, headless_resources, mocker) -> None:
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=2, faded_in=False)
    score_card = mocker.spy(quest_results_module, "ui_text_input_render")

    # `quest_results_anim_timer += frame_dt_ms`, alpha = timer * 0.002.
    for _ in range(15):
        view.update(1.0 / 60.0)
    view.draw(mouse=rl.Vector2(0.0, 0.0))
    assert score_card.call_args.args[2] == pytest.approx(15 * 16 * 0.002)
    assert view._play_next_button.alpha == pytest.approx(15 * 16 * 0.002)

    for _ in range(30):
        view.update(1.0 / 60.0)
    view.draw(mouse=rl.Vector2(0.0, 0.0))
    assert score_card.call_args.args[2] == 1.0


def test_quest_results_world_entity_alpha_tracks_close_timeline(make_game_state, headless_resources, mocker) -> None:
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=2)
    assert view.world_entity_alpha() == 1.0

    # The UI timeline stops at 400 ms, so closing starts from 400 / 500.
    view._begin_close_transition(Route.MENU)
    assert view.world_entity_alpha() == 0.8

    view.state.ui.timeline_ms = int(ui_element_timeline_window(28)[1] * 0.5)
    assert view.world_entity_alpha() == 0.5

    view.state.ui.timeline_ms = 0
    assert view.world_entity_alpha() == 0.0


@pytest.mark.parametrize("level", [QuestLevel(1, 1), QuestLevel(1, 2)])
def test_quest_results_next_run_keeps_the_world_lit(
    make_game_state, headless_resources, mocker, level: QuestLevel,
) -> None:
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=2)

    view._begin_close_transition(StartRun(GameMode.QUESTS, level))
    view.state.ui.timeline_ms = 0
    assert view.world_entity_alpha() == 1.0


@pytest.mark.parametrize(("phase", "leaves"), [(0, False), (1, False), (2, True)])
def test_escape_is_main_menu_once_the_buttons_show(
    make_game_state, headless_resources, mocker, phase: int, leaves: bool,
) -> None:
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=phase)
    # Escape, or the pad's B: the reveal and the name entry keep it, so a stray press does not leave unsaved.
    view.state.focus.escape = True
    view.update(0.016)
    assert view.state.ui.closing == leaves


def test_quest_results_name_entry_waits_for_controls_release(make_game_state, headless_resources, mocker) -> None:
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=1)
    view.name_entry.waiting_for_release = True
    _type_chars(mocker, [ord("w"), ord("w")])
    # Player one still holds fire (mouse left) from the finishing kill.
    fire_held = mocker.patch.object(rl, "is_mouse_button_down", return_value=True)

    view.update(0.0)
    assert view.name_entry.text == "banteg"
    assert view.name_entry.waiting_for_release is True

    fire_held.return_value = False
    view.update(0.0)
    # Keys typed while fire was held were flushed, not typed.
    assert view.name_entry.text == "banteg"
    assert view.name_entry.waiting_for_release is False


def test_quest_results_name_entry_uses_shared_ui_text_input_typeclick_caller(
    make_game_state, headless_resources, mocker,
) -> None:
    view, audio = _open_view(make_game_state, headless_resources, mocker, phase=1)
    _type_chars(mocker, [ord("w"), ord("w")])
    rand_tagged = mocker.patch.object(view.state.rng, "rand_tagged", return_value=0)

    view.update(0.0)

    assert view.name_entry.text == "bantegww"
    assert audio.played() == [SfxId.UI_TYPECLICK_01]
    rand_tagged.assert_called_once_with(RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK)


def test_score_write_failure_stays_on_name_entry_and_can_retry(make_game_state, headless_resources, mocker) -> None:
    view, audio = _open_view(make_game_state, headless_resources, mocker, phase=1)
    path = scores_path(view.state.base_dir)
    # A directory where the score file belongs makes the write fail like a full disk would.
    path.mkdir(parents=True)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)

    # The game loop starts each frame's focus, sampling Enter.
    view.state.focus.begin_frame(0)
    view.update(0.05)
    assert view.phase == 1
    assert not view.name_entry.saved
    assert view.name_entry.save_error is not None

    path.rmdir()
    view.state.focus.begin_frame(0)
    view.update(0.05)
    assert view.phase == 2
    assert view.name_entry.saved
    assert view.name_entry.save_error is None
    assert [record.name for record in read_highscore_records(view.state.base_dir)] == ["banteg"]
    assert audio.played() == [SfxId.UI_TYPEENTER, SfxId.UI_TYPEENTER]


def test_a_1_9_8_quest_clear_ranks_and_saves_in_the_1_9_8_table(make_game_state, headless_resources, mocker, tmp_path) -> None:
    # A full 1.9.93 table of faster clears leaves the 1.9.8 run's own table empty, so its time qualifies.
    faster = HighScoreRecord(game_mode_id=GameMode.QUESTS, quest_level=QuestLevel(1, 1), run_elapsed_ms=1000)
    append_highscore_records(tmp_path, [faster] * TABLE_MAX)
    view, _audio = _open_view(make_game_state, headless_resources, mocker, phase=1, cl_build=ClBuild.V1_9_8)
    assert view.rank == 0
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)

    view.state.focus.begin_frame(0)
    view.update(0.05)

    assert view.name_entry.saved
    table = ScoreTable(GameMode.QUESTS, quest_level=QuestLevel(1, 1))
    assert [record.name for record in read_highscore_table(tmp_path, table)] == [""] * TABLE_MAX
    saved = read_highscore_table(tmp_path, msgspec.structs.replace(table, cl_build=ClBuild.V1_9_8))
    assert [record.name for record in saved] == ["banteg"]
