from __future__ import annotations

from pathlib import Path

import pytest

import crimson.screens.results.quest_results as quest_results_module
from crimson.game_modes import GameMode
from crimson.persistence.highscores import HighScoreRecord, read_highscore_records
from crimson.quests.level import QuestLevel
from crimson.quests.results import QuestFinalTime
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.actions import ResultAction
from crimson.screens.results.quest_results import QuestResultsUi
from crimson.ui.animation import ui_element_timeline_window
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

# At 640x480 with the panel slid in: panel left = geom x0 -63 + pos x -45, top = geom y0 -81 + pos y 110.
PANEL_TOP_LEFT = Vec2(-108.0, 29.0)
# `quest_results_screen_update`: content x = panel left + 180 + 40.
CONTENT = PANEL_TOP_LEFT.offset(dx=220.0)
# The name input box sits 150 below the content anchor.
INPUT = CONTENT.offset(dy=150.0)


def _record() -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.QUESTS
    record.run_elapsed_ms = 17_610
    record.score_xp = 1750
    record.creature_kill_count = 10
    record.shots_fired = 43
    record.shots_hit = 10
    record.most_used_weapon_id = WeaponId.SHOTGUN
    return record


def _open_ui(
    tmp_path: Path, assets_dir: Path, make_mode_config, *, phase: int, faded_in: bool = True,
) -> QuestResultsUi:
    """Open the results for a first-place quest time, then jump to `phase` with the panel slid in."""
    config = make_mode_config(game_mode=GameMode.QUESTS)
    config.display.shadows_enabled = False
    ui = QuestResultsUi(assets_root=assets_dir, base_dir=tmp_path, config=config)
    ui.open(
        record=_record(),
        breakdown=QuestFinalTime(base_time_ms=17_610, life_bonus_ms=0, unpicked_perk_bonus_ms=0, final_time_ms=17_610),
        quest_level=QuestLevel(1, 1),
        quest_title="Land Hostile",
        unlock_weapon_name="",
        unlock_perk_name="",
        player_name_default="banteg",
    )
    if phase == 1:
        ui._enter_rank_phase(qualifies=True)
        ui.name_entry.waiting_for_release = False
    ui.phase = phase
    ui.timeline.timeline_ms = ui.timeline.max_timeline_ms
    if faded_in:
        ui._anim_timer = 500
    ui._panel_open_sfx_played = True
    ui._consume_enter = False
    return ui


def _type_chars(mocker, pending: list[int]) -> None:
    mocker.patch.object(rl, "get_char_pressed", side_effect=lambda: pending.pop(0) if pending else 0)


def test_quest_results_name_entry_uses_native_offsets_and_colors(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    draw_text = mocker.spy(quest_results_module, "draw_small_text")
    score_card = mocker.spy(quest_results_module, "ui_text_input_render")

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    (prompt,) = [call.args for call in draw_text.call_args_list if call.args[1] == "State your name trooper!"]
    _font, _text, pos, color = prompt
    assert pos == Vec2(CONTENT.x + 42.0, PANEL_TOP_LEFT.y + 118.0)
    assert (color.r, color.g, color.b, color.a) == (149, 175, 198, 255)
    xy, record, _alpha, rank = score_card.call_args.args
    assert (xy, record, rank) == (INPUT + Vec2(26.0, 46.0), ui.record, 1)
    assert score_card.call_args.kwargs["ui_phase"] == 1


def test_quest_results_fade_in_over_half_a_second(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=2, faded_in=False)
    score_card = mocker.spy(quest_results_module, "ui_text_input_render")

    # `quest_results_anim_timer += frame_dt_ms`, alpha = timer * 0.002.
    for _ in range(15):
        ui.update(1.0 / 60.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    ui.draw(mouse=rl.Vector2(0.0, 0.0))
    assert score_card.call_args.args[2] == pytest.approx(15 * 16 * 0.002)
    assert ui._play_next_button.alpha == pytest.approx(15 * 16 * 0.002)

    for _ in range(30):
        ui.update(1.0 / 60.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    ui.draw(mouse=rl.Vector2(0.0, 0.0))
    assert score_card.call_args.args[2] == 1.0


def test_quest_results_buttons_phase_passes_its_phase_to_the_card(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=2)
    score_card = mocker.spy(quest_results_module, "ui_text_input_render")

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert score_card.call_args.kwargs["ui_phase"] == 2


def test_quest_results_world_entity_alpha_tracks_close_timeline(tmp_path: Path, assets_dir: Path, make_mode_config) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=2)
    assert ui.world_entity_alpha() == 1.0

    # The UI timeline stops at 400 ms, so closing starts from 400 / 500.
    ui._begin_close_transition(ResultAction.MAIN_MENU)
    assert ui.world_entity_alpha() == 0.8

    ui.timeline.timeline_ms = int(ui_element_timeline_window(28)[1] * 0.5)
    assert ui.world_entity_alpha() == 0.5

    ui.timeline.timeline_ms = 0
    assert ui.world_entity_alpha() == 0.0


@pytest.mark.parametrize("action", [ResultAction.PLAY_NEXT, ResultAction.PLAY_AGAIN])
def test_quest_results_next_run_keeps_the_world_lit(
    tmp_path: Path, assets_dir: Path, make_mode_config, action: ResultAction,
) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=2)

    ui._begin_close_transition(action)
    ui.timeline.timeline_ms = 0
    assert ui.world_entity_alpha() == 1.0


def test_quest_results_name_entry_waits_for_controls_release(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    ui.name_entry.waiting_for_release = True
    _type_chars(mocker, [ord("w"), ord("w")])
    # Player one still holds fire (mouse left) from the finishing kill.
    fire_held = mocker.patch.object(rl, "is_mouse_button_down", return_value=True)

    ui.update(0.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    assert ui.name_entry.text == "banteg"
    assert ui.name_entry.waiting_for_release is True

    fire_held.return_value = False
    ui.update(0.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    # Keys typed while fire was held were flushed, not typed.
    assert ui.name_entry.text == "banteg"
    assert ui.name_entry.waiting_for_release is False


def test_quest_results_name_entry_uses_shared_ui_text_input_typeclick_caller(
    tmp_path: Path, assets_dir: Path, make_mode_config, mocker,
) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    _type_chars(mocker, [ord("w"), ord("w")])
    played: list[SfxId] = []
    rng = ScriptedCrand([0])

    ui.update(0.0, play_sfx=played.append, rng=rng, mouse=rl.Vector2(0.0, 0.0))

    assert ui.name_entry.text == "bantegww"
    assert played == [SfxId.UI_TYPECLICK_01]
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK]


def test_score_write_failure_stays_on_name_entry_and_can_retry(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    scores_path = ui._scores_path
    assert scores_path is not None
    # A directory where the score file belongs makes the write fail like a full disk would.
    scores_path.mkdir(parents=True)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ENTER)
    played: list[SfxId] = []

    # The game loop starts each frame's focus, sampling Enter.
    ui.focus.begin_frame(0)
    ui.update(0.0, play_sfx=played.append, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    assert ui.phase == 1
    assert not ui.name_entry.saved
    assert ui.name_entry.save_error is not None

    scores_path.rmdir()
    ui.focus.begin_frame(0)
    ui.update(0.0, play_sfx=played.append, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    assert ui.phase == 2
    assert ui.name_entry.saved
    assert ui.name_entry.save_error is None
    assert [record.name() for record in read_highscore_records(scores_path)] == ["banteg"]
    assert played == [SfxId.UI_TYPEENTER, SfxId.UI_TYPEENTER]
