from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.persistence.highscores import HighScoreRecord
from crimson.screens.actions import Route, ScoreQuery, ShowScores, StartRun
from crimson.screens.high_scores_view import HighScoresView
from crimson.screens.results.game_over import GameOverUi
from crimson.ui.animation import ui_elements_max_timeline
from crimson.weapons import WeaponId
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run, update_frame

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")


def test_game_over_panel_open_plays_panel_click(tmp_path: Path, assets_dir: Path, make_mode_config) -> None:
    ui = GameOverUi(assets_root=assets_dir, base_dir=tmp_path, config=make_mode_config(game_mode=GameMode.SURVIVAL))
    ui.phase = 1
    ui.timeline.enter(ui_elements_max_timeline(GameStateId.GAME_OVER))
    ui.timeline.timeline_ms = ui.timeline.max_timeline_ms - 60
    record = HighScoreRecord.blank()
    record.most_used_weapon_id = WeaponId.PISTOL
    played: list[SfxId] = []

    ui.update(0.1, record=record, player_name_default="", play_sfx=played.append, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    ui.update(0.1, record=record, player_name_default="", play_sfx=played.append, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))

    assert played == [SfxId.UI_PANELCLICK]


@pytest.fixture
def scores_over_run(make_game_state, headless_resources, mocker):
    """High scores opened from a survival run's game over, the run retained underneath."""
    audio = HeadlessAudio(mocker)
    state = make_game_state(resources=headless_resources, audio=audio.state)
    navigator, run = start_run(state, StartRun(GameMode.SURVIVAL))
    navigator.navigate(ShowScores(ScoreQuery(game_mode_id=GameMode.SURVIVAL)))
    view = state.screens.active
    assert isinstance(view, HighScoresView)
    return view, run, audio


def test_high_scores_view_open_plays_panel_click_and_escape_plays_button_click(scores_over_run, mocker) -> None:
    view, _run, audio = scores_over_run

    assert audio.played() == [SfxId.UI_PANELCLICK]

    # High scores view animates in; advance its timeline before pressing escape.
    view.update(0.1)
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
    assert action == Route.BACK


def test_high_scores_view_draw_fades_the_retained_run_with_the_timeline(scores_over_run, mocker) -> None:
    view, run, _audio = scores_over_run
    mocker.patch.object(run, "_draw_world")
    background = mocker.spy(run, "draw_pause_background")
    view.state.ui.timeline_ms = ui_elements_max_timeline(GameStateId.HIGHSCORES)

    view.draw()

    # `gameplay_render_world` runs over `ui_element_table[28]`'s 500 ms, so the scores' 300 ms timeline stops at 0.6.
    background.assert_called_once_with(entity_alpha=0.6)
