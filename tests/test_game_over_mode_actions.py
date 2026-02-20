from __future__ import annotations

from pathlib import Path

from crimson.game_world import GameWorld
from crimson.modes.rush_mode import RushMode
from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import PANEL_SLIDE_DURATION_MS, GameOverUi
from grim.config import CrimsonConfig
from grim.view import ViewContext


def _make_mode() -> RushMode:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    config = CrimsonConfig(path=repo_root / "crimson.cfg", data={"game_mode": 2})
    mode = RushMode(ctx, config=config)
    mode._game_over_active = True
    mode._game_over_record = HighScoreRecord.blank()
    return mode


def test_update_game_over_ui_routes_high_scores(mocker) -> None:
    mode = _make_mode()

    def _update(*_args, **_kwargs):
        return "high_scores"

    mocker.patch.object(GameOverUi, "update", side_effect=_update)

    mode._update_game_over_ui(0.1)

    assert mode.take_action() == "open_high_scores"
    assert mode.close_requested is False


def test_update_game_over_ui_routes_main_menu(mocker) -> None:
    mode = _make_mode()

    def _update(*_args, **_kwargs):
        return "main_menu"

    mocker.patch.object(GameOverUi, "update", side_effect=_update)

    mode._update_game_over_ui(0.1)

    assert mode.take_action() == "back_to_menu"
    assert mode.close_requested is True


def test_update_game_over_ui_calls_open_on_play_again(mocker) -> None:
    mode = _make_mode()
    open_mode = mocker.patch.object(mode, "open")

    def _update(*_args, **_kwargs):
        return "play_again"

    mocker.patch.object(GameOverUi, "update", side_effect=_update)

    mode._update_game_over_ui(0.1)

    open_mode.assert_called_once_with()
    assert mode.take_action() is None


def test_draw_pause_background_fades_entities_during_game_over_close(mocker) -> None:
    mode = _make_mode()
    mode._game_over_ui._closing = True
    mode._game_over_ui._intro_ms = PANEL_SLIDE_DURATION_MS * 0.5

    world_draw = mocker.patch.object(GameWorld, "draw")

    mode.draw_pause_background()

    world_draw.assert_called_once()
    assert world_draw.call_args.kwargs["draw_aim_indicators"] is False
    assert world_draw.call_args.kwargs["entity_alpha"] == 0.5
