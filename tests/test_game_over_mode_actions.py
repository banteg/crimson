from __future__ import annotations

from pathlib import Path

from crimson.game_world import GameWorld
from crimson.modes.rush_mode import RushMode
from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import PANEL_SLIDE_DURATION_MS
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


def test_update_game_over_ui_routes_high_scores(monkeypatch) -> None:
    mode = _make_mode()

    def _update(*_args, **_kwargs):  # noqa: ANN001
        return "high_scores"

    monkeypatch.setattr("crimson.ui.game_over.GameOverUi.update", _update)

    mode._update_game_over_ui(0.1)

    assert mode.take_action() == "open_high_scores"
    assert mode.close_requested is False


def test_update_game_over_ui_routes_main_menu(monkeypatch) -> None:
    mode = _make_mode()

    def _update(*_args, **_kwargs):  # noqa: ANN001
        return "main_menu"

    monkeypatch.setattr("crimson.ui.game_over.GameOverUi.update", _update)

    mode._update_game_over_ui(0.1)

    assert mode.take_action() == "back_to_menu"
    assert mode.close_requested is True


def test_update_game_over_ui_calls_open_on_play_again(monkeypatch) -> None:
    mode = _make_mode()

    opened: list[bool] = []

    def _open() -> None:
        opened.append(True)

    monkeypatch.setattr(mode, "open", _open)

    def _update(*_args, **_kwargs):  # noqa: ANN001
        return "play_again"

    monkeypatch.setattr("crimson.ui.game_over.GameOverUi.update", _update)

    mode._update_game_over_ui(0.1)

    assert opened == [True]
    assert mode.take_action() is None


def test_draw_pause_background_fades_entities_during_game_over_close(monkeypatch) -> None:
    mode = _make_mode()
    mode._game_over_ui._closing = True
    mode._game_over_ui._intro_ms = PANEL_SLIDE_DURATION_MS * 0.5

    captured: dict[str, object] = {}

    def _draw(*, draw_aim_indicators: bool, entity_alpha: float = 1.0) -> None:
        captured["draw_aim_indicators"] = draw_aim_indicators
        captured["entity_alpha"] = entity_alpha

    monkeypatch.setattr(GameWorld, "draw", lambda *_args, **kwargs: _draw(**kwargs))

    mode.draw_pause_background()

    assert captured["draw_aim_indicators"] is False
    assert captured["entity_alpha"] == 0.5
