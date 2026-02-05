from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import GameOverUi, PANEL_SLIDE_DURATION_MS


def test_game_over_panel_layout_uses_native_panel_anchor(tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=object())
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    panel_640, _left_640, top_640 = ui._panel_layout(screen_w=640.0, scale=1.0)
    assert top_640 == 29.0
    assert panel_640.y == 29.0

    panel_1024, _left_1024, top_1024 = ui._panel_layout(screen_w=1024.0, scale=1.0)
    assert top_1024 == 119.0
    assert panel_1024.y == 119.0


def test_game_over_phase1_button_x_uses_native_banner_anchor(monkeypatch, tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=object())
    ui.assets = object()
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    captured_x: list[float] = []

    def _button_update(_button, *, x, y, width, dt_ms, mouse, click):  # noqa: ANN001, ARG001
        captured_x.append(float(x))
        return False

    monkeypatch.setattr("crimson.ui.game_over.button_update", _button_update)
    monkeypatch.setattr("crimson.ui.game_over.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.ui.game_over.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.ui.game_over.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.ui.game_over.rl.is_key_pressed", lambda _key: False)
    monkeypatch.setattr("crimson.ui.game_over.rl.check_collision_point_rec", lambda _pos, _rect: False)

    ui.update(
        0.0,
        record=HighScoreRecord.blank(),
        player_name_default="",
        mouse=SimpleNamespace(x=0.0, y=0.0),
    )

    # At 640x480: panel_left = -24, banner_x = panel_left + 214, first button x = banner_x + 52.
    assert captured_x
    assert captured_x[0] == 242.0
