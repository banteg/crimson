from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import GameOverUi, PANEL_SLIDE_DURATION_MS


def test_game_over_panel_layout_uses_native_panel_anchor(tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=object())
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    layout_640 = ui._panel_layout(screen_w=640.0, scale=1.0)
    assert layout_640.top_left.y == 29.0
    assert layout_640.panel.y == 29.0

    layout_1024 = ui._panel_layout(screen_w=1024.0, scale=1.0)
    assert layout_1024.top_left.y == 119.0
    assert layout_1024.panel.y == 119.0


def test_game_over_phase1_button_x_uses_native_banner_anchor(monkeypatch, tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=object())
    ui.assets = object()
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    captured_x: list[float] = []

    def _button_update(_button, *, pos, width, dt_ms, mouse, click):  # noqa: ANN001, ARG001
        captured_x.append(float(pos.x))
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


def test_game_over_draw_uses_classic_menu_panel(monkeypatch, tmp_path: Path) -> None:
    ui = GameOverUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=SimpleNamespace(data={"fx_detail_0": 0}),
    )
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    ui.assets = SimpleNamespace(
        menu_panel=SimpleNamespace(width=512, height=256),
        text_reaper=None,
        text_well_done=None,
        particles=None,
        perk_menu_assets=SimpleNamespace(cursor=None),
    )

    captured_panel: list[tuple[object, bool]] = []

    def _draw_classic_menu_panel(_texture, *, dst, tint, shadow):  # noqa: ANN001, ARG001
        captured_panel.append((dst, bool(shadow)))

    monkeypatch.setattr("crimson.ui.game_over.draw_classic_menu_panel", _draw_classic_menu_panel)
    monkeypatch.setattr("crimson.ui.game_over.draw_menu_cursor", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.game_over.button_draw", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.game_over.button_width", lambda *_args, **_kwargs: 82.0)
    monkeypatch.setattr("crimson.ui.game_over.GameOverUi._draw_score_card", lambda _self, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.game_over.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.ui.game_over.rl.get_screen_height", lambda: 480)

    ui.draw(
        record=HighScoreRecord.blank(),
        banner_kind="reaper",
        hud_assets=None,
        mouse=SimpleNamespace(x=0.0, y=0.0),
    )

    assert len(captured_panel) == 1
    panel_rect, shadow_enabled = captured_panel[0]
    assert panel_rect.x == -24.0
    assert panel_rect.y == 29.0
    assert panel_rect.width == 510.0
    assert panel_rect.height == 378.0
    assert shadow_enabled is False
