from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.quest_results import PANEL_SLIDE_START_MS, QuestResultsUi


def _build_ui(tmp_path: Path, *, phase: int) -> QuestResultsUi:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=SimpleNamespace(data={"fx_detail_0": 0}),
    )
    ui.phase = int(phase)
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_START_MS
    ui.breakdown = object()
    ui.input_text = "banteg"
    ui.input_caret = len(ui.input_text)
    ui.assets = SimpleNamespace(
        menu_panel=None,
        text_well_done=None,
        particles=None,
        wicons=SimpleNamespace(width=256, height=256),
        perk_menu_assets=SimpleNamespace(cursor=None),
    )

    record = HighScoreRecord.blank()
    record.survival_elapsed_ms = 17_610
    record.score_xp = 1750
    record.creature_kill_count = 10
    record.shots_fired = 43
    record.shots_hit = 10
    record.most_used_weapon_id = 3
    ui.record = record
    return ui


def _patch_draw_environment(monkeypatch, captured_text: list[str], texture_draws: list[object]) -> None:  # noqa: ANN001
    monkeypatch.setattr("crimson.ui.quest_results.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.ui.quest_results.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.ui.quest_results.rl.get_time", lambda: 0.0)
    monkeypatch.setattr("crimson.ui.quest_results.rl.draw_rectangle_lines", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.rl.draw_rectangle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.rl.draw_line", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.button_draw", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.button_width", lambda *_args, **_kwargs: 82.0)
    monkeypatch.setattr("crimson.ui.quest_results.draw_ui_text", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.draw_menu_cursor", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.QuestResultsUi._text_width", lambda _self, text, _scale: float(len(text) * 8))
    monkeypatch.setattr(
        "crimson.ui.quest_results.QuestResultsUi._draw_small",
        lambda _self, text, _x, _y, _scale, _color: captured_text.append(str(text)),
    )
    monkeypatch.setattr(
        "crimson.ui.quest_results.rl.draw_texture_pro",
        lambda texture, _src, _dst, _origin, _rotation, _tint: texture_draws.append(texture),
    )


def test_quest_results_name_entry_draws_stats_card(monkeypatch, tmp_path: Path) -> None:
    ui = _build_ui(tmp_path, phase=1)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(monkeypatch, captured_text, texture_draws)

    ui.draw(mouse=SimpleNamespace(x=0.0, y=0.0))

    assert "State your name trooper!" in captured_text
    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Rank: 1st" in captured_text
    assert "Shotgun" in captured_text
    assert "Frags: 10" in captured_text
    assert "Hit %: 23%" in captured_text
    assert len(texture_draws) == 1


def test_quest_results_buttons_phase_keeps_weapon_stats_hidden(monkeypatch, tmp_path: Path) -> None:
    ui = _build_ui(tmp_path, phase=2)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(monkeypatch, captured_text, texture_draws)

    ui.draw(mouse=SimpleNamespace(x=0.0, y=0.0))

    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Frags: 10" not in captured_text
    assert "Hit %: 23%" not in captured_text
    assert "Shotgun" not in captured_text
    assert texture_draws == []
