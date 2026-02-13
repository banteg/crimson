from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pyray as rl

from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.quest_results import PANEL_SLIDE_END_MS, PANEL_SLIDE_START_MS, QuestResultsUi
from grim.config import CrimsonConfig, default_crimson_cfg_data


def _test_config(**updates: object) -> CrimsonConfig:
    data = default_crimson_cfg_data()
    data.update(updates)
    return CrimsonConfig(path=Path("<memory>"), data=data)


def _build_ui(tmp_path: Path, *, phase: int) -> QuestResultsUi:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(fx_detail_0=0),
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


def _patch_draw_environment(  # noqa: ANN001
    monkeypatch,
    captured_text: list[str],
    texture_draws: list[object],
    *,
    captured_draws: list[tuple[str, float, float, object]] | None = None,
    line_draws: list[tuple[int, int, int, int, object]] | None = None,
) -> None:
    monkeypatch.setattr("crimson.ui.quest_results.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.ui.quest_results.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.ui.quest_results.rl.get_time", lambda: 0.0)
    monkeypatch.setattr("crimson.ui.quest_results.rl.draw_rectangle_lines", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.rl.draw_rectangle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "crimson.ui.quest_results.rl.draw_line",
        lambda x1, y1, x2, y2, color: (
            line_draws.append((int(x1), int(y1), int(x2), int(y2), color)) if line_draws is not None else None
        ),
    )
    monkeypatch.setattr("crimson.ui.quest_results.button_draw", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.button_width", lambda *_args, **_kwargs: 82.0)
    monkeypatch.setattr("crimson.ui.quest_results.draw_ui_text", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.draw_menu_cursor", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("crimson.ui.quest_results.QuestResultsUi._text_width", lambda _self, text, _scale: float(len(text) * 8))
    monkeypatch.setattr(
        "crimson.ui.quest_results.QuestResultsUi._draw_small",
        lambda _self, text, pos, _scale, color: (
            captured_text.append(str(text)),
            captured_draws.append((str(text), float(pos.x), float(pos.y), color)) if captured_draws is not None else None,
        ),
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

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert "State your name, trooper!" in captured_text
    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Rank: 1st" in captured_text
    assert "Shotgun" in captured_text
    assert "Frags: 10" in captured_text
    assert "Hit %: 23%" in captured_text
    assert len(texture_draws) == 1


def test_quest_results_name_prompt_preserve_bugs(monkeypatch, tmp_path: Path) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui.preserve_bugs = True
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(monkeypatch, captured_text, texture_draws)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert "State your name trooper!" in captured_text
    assert "State your name, trooper!" not in captured_text


def test_quest_results_name_entry_uses_native_offsets_and_colors(monkeypatch, tmp_path: Path) -> None:
    ui = _build_ui(tmp_path, phase=1)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    captured_draws: list[tuple[str, float, float, object]] = []
    line_draws: list[tuple[int, int, int, int, object]] = []
    _patch_draw_environment(
        monkeypatch,
        captured_text,
        texture_draws,
        captured_draws=captured_draws,
        line_draws=line_draws,
    )

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    draw_map = {text: (x, y, color) for text, x, y, color in captured_draws}

    state_x, state_y, state_color = draw_map["State your name, trooper!"]
    assert (state_x, state_y) == (154.0, 147.0)
    assert (state_color.r, state_color.g, state_color.b, state_color.a) == (149, 175, 198, 255)

    score_x, score_y, _score_color = draw_map["Score"]
    assert (score_x, score_y) == (154.0, 225.0)
    exp_x, exp_y, exp_color = draw_map["Experience"]
    assert (exp_x, exp_y) == (238.0, 225.0)
    assert (exp_color.r, exp_color.g, exp_color.b, exp_color.a) == (149, 175, 198, 178)
    frags_x, frags_y, _frags_color = draw_map["Frags: 10"]
    assert (frags_x, frags_y) == (252.0, 278.0)
    hit_x, hit_y, _hit_color = draw_map["Hit %: 23%"]
    assert (hit_x, hit_y) == (252.0, 292.0)

    assert (126, 277, 318, 277) in [(x1, y1, x2, y2) for x1, y1, x2, y2, _c in line_draws]
    assert (126, 325, 318, 325) in [(x1, y1, x2, y2) for x1, y1, x2, y2, _c in line_draws]
    assert (222, 225, 222, 273) in [(x1, y1, x2, y2) for x1, y1, x2, y2, _c in line_draws]


def test_quest_results_buttons_phase_keeps_weapon_stats_hidden(monkeypatch, tmp_path: Path) -> None:
    ui = _build_ui(tmp_path, phase=2)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(monkeypatch, captured_text, texture_draws)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Frags: 10" not in captured_text
    assert "Hit %: 23%" not in captured_text
    assert "Shotgun" not in captured_text
    assert texture_draws == []


def test_quest_results_world_entity_alpha_tracks_close_timeline(tmp_path: Path) -> None:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(fx_detail_0=0),
    )

    ui._closing = True
    ui._intro_ms = PANEL_SLIDE_END_MS
    assert ui.world_entity_alpha() == 0.0

    ui._intro_ms = (PANEL_SLIDE_START_MS + PANEL_SLIDE_END_MS) * 0.5
    assert ui.world_entity_alpha() == 0.5

    ui._intro_ms = PANEL_SLIDE_START_MS
    assert ui.world_entity_alpha() == 1.0

    ui._closing = False
    assert ui.world_entity_alpha() == 1.0
