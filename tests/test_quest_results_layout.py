from __future__ import annotations

from pathlib import Path

import crimson.ui.quest_results as quest_results_module
from crimson.persistence.highscores import HighScoreRecord
from crimson.quests.results import QuestFinalTime
from crimson.ui.perk_menu import PerkMenuAssets
from crimson.ui.quest_results import PANEL_SLIDE_END_MS, PANEL_SLIDE_START_MS, QuestResultsAssets, QuestResultsUi
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.raylib_api import rl


def _test_config(**updates: object) -> CrimsonConfig:
    data = default_crimson_cfg_data()
    data.update(updates)
    return CrimsonConfig(path=Path("<memory>"), data=data)


def _texture(*, width: int = 0, height: int = 0) -> rl.Texture:
    texture = rl.Texture()
    texture.width = int(width)
    texture.height = int(height)
    return texture


def _perk_menu_assets() -> PerkMenuAssets:
    return PerkMenuAssets(
        menu_panel=None,
        title_pick_perk=None,
        title_level_up=None,
        menu_item=None,
        button_sm=None,
        button_md=None,
        cursor=None,
        aim=None,
    )


def _quest_results_assets() -> QuestResultsAssets:
    return QuestResultsAssets(
        menu_panel=None,
        text_well_done=None,
        particles=None,
        wicons=_texture(width=256, height=256),
        perk_menu_assets=_perk_menu_assets(),
    )


def _set_assets(ui: QuestResultsUi, assets: QuestResultsAssets) -> None:
    ui.assets = assets


def _build_ui(tmp_path: Path, *, phase: int) -> QuestResultsUi:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(fx_detail_0=0),
    )
    ui.phase = int(phase)
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_START_MS
    ui.breakdown = QuestFinalTime(
        base_time_ms=17_610,
        life_bonus_ms=0,
        unpicked_perk_bonus_ms=0,
        final_time_ms=17_610,
    )
    ui.input_text = "banteg"
    ui.input_caret = len(ui.input_text)
    _set_assets(ui, _quest_results_assets())

    record = HighScoreRecord.blank()
    record.survival_elapsed_ms = 17_610
    record.score_xp = 1750
    record.creature_kill_count = 10
    record.shots_fired = 43
    record.shots_hit = 10
    record.most_used_weapon_id = 3
    ui.record = record
    return ui


def _patch_draw_environment(
    mocker,
    captured_text: list[str],
    texture_draws: list[object],
    *,
    captured_draws: list[tuple[str, float, float, rl.Color]] | None = None,
    line_draws: list[tuple[int, int, int, int, object]] | None = None,
) -> None:
    mocker.patch.object(quest_results_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(quest_results_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(quest_results_module.rl, "get_time", side_effect=lambda: 0.0)
    mocker.patch.object(quest_results_module.rl, "draw_rectangle_lines", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module.rl, "draw_rectangle", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(
        quest_results_module.rl,
        "draw_line",
        side_effect=lambda x1, y1, x2, y2, color: (
            line_draws.append((int(x1), int(y1), int(x2), int(y2), color)) if line_draws is not None else None
        ),
    )
    mocker.patch.object(quest_results_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "button_width", side_effect=lambda *_args, **_kwargs: 82.0)
    mocker.patch.object(quest_results_module, "draw_ui_text", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(
        QuestResultsUi,
        "_text_width",
        autospec=True,
        side_effect=lambda _self, text, _scale: float(len(text) * 8),
    )
    mocker.patch.object(
        QuestResultsUi,
        "_draw_small",
        autospec=True,
        side_effect=lambda _self, text, pos, _scale, color: (
            captured_text.append(str(text)),
            captured_draws.append((str(text), float(pos.x), float(pos.y), color)) if captured_draws is not None else None,
        ),
    )
    mocker.patch.object(
        quest_results_module.rl,
        "draw_texture_pro",
        side_effect=lambda texture, _src, _dst, _origin, _rotation, _tint: texture_draws.append(texture),
    )


def test_quest_results_name_entry_draws_stats_card(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(mocker, captured_text, texture_draws)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert "State your name, trooper!" in captured_text
    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Rank: 1st" in captured_text
    assert "Shotgun" in captured_text
    assert "Frags: 10" in captured_text
    assert "Hit %: 23%" in captured_text
    assert len(texture_draws) == 1


def test_quest_results_name_prompt_preserve_bugs(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui.preserve_bugs = True
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(mocker, captured_text, texture_draws)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert "State your name trooper!" in captured_text
    assert "State your name, trooper!" not in captured_text


def test_quest_results_name_entry_uses_native_offsets_and_colors(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    captured_draws: list[tuple[str, float, float, rl.Color]] = []
    line_draws: list[tuple[int, int, int, int, object]] = []
    _patch_draw_environment(
        mocker,
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


def test_quest_results_buttons_phase_keeps_weapon_stats_hidden(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=2)
    captured_text: list[str] = []
    texture_draws: list[object] = []
    _patch_draw_environment(mocker, captured_text, texture_draws)

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
