from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import crimson.screens.results.quest_results as quest_results_module
import crimson.ui.text_input as text_input_module
from crimson.game_modes import GameMode
from crimson.persistence.highscores import HighScoreRecord
from crimson.quests.results import QuestFinalTime
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.results.quest_results import (
    PANEL_SLIDE_END_MS,
    PANEL_SLIDE_START_MS,
    QuestResultsUi,
)
from crimson.weapons import WeaponId
from grim.assets import RuntimeResources, TextureId
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand


def _test_config(**updates: object) -> CrimsonConfig:
    cfg = default_crimson_cfg(Path("<memory>"))
    for key, value in updates.items():
        match str(key):
            case "shadows_enabled":
                cfg.display.shadows_enabled = bool(value)
            case "game_mode":
                cfg.gameplay.mode = GameMode(int(cast(Any, value)))
            case _:
                raise KeyError(f"unsupported config update: {key}")
    return cfg


def _texture(*, width: int = 0, height: int = 0) -> rl.Texture:
    texture = rl.Texture()
    texture.width = int(width)
    texture.height = int(height)
    return texture


class _ResourcesStub:
    def __init__(self) -> None:
        tex = _texture(width=32, height=32)
        self._textures = {
            TextureId.UI_MENU_PANEL: tex,
            TextureId.UI_BUTTON_SM: tex,
            TextureId.UI_BUTTON_MD: tex,
            TextureId.UI_CURSOR: tex,
            TextureId.PARTICLES: tex,
            TextureId.UI_WICONS: _texture(width=256, height=256),
            TextureId.UI_TEXT_WELL_DONE: _texture(width=256, height=64),
        }
        self.small_font = SimpleNamespace(cell_size=8, widths=[8] * 256)

    def texture(self, texture_id: TextureId) -> rl.Texture:
        return self._textures[texture_id]


def _resources_stub() -> RuntimeResources:
    return cast("RuntimeResources", _ResourcesStub())


def _build_ui(tmp_path: Path, *, phase: int) -> QuestResultsUi:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(shadows_enabled=0),
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

    record = HighScoreRecord.blank()
    record.survival_elapsed_ms = 17_610
    record.score_xp = 1750
    record.creature_kill_count = 10
    record.shots_fired = 43
    record.shots_hit = 10
    record.most_used_weapon_id = WeaponId.SHOTGUN
    ui.record = record
    return ui


def _patch_draw_environment(
    mocker,
) -> tuple[MagicMock, MagicMock, MagicMock]:
    mocker.patch.object(quest_results_module, "runtime_resources_for", return_value=_resources_stub())
    mocker.patch.object(quest_results_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(quest_results_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(quest_results_module.rl, "get_time", side_effect=lambda: 0.0)
    mocker.patch.object(quest_results_module.rl, "draw_rectangle_lines", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module.rl, "draw_rectangle", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    draw_line = mocker.patch.object(quest_results_module.rl, "draw_line")
    mocker.patch.object(quest_results_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "button_width", side_effect=lambda *_args, **_kwargs: 82.0)
    mocker.patch.object(quest_results_module, "draw_ui_text", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(
        QuestResultsUi,
        "_text_width",
        autospec=True,
        side_effect=lambda _self, _font, text, _scale: float(len(text) * 8),
    )
    draw_small = mocker.patch.object(
        QuestResultsUi,
        "_draw_small",
        autospec=True,
    )
    draw_texture_pro = mocker.patch.object(quest_results_module.rl, "draw_texture_pro")
    return draw_small, draw_texture_pro, draw_line


def test_quest_results_name_entry_draws_stats_card(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    draw_small, draw_texture_pro, _draw_line = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    captured_text = [str(call.args[2]) for call in draw_small.call_args_list]
    assert "State your name trooper!" in captured_text
    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Rank: 1st" in captured_text
    assert "Shotgun" in captured_text
    assert "Frags: 10" in captured_text
    assert "Hit %: 23%" in captured_text
    assert len(draw_texture_pro.call_args_list) == 2


def test_quest_results_name_prompt_preserve_bugs(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui.preserve_bugs = True
    draw_small, _draw_texture_pro, _draw_line = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    captured_text = [str(call.args[2]) for call in draw_small.call_args_list]
    assert "State your name trooper!" in captured_text
    assert "State your name, trooper!" not in captured_text


def test_quest_results_name_entry_uses_native_offsets_and_colors(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    draw_small, _draw_texture_pro, draw_line = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    draw_map = {
        str(call.args[2]): (float(call.args[3].x), float(call.args[3].y), call.args[5])
        for call in draw_small.call_args_list
    }

    state_x, state_y, state_color = draw_map["State your name trooper!"]
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

    line_draws = [
        (int(call.args[0]), int(call.args[1]), int(call.args[2]), int(call.args[3]), call.args[4])
        for call in draw_line.call_args_list
    ]
    assert (126, 277, 318, 277) in [(x1, y1, x2, y2) for x1, y1, x2, y2, _c in line_draws]
    assert (126, 325, 318, 325) in [(x1, y1, x2, y2) for x1, y1, x2, y2, _c in line_draws]
    assert (222, 225, 222, 273) in [(x1, y1, x2, y2) for x1, y1, x2, y2, _c in line_draws]


def test_quest_results_buttons_phase_keeps_weapon_stats_hidden(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=2)
    draw_small, draw_texture_pro, _draw_line = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    captured_text = [str(call.args[2]) for call in draw_small.call_args_list]
    assert "Score" in captured_text
    assert "Experience" in captured_text
    assert "Frags: 10" not in captured_text
    assert "Hit %: 23%" not in captured_text
    assert "Shotgun" not in captured_text
    assert len(draw_texture_pro.call_args_list) == 1


def test_quest_results_world_entity_alpha_tracks_close_timeline(tmp_path: Path) -> None:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(shadows_enabled=0),
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


def test_quest_results_name_entry_waits_for_controls_release(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui._defer_name_input_until_controls_released = True
    poll_text = mocker.patch.object(text_input_module, "poll_text_input", return_value="ww")
    mocker.patch.object(quest_results_module, "gameplay_controls_held", side_effect=[True, False])

    ui.update(0.0, mouse=rl.Vector2(0.0, 0.0))
    assert ui.input_text == "banteg"
    assert ui._defer_name_input_until_controls_released is True

    ui.update(0.0, mouse=rl.Vector2(0.0, 0.0))
    assert ui.input_text == "banteg"
    assert ui._defer_name_input_until_controls_released is False
    assert poll_text.call_count == 0


def test_quest_results_name_entry_uses_shared_ui_text_input_typeclick_caller(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui._panel_open_sfx_played = True
    _patch_draw_environment(mocker)
    poll_text = mocker.patch.object(text_input_module, "poll_text_input", return_value="ww")
    mocker.patch.object(quest_results_module.rl, "is_mouse_button_pressed", side_effect=lambda _button: False)
    mocker.patch.object(quest_results_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    play_sfx = mocker.Mock()
    rng = ScriptedCrand([0])

    ui.update(0.0, play_sfx=play_sfx, rng=rng, mouse=rl.Vector2(0.0, 0.0))

    assert ui.input_text == "bantegww"
    assert poll_text.call_count == 1
    assert [call.args[0] for call in play_sfx.call_args_list] == [SfxId.UI_TYPECLICK_01]
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK]
