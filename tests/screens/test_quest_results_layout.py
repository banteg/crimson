from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import crimson.screens.results.quest_results as quest_results_module
import crimson.ui.text_input as text_input_module
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.persistence.highscores import HighScoreRecord
from crimson.quests.results import QuestFinalTime
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.results.quest_results import QuestResultsUi
from crimson.ui.animation import ui_element_timeline_window, ui_elements_max_timeline
from crimson.weapons import WeaponId
from grim.assets import RuntimeResources, TextureId
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.geom import Vec2
from grim.rand import Crand
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
    ui.timeline.enter(ui_elements_max_timeline(GameStateId.QUEST_RESULTS))
    ui.timeline.timeline_ms = ui.timeline.max_timeline_ms
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
) -> tuple[MagicMock, MagicMock]:
    mocker.patch.object(quest_results_module, "runtime_resources_for", return_value=_resources_stub())
    mocker.patch.object(quest_results_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(quest_results_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(quest_results_module.rl, "get_time", side_effect=lambda: 0.0)
    mocker.patch.object(quest_results_module.rl, "draw_rectangle_lines", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module.rl, "draw_rectangle", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module.rl, "draw_line")
    mocker.patch.object(quest_results_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "draw_ui_text", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(quest_results_module, "ui_cursor_render", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(
        QuestResultsUi,
        "_text_width",
        autospec=True,
        side_effect=lambda _self, _font, text: float(len(text) * 8),
    )
    draw_small = mocker.patch.object(
        QuestResultsUi,
        "_draw_small",
        autospec=True,
    )
    mocker.patch.object(quest_results_module.rl, "draw_texture_pro")
    score_card = mocker.patch.object(quest_results_module, "ui_text_input_render")
    return draw_small, score_card


def test_quest_results_name_prompt_preserve_bugs(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui.preserve_bugs = True
    draw_small, _score_card = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    captured_text = [str(call.args[2]) for call in draw_small.call_args_list]
    assert "State your name trooper!" in captured_text
    assert "State your name, trooper!" not in captured_text


def test_quest_results_name_entry_uses_native_offsets_and_colors(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    draw_small, score_card = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    draw_map = {
        str(call.args[2]): (float(call.args[3].x), float(call.args[3].y), call.args[4])
        for call in draw_small.call_args_list
    }
    state_x, state_y, state_color = draw_map["State your name trooper!"]
    assert (state_x, state_y) == (154.0, 147.0)
    assert (state_color.r, state_color.g, state_color.b, state_color.a) == (149, 175, 198, 255)
    xy, record, _alpha, rank = score_card.call_args.args
    assert (xy, record, rank) == (Vec2(138.0, 225.0), ui.record, 1)
    assert score_card.call_args.kwargs["ui_phase"] == 1


def test_quest_results_buttons_phase_passes_its_phase_to_the_card(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=2)
    _draw_small, score_card = _patch_draw_environment(mocker)

    ui.draw(mouse=rl.Vector2(0.0, 0.0))

    assert score_card.call_args.kwargs["ui_phase"] == 2


def test_quest_results_world_entity_alpha_tracks_close_timeline(tmp_path: Path) -> None:
    ui = QuestResultsUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(shadows_enabled=0),
    )

    ui.timeline.closing = True
    ui.timeline.timeline_ms = int(0.0)
    assert ui.world_entity_alpha() == 0.0

    ui.timeline.timeline_ms = int(ui_element_timeline_window(28)[1] * 0.5)
    assert ui.world_entity_alpha() == 0.5

    # The UI timeline stops at 400 ms, so closing starts from 400 / 500.
    ui.timeline.enter(ui_elements_max_timeline(GameStateId.QUEST_RESULTS))
    ui.timeline.timeline_ms = ui.timeline.max_timeline_ms
    ui.timeline.closing = True
    assert ui.world_entity_alpha() == 0.8

    ui.timeline.closing = False
    assert ui.world_entity_alpha() == 1.0


def test_quest_results_name_entry_waits_for_controls_release(tmp_path: Path, mocker) -> None:
    ui = _build_ui(tmp_path, phase=1)
    ui._defer_name_input_until_controls_released = True
    poll_text = mocker.patch.object(text_input_module, "poll_text_input", return_value="ww")
    mocker.patch.object(quest_results_module, "gameplay_controls_held", side_effect=[True, False])

    ui.update(0.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    assert ui.input_text == "banteg"
    assert ui._defer_name_input_until_controls_released is True

    ui.update(0.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
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


def test_score_write_failure_stays_on_name_entry_and_can_retry(tmp_path: Path, mocker) -> None:
    from crimson.persistence.highscores import read_highscore_records, upsert_highscore_record

    ui = _build_ui(tmp_path, phase=1)
    ui.config = default_crimson_cfg(tmp_path / "crimson.cfg")
    ui._scores_path = tmp_path / "scores.hi"
    ui._consume_enter = False
    _patch_draw_environment(mocker)
    mocker.patch.object(quest_results_module, "update_name_entry_text", return_value=("Player", 6))
    mocker.patch.object(quest_results_module, "button_update", return_value=True)
    mocker.patch.object(quest_results_module.rl, "is_mouse_button_pressed", return_value=False)
    mocker.patch.object(quest_results_module.rl, "is_key_pressed", return_value=False)
    failed_save = mocker.patch.object(quest_results_module, "upsert_highscore_record", side_effect=OSError("disk full"))
    ui.update(0.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    assert ui.phase == 1
    assert not ui._saved
    assert ui.save_error is not None
    failed_save.side_effect = upsert_highscore_record
    ui.update(0.0, rng=Crand(0), mouse=rl.Vector2(0.0, 0.0))
    assert ui.phase == 2
    assert ui._saved
    assert ui.save_error is None
    assert len(read_highscore_records(ui._scores_path)) == 1
