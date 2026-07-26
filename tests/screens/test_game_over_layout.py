from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import crimson.screens.results.game_over as game_over_module
import crimson.ui.text_input as text_input_module
from crimson.game_modes import GameMode
from crimson.persistence.highscores import HighScoreRecord
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.results.game_over import PANEL_SLIDE_DURATION_MS, GameOverUi
from crimson.weapons import WeaponId
from grim.assets import RuntimeResources, TextureId
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand


def _test_config(**updates: object) -> CrimsonConfig:
    cfg = default_crimson_cfg(Path("<memory>"))
    for key, value in updates.items():
        match str(key):
            case "fx_detail_0":
                cfg.display.set_fx_detail(0, bool(value))
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
            TextureId.UI_CLOCK_TABLE: tex,
            TextureId.UI_CLOCK_POINTER: tex,
            TextureId.UI_TEXT_REAPER: _texture(width=256, height=64),
            TextureId.UI_TEXT_WELL_DONE: _texture(width=256, height=64),
        }
        self.small_font = SimpleNamespace(cell_size=8, widths=[8] * 256)

    def texture(self, texture_id: TextureId) -> rl.Texture:
        return self._textures[texture_id]


def _resources_for_score_card() -> RuntimeResources:
    return cast("RuntimeResources", _ResourcesStub())


def test_game_over_panel_layout_uses_native_panel_anchor(tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config())
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    layout_640 = ui._panel_layout(screen_w=640.0, scale=1.0)
    assert layout_640.top_left.y == 29.0
    assert layout_640.panel.y == 29.0

    layout_1024 = ui._panel_layout(screen_w=1024.0, scale=1.0)
    assert layout_1024.top_left.y == 119.0
    assert layout_1024.panel.y == 119.0


def test_game_over_phase1_button_x_uses_native_banner_anchor(monkeypatch, patch_raylib_module, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config())
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_resources_for_score_card())

    button_update = mocker.patch.object(game_over_module, "button_update", return_value=False)
    patch_raylib_module("crimson.screens.results.game_over")

    ui.update(
        0.0,
        record=HighScoreRecord.blank(),
        player_name_default="",
        mouse=rl.Vector2(0.0, 0.0),
    )

    # At 640x480: panel_left = -24, banner_x = panel_left + 214, first button x = banner_x + 52.
    assert button_update.call_count > 0
    first_pos = button_update.call_args_list[0].kwargs["pos"]
    assert float(first_pos.x) == 242.0


def test_game_over_name_entry_flushes_buffered_text_input(monkeypatch, patch_raylib_module, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config(game_mode=1))
    ui.phase = -1
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_resources_for_score_card())

    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.SURVIVAL

    char_events = [ord("w"), ord("w"), 0]
    key_events = [0]

    def _get_char_pressed() -> int:
        if char_events:
            return int(char_events.pop(0))
        return 0

    def _get_key_pressed() -> int:
        if key_events:
            return int(key_events.pop(0))
        return 0

    mocker.patch.object(game_over_module, "read_highscore_table", side_effect=lambda *_args, **_kwargs: [])
    mocker.patch.object(game_over_module, "rank_index", side_effect=lambda _records, _candidate: 0)
    mocker.patch.object(game_over_module, "scores_path_for_config", side_effect=lambda *_args, **_kwargs: tmp_path / "scores.hi")
    mocker.patch.object(game_over_module, "button_update", side_effect=lambda *args, **kwargs: False)
    patch_raylib_module("crimson.screens.results.game_over")
    mocker.patch.object(game_over_module.rl, "get_char_pressed", side_effect=_get_char_pressed)
    mocker.patch.object(game_over_module.rl, "get_key_pressed", side_effect=_get_key_pressed)

    ui.update(
        0.0,
        record=record,
        player_name_default="player",
        mouse=rl.Vector2(0.0, 0.0),
    )

    assert ui.phase == 0
    assert ui.input_text == "player"
    assert ui.input_caret == len("player")


def test_game_over_name_entry_waits_for_controls_release(patch_raylib_module, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config(game_mode=1))
    ui.phase = 0
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    ui.input_text = "user"
    ui.input_caret = len(ui.input_text)
    ui._defer_name_input_until_controls_released = True
    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_resources_for_score_card())

    patch_raylib_module("crimson.screens.results.game_over")
    mocker.patch.object(game_over_module, "button_update", return_value=False)
    mocker.patch.object(game_over_module, "gameplay_controls_held", side_effect=[True, False, False])
    poll_text = mocker.patch.object(text_input_module, "poll_text_input", return_value="ww")

    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.SURVIVAL

    ui.update(0.0, record=record, player_name_default="user", mouse=rl.Vector2(0.0, 0.0))
    assert ui.input_text == "user"
    assert ui._defer_name_input_until_controls_released is True

    ui.update(0.0, record=record, player_name_default="user", mouse=rl.Vector2(0.0, 0.0))
    assert ui.input_text == "user"
    assert ui._defer_name_input_until_controls_released is False

    ui.update(0.0, record=record, player_name_default="user", mouse=rl.Vector2(0.0, 0.0))
    assert ui.input_text == "userww"
    assert poll_text.call_count == 1


def test_game_over_name_entry_uses_shared_ui_text_input_typeclick_caller(
    patch_raylib_module,
    tmp_path: Path,
    mocker,
) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config(game_mode=1))
    ui.phase = 0
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    ui._panel_open_sfx_played = True
    ui.input_text = "user"
    ui.input_caret = len(ui.input_text)
    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_resources_for_score_card())

    patch_raylib_module("crimson.screens.results.game_over")
    mocker.patch.object(game_over_module, "button_update", return_value=False)
    poll_text = mocker.patch.object(text_input_module, "poll_text_input", return_value="ww")
    play_sfx = mocker.Mock()
    rng = ScriptedCrand([0])

    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.SURVIVAL

    ui.update(
        0.0,
        record=record,
        player_name_default="user",
        play_sfx=play_sfx,
        rng=rng,
        mouse=rl.Vector2(0.0, 0.0),
    )

    assert ui.input_text == "userww"
    assert poll_text.call_count == 1
    assert [call.args[0] for call in play_sfx.call_args_list] == [SfxId.UI_TYPECLICK_01]
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK]


def test_game_over_draw_uses_classic_menu_panel(monkeypatch, patch_raylib_module, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(fx_detail_0=0),
    )
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_resources_for_score_card())

    draw_classic_menu_panel = mocker.patch.object(game_over_module, "draw_classic_menu_panel")
    mocker.patch.object(game_over_module, "draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(game_over_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(game_over_module, "button_width", side_effect=lambda *_args, **_kwargs: 82.0)
    mocker.patch.object(GameOverUi, "_draw_score_card", return_value=None)
    patch_raylib_module("crimson.screens.results.game_over")

    ui.draw(
        record=HighScoreRecord.blank(),
        banner_kind="reaper",
        resources=_resources_for_score_card(),
        mouse=rl.Vector2(0.0, 0.0),
    )

    draw_classic_menu_panel.assert_called_once()
    panel_rect = draw_classic_menu_panel.call_args.kwargs["dst"]
    shadow_enabled = bool(draw_classic_menu_panel.call_args.kwargs["shadow"])
    assert panel_rect.x == -24.0
    assert panel_rect.y == 29.0
    assert panel_rect.width == 510.0
    assert panel_rect.height == 378.0
    assert shadow_enabled is False


def test_game_over_world_entity_alpha_tracks_close_timeline(tmp_path: Path) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config())

    ui._closing = True
    ui._intro_ms = PANEL_SLIDE_DURATION_MS * 0.5
    assert ui.world_entity_alpha() == 0.5

    ui._intro_ms = -1.0
    assert ui.world_entity_alpha() == 0.0

    ui._closing = False
    ui._intro_ms = 0.0
    assert ui.world_entity_alpha() == 1.0


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_tooltip"),
    [
        (False, "The % of bullets that hit the target"),
        (True, "The % of shot bullets hit the target"),
    ],
)
def test_game_over_hit_ratio_tooltip_respects_preserve_bugs(
    tmp_path: Path, preserve_bugs: bool, expected_tooltip: str, mocker,
) -> None:
    ui = GameOverUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(fx_detail_0=0, game_mode=1),
        preserve_bugs=preserve_bugs,
    )
    ui.rank = 0
    ui._dt = 0.0
    ui._hover_weapon = 0.0
    ui._hover_time = 0.0
    ui._hover_hit_ratio = 1.0

    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.SURVIVAL
    record.score_xp = 1000
    record.survival_elapsed_ms = 12_000
    record.creature_kill_count = 20
    record.shots_fired = 50
    record.shots_hit = 25
    record.most_used_weapon_id = WeaponId.PISTOL

    mocker.patch.object(game_over_module.rl, "measure_text", side_effect=lambda text, _size: len(str(text)) * 8)
    mocker.patch.object(game_over_module.rl, "draw_line", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(game_over_module.rl, "draw_texture_pro", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(game_over_module, "runtime_resources_for", return_value=_resources_for_score_card())
    draw_small = mocker.patch.object(
        GameOverUi,
        "_draw_small",
        autospec=True,
    )

    ui._draw_score_card(
        pos=Vec2(0.0, 0.0),
        record=record,
        resources=_resources_for_score_card(),
        font=_resources_for_score_card().small_font,
        alpha=1.0,
        show_weapon_row=True,
        scale=1.0,
        mouse=rl.Vector2(-1000.0, -1000.0),
    )

    captured_text = [str(call.args[2]) for call in draw_small.call_args_list]
    assert expected_tooltip in captured_text
