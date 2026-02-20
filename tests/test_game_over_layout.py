from __future__ import annotations

from pathlib import Path

import pyray as rl
import pytest

from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.game_over import PANEL_SLIDE_DURATION_MS, GameOverAssets, GameOverUi
from crimson.ui.hud import HudAssets
from crimson.ui.perk_menu import PerkMenuAssets
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.geom import Vec2


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


def _game_over_assets(
    *,
    menu_panel: rl.Texture | None = None,
    text_reaper: rl.Texture | None = None,
    text_well_done: rl.Texture | None = None,
    particles: rl.Texture | None = None,
) -> GameOverAssets:
    return GameOverAssets(
        menu_panel=menu_panel,
        text_reaper=text_reaper,
        text_well_done=text_well_done,
        particles=particles,
        perk_menu_assets=_perk_menu_assets(),
    )


def _hud_assets_for_score_card() -> HudAssets:
    return HudAssets(
        game_top=None,
        life_heart=None,
        ind_life=None,
        ind_panel=None,
        ind_bullet=None,
        ind_fire=None,
        ind_rocket=None,
        ind_electric=None,
        wicons=_texture(width=256, height=256),
        clock_table=None,
        clock_pointer=None,
        bonuses=None,
    )


def _set_assets(ui: GameOverUi, assets: GameOverAssets) -> None:
    ui.assets = assets


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
    _set_assets(ui, _game_over_assets())
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    captured_x: list[float] = []

    def _button_update(_button, *, pos, width, dt_ms, mouse, click):
        captured_x.append(float(pos.x))
        return False

    mocker.patch("crimson.ui.game_over.button_update", side_effect=_button_update)
    patch_raylib_module("crimson.ui.game_over")

    ui.update(
        0.0,
        record=HighScoreRecord.blank(),
        player_name_default="",
        mouse=rl.Vector2(0.0, 0.0),
    )

    # At 640x480: panel_left = -24, banner_x = panel_left + 214, first button x = banner_x + 52.
    assert captured_x
    assert captured_x[0] == 242.0


def test_game_over_name_entry_flushes_buffered_text_input(monkeypatch, patch_raylib_module, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(assets_root=tmp_path, base_dir=tmp_path, config=_test_config(game_mode=1))
    _set_assets(ui, _game_over_assets())
    ui.phase = -1
    ui._intro_ms = PANEL_SLIDE_DURATION_MS

    record = HighScoreRecord.blank()
    record.game_mode_id = 1

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

    mocker.patch("crimson.ui.game_over.read_highscore_table", side_effect=lambda *_args, **_kwargs: [])
    mocker.patch("crimson.ui.game_over.rank_index", side_effect=lambda _records, _candidate: 0)
    mocker.patch("crimson.ui.game_over.scores_path_for_config", side_effect=lambda *_args, **_kwargs: tmp_path / "scores.hi")
    mocker.patch("crimson.ui.game_over.button_update", side_effect=lambda *args, **kwargs: False)
    patch_raylib_module("crimson.ui.game_over")
    mocker.patch("crimson.ui.game_over.rl.get_char_pressed", side_effect=_get_char_pressed)
    mocker.patch("crimson.ui.game_over.rl.get_key_pressed", side_effect=_get_key_pressed)

    ui.update(
        0.0,
        record=record,
        player_name_default="player",
        mouse=rl.Vector2(0.0, 0.0),
    )

    assert ui.phase == 0
    assert ui.input_text == "player"
    assert ui.input_caret == len("player")


def test_game_over_draw_uses_classic_menu_panel(monkeypatch, patch_raylib_module, tmp_path: Path, mocker) -> None:
    ui = GameOverUi(
        assets_root=tmp_path,
        base_dir=tmp_path,
        config=_test_config(fx_detail_0=0),
    )
    ui.phase = 1
    ui.rank = 0
    ui._intro_ms = PANEL_SLIDE_DURATION_MS
    _set_assets(ui, _game_over_assets(menu_panel=_texture(width=512, height=256)))

    captured_panel: list[tuple[rl.Rectangle, bool]] = []

    def _draw_classic_menu_panel(_texture, *, dst, tint, shadow):
        captured_panel.append((dst, bool(shadow)))

    mocker.patch("crimson.ui.game_over.draw_classic_menu_panel", side_effect=_draw_classic_menu_panel)
    mocker.patch("crimson.ui.game_over.draw_menu_cursor", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.ui.game_over.button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.ui.game_over.button_width", side_effect=lambda *_args, **_kwargs: 82.0)
    mocker.patch("crimson.ui.game_over.GameOverUi._draw_score_card", return_value=None)
    patch_raylib_module("crimson.ui.game_over")

    ui.draw(
        record=HighScoreRecord.blank(),
        banner_kind="reaper",
        hud_assets=None,
        mouse=rl.Vector2(0.0, 0.0),
    )

    assert len(captured_panel) == 1
    panel_rect, shadow_enabled = captured_panel[0]
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
    monkeypatch, tmp_path: Path, preserve_bugs: bool, expected_tooltip: str, mocker,
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
    record.game_mode_id = 1
    record.score_xp = 1000
    record.survival_elapsed_ms = 12_000
    record.creature_kill_count = 20
    record.shots_fired = 50
    record.shots_hit = 25
    record.most_used_weapon_id = 1

    captured_text: list[str] = []
    mocker.patch("crimson.ui.game_over.rl.measure_text", side_effect=lambda text, _size: len(str(text)) * 8)
    mocker.patch("crimson.ui.game_over.rl.draw_line", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch("crimson.ui.game_over.rl.draw_texture_pro", side_effect=lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        GameOverUi,
        "_draw_small",
        lambda _self, text, _pos, _scale, _color: captured_text.append(str(text)),
    )

    ui._draw_score_card(
        pos=Vec2(0.0, 0.0),
        record=record,
        hud_assets=_hud_assets_for_score_card(),
        alpha=1.0,
        show_weapon_row=True,
        scale=1.0,
        mouse=rl.Vector2(-1000.0, -1000.0),
    )

    assert expected_tooltip in captured_text
