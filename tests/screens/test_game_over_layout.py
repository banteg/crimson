from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.persistence.highscores import HighScoreRecord
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.actions import ResultAction
from crimson.screens.results.game_over import GameOverUi
from crimson.ui.animation import ui_element_timeline_window, ui_elements_max_timeline
from crimson.weapons import WeaponId
from grim.assets import RuntimeResources, TextureId
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

# At 640x480 with the panel slid in: panel left = -45 - 63 = -108, top = 110 - 81 = 29.
PANEL_LEFT = -108.0
PANEL_TOP = 29.0
# `game_over_screen_update`: banner/content anchor = panel left + 214, panel top + 40.
BANNER_X = PANEL_LEFT + 214.0
BANNER_Y = PANEL_TOP + 40.0


def _open_ui(tmp_path: Path, assets_dir: Path, make_mode_config, *, phase: int) -> GameOverUi:
    config = make_mode_config(game_mode=GameMode.SURVIVAL)
    ui = GameOverUi(assets_root=assets_dir, base_dir=tmp_path, config=config)
    ui.phase = phase
    ui.rank = 0
    ui.timeline.enter(ui_elements_max_timeline(GameStateId.GAME_OVER))
    ui.timeline.timeline_ms = ui.timeline.max_timeline_ms
    ui._panel_open_sfx_played = True
    return ui


def _survival_record() -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.game_mode_id = GameMode.SURVIVAL
    record.most_used_weapon_id = WeaponId.PISTOL
    return record


def _type_chars(mocker, pending: list[int]) -> None:
    """Feed raylib's char queue from `pending`; tests append to it between frames."""
    mocker.patch.object(rl, "get_char_pressed", side_effect=lambda: pending.pop(0) if pending else 0)


def test_game_over_panel_layout_uses_native_panel_anchor(tmp_path: Path, assets_dir: Path, make_mode_config) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)

    layout_640 = ui._panel_layout(screen_w=640.0)
    assert (layout_640.top_left.x, layout_640.top_left.y) == (PANEL_LEFT, PANEL_TOP)

    # The widescreen shift moves the panel down at 1024 wide.
    layout_1024 = ui._panel_layout(screen_w=1024.0)
    assert layout_1024.top_left.y == 119.0


@pytest.mark.parametrize(("mouse_x", "clicked"), [(BANNER_X + 52.0, True), (BANNER_X + 52.0 - 1.0, False)])
def test_play_again_button_starts_at_the_native_banner_anchor(
    tmp_path: Path, assets_dir: Path, make_mode_config, mocker, mouse_x: float, clicked: bool,
) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    played: list[SfxId] = []

    # A qualifying rank puts the first button at banner y + 210; its hit box starts 2px lower.
    mouse = rl.Vector2(mouse_x, BANNER_Y + 210.0 + 2.0)
    ui.update(0.016, record=_survival_record(), player_name_default="", play_sfx=played.append, rng=Crand(0), mouse=mouse)

    assert ui.closing is clicked
    assert played == ([SfxId.UI_BUTTONCLICK] if clicked else [])
    if clicked:
        actions = [
            ui.update(0.1, record=_survival_record(), player_name_default="", rng=Crand(0), mouse=mouse) for _ in range(10)
        ]
        assert [action for action in actions if action is not None] == [ResultAction.PLAY_AGAIN]


def test_game_over_name_entry_flushes_buffered_text_input(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=-1)
    _type_chars(mocker, [ord("w"), ord("w")])

    ui.update(0.0, rng=Crand(0), record=_survival_record(), player_name_default="player", mouse=rl.Vector2(0.0, 0.0))

    # An empty score table ranks the run first, so it asks for a name.
    assert ui.phase == 0
    assert ui.rank == 0
    assert ui.name_entry.text == "player"
    assert ui.name_entry.caret == len("player")


def test_game_over_name_entry_waits_for_controls_release(tmp_path: Path, assets_dir: Path, make_mode_config, mocker) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=0)
    ui.name_entry.text = "user"
    ui.name_entry.caret = len(ui.name_entry.text)
    ui.name_entry.waiting_for_release = True
    pending: list[int] = [ord("x")]
    _type_chars(mocker, pending)
    # Player one still holds fire (mouse left) from the fatal moment.
    fire_held = mocker.patch.object(rl, "is_mouse_button_down", return_value=True)
    record = _survival_record()

    ui.update(0.0, rng=Crand(0), record=record, player_name_default="user", mouse=rl.Vector2(0.0, 0.0))
    assert ui.name_entry.text == "user"
    assert ui.name_entry.waiting_for_release is True

    fire_held.return_value = False
    ui.update(0.0, rng=Crand(0), record=record, player_name_default="user", mouse=rl.Vector2(0.0, 0.0))
    assert ui.name_entry.text == "user"
    assert ui.name_entry.waiting_for_release is False

    pending.extend([ord("w"), ord("w")])
    ui.update(0.0, rng=Crand(0), record=record, player_name_default="user", mouse=rl.Vector2(0.0, 0.0))
    assert ui.name_entry.text == "userww"


def test_game_over_name_entry_uses_shared_ui_text_input_typeclick_caller(
    tmp_path: Path, assets_dir: Path, make_mode_config, mocker,
) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=0)
    ui.name_entry.text = "user"
    ui.name_entry.caret = len(ui.name_entry.text)
    _type_chars(mocker, [ord("w"), ord("w")])
    played: list[SfxId] = []
    rng = ScriptedCrand([0])

    ui.update(0.0, record=_survival_record(), player_name_default="user", play_sfx=played.append, rng=rng, mouse=rl.Vector2(0.0, 0.0))

    assert ui.name_entry.text == "userww"
    assert played == [SfxId.UI_TYPECLICK_01]
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.UI_TEXT_INPUT_UPDATE_TYPECLICK]


def test_game_over_draw_places_the_classic_panel_and_banner(
    tmp_path: Path, assets_dir: Path, make_mode_config, headless_resources: RuntimeResources, headless_window,
) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    ui.config.display.shadows_enabled = False

    ui.draw(record=_survival_record(), banner_kind="reaper", resources=headless_resources, mouse=rl.Vector2(0.0, 0.0))

    draws = headless_window.draw_texture_pro.call_args_list
    panel_texture = headless_resources.texture(TextureId.UI_MENU_PANEL)
    panel_quads = [call.args[2] for call in draws if call.args[0] is panel_texture]
    # Without shadows the 3-slice panel is three stacked quads tiling the native 510x378 box.
    assert len(panel_quads) == 3
    assert all((quad.x, quad.width) == (PANEL_LEFT, 510.0) for quad in panel_quads)
    assert [quad.y for quad in panel_quads] == [PANEL_TOP, *(quad.y + quad.height for quad in panel_quads[:-1])]
    assert panel_quads[-1].y + panel_quads[-1].height == PANEL_TOP + 378.0

    reaper = headless_resources.texture(TextureId.UI_TEXT_REAPER)
    (banner,) = [call.args[2] for call in draws if call.args[0] is reaper]
    assert (banner.x, banner.y, banner.width, banner.height) == (BANNER_X, BANNER_Y, 256.0, 64.0)


def test_game_over_world_entity_alpha_tracks_close_timeline(tmp_path: Path, assets_dir: Path, make_mode_config) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)
    assert ui.world_entity_alpha() == 1.0

    ui._begin_close_transition(ResultAction.MAIN_MENU)
    ui.timeline.timeline_ms = int(ui_element_timeline_window(28)[1] * 0.5)
    assert ui.world_entity_alpha() == 0.5

    ui.timeline.timeline_ms = -1
    assert ui.world_entity_alpha() == 0.0


def test_game_over_play_again_keeps_the_world_lit(tmp_path: Path, assets_dir: Path, make_mode_config) -> None:
    ui = _open_ui(tmp_path, assets_dir, make_mode_config, phase=1)

    # `game_over_screen_update` makes gameplay pending, which `gameplay_render_world` holds at full alpha.
    ui._begin_close_transition(ResultAction.PLAY_AGAIN)
    ui.timeline.timeline_ms = 0
    assert ui.world_entity_alpha() == 1.0
