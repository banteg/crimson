from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import msgspec

import crimson.modes.components.perk_menu_controller as perk_menu_controller_module
from crimson.modes.components.perk_menu_controller import PerkMenuController, PerkMenuRuntime, PerkMenuUiContext
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.assets import RuntimeResources
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId


def _texture() -> rl.Texture:
    return rl.Texture()


def _dummy_resources() -> RuntimeResources:
    texture = _texture()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: texture,
            small_font=_dummy_font(),
        ),
    )


def _dummy_font() -> SmallFontData:
    return SmallFontData(widths=[8] * 256, texture=_texture(), cell_size=16, grid=16)


def _dummy_player() -> PlayerState:
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts = [0] * 128
    return player


class _RecordingPerkMenuRuntime(PerkMenuRuntime):
    played: list[SfxId] = msgspec.field(default_factory=list)
    closed_count: int = 0

    def on_close(self) -> None:
        self.closed_count += 1

    def play_sfx(self, sfx_id: SfxId) -> None:
        self.played.append(sfx_id)


def _patch_perk_menu_raylib(
    mocker,
    *,
    is_key_pressed: Callable[[int], bool] | None = None,
) -> SimpleNamespace:
    key_handler = is_key_pressed if is_key_pressed is not None else (lambda _key: False)
    stub = SimpleNamespace(
        KeyboardKey=rl.KeyboardKey,
        MouseButton=rl.MouseButton,
        Rectangle=rl.Rectangle,
        Vector2=rl.Vector2,
        WHITE=rl.WHITE,
        get_screen_width=mocker.Mock(return_value=640),
        get_screen_height=mocker.Mock(return_value=480),
        is_mouse_button_pressed=mocker.Mock(side_effect=lambda _button: False),
        is_key_pressed=mocker.Mock(side_effect=lambda key: bool(key_handler(int(key)))),
        draw_texture_pro=mocker.Mock(),
        begin_blend_mode=mocker.Mock(),
        end_blend_mode=mocker.Mock(),
        BlendMode=rl.BlendMode,
    )
    mocker.patch.object(perk_menu_controller_module, "rl", stub)
    return stub


def _ctx() -> PerkMenuUiContext:
    return PerkMenuUiContext(
        player=_dummy_player(),
        violence_disabled=0,
        preserve_bugs=False,
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
    )


def test_open_perk_menu_plays_panel_click() -> None:
    runtime = _RecordingPerkMenuRuntime()
    menu = PerkMenuController(runtime=runtime)

    assert menu.open is False
    menu.open_menu()
    assert menu.open is True
    assert runtime.played == [SfxId.UI_PANELCLICK]


def test_perk_menu_pick_returns_selected_index_and_plays_button_click(mocker) -> None:
    runtime = _RecordingPerkMenuRuntime()
    menu = PerkMenuController(runtime=runtime)
    menu.open = True

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    choice_index = menu.handle_input(
        _ctx(),
        [PerkId.SHARPSHOOTER],
        dt_ui_ms=0.0,
    )

    assert choice_index == 0
    assert runtime.played == [SfxId.UI_BUTTONCLICK]
    assert runtime.closed_count == 1
    assert menu.open is False


def test_perk_menu_cancel_plays_button_click_and_returns_none(mocker) -> None:
    runtime = _RecordingPerkMenuRuntime()
    menu = PerkMenuController(runtime=runtime)
    menu.open = True

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: True)
    _patch_perk_menu_raylib(mocker)

    choice_index = menu.handle_input(
        _ctx(),
        [PerkId.SHARPSHOOTER],
        dt_ui_ms=0.0,
    )

    assert choice_index is None
    assert runtime.played == [SfxId.UI_BUTTONCLICK]
    assert runtime.closed_count == 1
    assert menu.open is False


def test_draw_accepts_prepared_choices_without_selection_helpers(mocker) -> None:
    menu = PerkMenuController()
    menu.open = True
    menu.timeline_ms = 1_000.0
    mocker.patch.object(perk_menu_controller_module, "draw_classic_menu_panel", return_value=None)
    mocker.patch.object(perk_menu_controller_module, "draw_menu_item", return_value=None)
    mocker.patch.object(perk_menu_controller_module, "draw_ui_text", return_value=None)
    mocker.patch.object(perk_menu_controller_module, "button_draw", return_value=None)
    mocker.patch.object(perk_menu_controller_module, "perk_display_description", return_value="desc")
    mocker.patch.object(perk_menu_controller_module, "perk_display_name", return_value="Sharpshooter")
    mocker.patch.object(perk_menu_controller_module, "measure_small_text_width", side_effect=lambda *_args: 8.0)
    _patch_perk_menu_raylib(mocker)

    menu.draw(
        _ctx(),
        [PerkId.SHARPSHOOTER],
    )
