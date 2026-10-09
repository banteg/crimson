from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import crimson.modes.components.perk_menu_controller as perk_menu_controller_module
from crimson.modes.components.perk_menu_controller import PerkMenuController, PerkMenuUiContext
from crimson.perks import PerkId
from crimson.screens.ui_timeline import UiTimeline
from crimson.sim.state_types import PerkCounts, PlayerState
from crimson.ui.focus import UiFocus
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


def _menu(played: list[SfxId]) -> PerkMenuController:
    return PerkMenuController(timeline=UiTimeline(), focus=UiFocus(), play_sfx=played.append)


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
        player=PlayerState(index=0, pos=Vec2()),
        perks=PerkCounts(),
        violence_disabled=0,
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
    )


def test_perk_menu_clicks_as_its_panel_comes_in() -> None:
    played: list[SfxId] = []
    menu = _menu(played)

    assert menu.open is False
    menu.open_menu()
    assert menu.open is True
    menu.tick_timeline()
    assert played == []
    # Slot 27 comes in at 400ms, and clicks once.
    for _ in range(5):
        menu.timeline.advance(100)
        menu.tick_timeline()
    assert played == [SfxId.UI_PANELCLICK]


def test_perk_menu_pick_returns_selected_index_and_plays_button_click(mocker) -> None:
    played: list[SfxId] = []
    menu = _menu(played)
    menu.open = True

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(mocker)
    # The frame's Enter reaches the menu through the focus frame the game loop starts.
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER))
    mocker.patch.object(rl, "is_key_down", return_value=False)
    menu.focus.begin_frame(0)

    choice_index = menu.handle_input(
        _ctx(),
        [PerkId.SHARPSHOOTER],
        dt_ui_ms=0.0,
    )

    assert choice_index == 0
    assert played == [SfxId.UI_BUTTONCLICK]
    assert menu.open is False
    assert menu.active


def test_perk_menu_cancel_plays_button_click_and_returns_none(mocker) -> None:
    played: list[SfxId] = []
    menu = _menu(played)
    menu.open = True

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: True)
    _patch_perk_menu_raylib(mocker)

    choice_index = menu.handle_input(
        _ctx(),
        [PerkId.SHARPSHOOTER],
        dt_ui_ms=0.0,
    )

    assert choice_index is None
    assert played == [SfxId.UI_BUTTONCLICK]
    assert menu.open is False
    assert menu.active
