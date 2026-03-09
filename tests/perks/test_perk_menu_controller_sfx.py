from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import pytest

import crimson.modes.components.perk_menu_controller as perk_menu_controller_module
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.modes.components.perk_menu_controller import PerkMenuContext, PerkMenuController
from crimson.perks import PerkId
from crimson.perks.state import PerkSelectionState
from crimson.sim.state_types import PlayerState
from grim.assets import RuntimeResources
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl


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
        check_collision_point_rec=mocker.Mock(side_effect=lambda _pos, _rect: False),
        measure_text=mocker.Mock(side_effect=lambda _text, _size: 10),
        is_key_pressed=mocker.Mock(side_effect=lambda key: bool(key_handler(int(key)))),
        draw_texture_pro=mocker.Mock(side_effect=lambda *_args, **_kwargs: None),
    )
    mocker.patch.object(perk_menu_controller_module, "rl", stub)
    return stub


def test_open_perk_menu_plays_panel_click(mocker) -> None:
    menu = PerkMenuController()
    play_sfx = mocker.Mock()

    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    assert menu.open is False
    assert menu.open_if_available(ctx) is True
    assert menu.open is True
    play_sfx.assert_called_once_with("sfx_ui_panelclick")


def test_perk_menu_draw_uses_cached_visible_choices_only(mocker) -> None:
    menu = PerkMenuController()
    menu.open = True
    menu.timeline_ms = 300.0

    state = GameplayState()
    player = _dummy_player()
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.SHARPSHOOTER],
        choices_dirty=True,
    )

    current_choices = mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=AssertionError("draw must not regenerate perk choices"),
    )
    visible_choices = mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_visible_choices",
        return_value=[PerkId.SHARPSHOOTER],
    )
    mocker.patch.object(
        perk_menu_controller_module,
        "perk_menu_compute_layout",
        return_value=SimpleNamespace(
            panel=SimpleNamespace(to_rl=lambda: rl.Rectangle(0.0, 0.0, 1.0, 1.0)),
            title=SimpleNamespace(to_rl=lambda: rl.Rectangle(0.0, 0.0, 1.0, 1.0)),
            sponsor_pos=Vec2(),
            list_pos=Vec2(),
            list_step_y=16.0,
            desc=SimpleNamespace(top_left=Vec2()),
            cancel_pos=Vec2(),
        ),
    )
    mocker.patch.object(perk_menu_controller_module, "draw_classic_menu_panel", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(perk_menu_controller_module, "draw_menu_item", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(perk_menu_controller_module, "draw_ui_text", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(perk_menu_controller_module, "button_draw", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(perk_menu_controller_module, "button_width", return_value=80.0)
    mocker.patch.object(
        perk_menu_controller_module,
        "menu_item_hit_rect",
        return_value=SimpleNamespace(contains=lambda *_args, **_kwargs: False),
    )
    mocker.patch.object(perk_menu_controller_module, "perk_display_name", return_value="Sharpshooter")
    mocker.patch.object(perk_menu_controller_module, "perk_display_description", return_value="desc")
    mocker.patch.object(menu, "_prewrapped_perk_desc", return_value="desc")

    _patch_perk_menu_raylib(mocker)

    ctx = PerkMenuContext(
        state=state,
        perk_state=perk_state,
        players=[player],
        creatures=[],
        player=player,
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=None,
    )

    menu.draw(ctx)

    current_choices.assert_not_called()
    visible_choices.assert_called_once_with([player], perk_state)


def test_perk_menu_pick_plays_button_click(mocker) -> None:
    menu = PerkMenuController()
    menu.open = True

    play_sfx = mocker.Mock()
    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )
    mocker.patch.object(perk_menu_controller_module, "perk_selection_pick", side_effect=lambda *args, **kwargs: object())

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)

    assert [call.args[0] for call in play_sfx.call_args_list] == ["sfx_ui_buttonclick", "sfx_ui_bonus"]
    assert menu.open is False


def test_perk_menu_pick_invokes_on_pick(mocker) -> None:
    on_pick = mocker.Mock()
    menu = PerkMenuController(on_pick=on_pick)
    menu.open = True

    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )
    mocker.patch.object(perk_menu_controller_module, "perk_selection_pick", side_effect=lambda *args, **kwargs: object())

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=None,
    )

    menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)

    on_pick.assert_called_once_with(0)


def test_perk_menu_deferred_pick_invokes_callback_without_direct_pick_apply(mocker) -> None:
    on_pick = mocker.Mock(return_value=True)
    menu = PerkMenuController(on_pick=on_pick, defer_pick_apply=True)
    menu.open = True

    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )
    pick_apply = mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_pick",
        side_effect=lambda *args, **kwargs: object(),
    )

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=None,
    )

    menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)

    on_pick.assert_called_once_with(0)
    pick_apply.assert_not_called()
    assert menu.open is False


def test_perk_menu_deferred_pick_does_not_play_bonus_sfx_immediately(mocker) -> None:
    on_pick = mocker.Mock(return_value=True)
    play_sfx = mocker.Mock()
    menu = PerkMenuController(on_pick=on_pick, defer_pick_apply=True)
    menu.open = True

    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )
    pick_apply = mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_pick",
        side_effect=lambda *args, **kwargs: object(),
    )
    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)

    on_pick.assert_called_once_with(0)
    pick_apply.assert_not_called()
    assert [call.args[0] for call in play_sfx.call_args_list] == ["sfx_ui_buttonclick"]
    assert menu.open is False


def test_perk_menu_deferred_pick_requires_callback() -> None:
    with pytest.raises(ValueError, match="on_pick is required"):
        PerkMenuController(on_pick=None, defer_pick_apply=True)


def test_perk_menu_deferred_pick_rejected_keeps_menu_open(mocker) -> None:
    on_pick = mocker.Mock(return_value=False)
    play_sfx = mocker.Mock()
    menu = PerkMenuController(on_pick=on_pick, defer_pick_apply=True)
    menu.open = True

    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )
    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)

    on_pick.assert_called_once_with(0)
    assert [call.args[0] for call in play_sfx.call_args_list] == ["sfx_ui_buttonclick"]
    assert menu.open is True


def test_perk_menu_deferred_pick_callback_requires_bool_return(mocker) -> None:
    on_pick = mocker.Mock(return_value=None)
    menu = PerkMenuController(on_pick=on_pick, defer_pick_apply=True)
    menu.open = True

    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )
    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    _patch_perk_menu_raylib(
        mocker,
        is_key_pressed=lambda key: int(key) == int(rl.KeyboardKey.KEY_ENTER),
    )

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=None,
    )

    with pytest.raises(TypeError, match="must return bool"):
        menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)


def test_perk_menu_cancel_plays_button_click(mocker) -> None:
    menu = PerkMenuController()
    menu.open = True

    play_sfx = mocker.Mock()
    mocker.patch.object(
        perk_menu_controller_module,
        "perk_selection_current_choices",
        side_effect=lambda *args, **kwargs: [PerkId.SHARPSHOOTER],
    )

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: True)
    _patch_perk_menu_raylib(mocker)

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=GameMode.SURVIVAL,
        player_count=1,
        gore_disabled=0,
        font=_dummy_font(),
        resources=_dummy_resources(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    menu.handle_input(ctx, dt=0.0, dt_ui_ms=0.0)

    play_sfx.assert_called_once_with("sfx_ui_buttonclick")
    assert menu.open is False


def test_wrap_small_text_native_inserts_newline_at_previous_space(mocker) -> None:
    menu = PerkMenuController()
    mocker.patch.object(
        perk_menu_controller_module,
        "measure_small_text_width",
        side_effect=lambda _font, text: float(len(text)),
    )
    wrapped = menu._wrap_small_text_native(object(), "alpha beta", 6.0, scale=1.0)  # type: ignore[arg-type]
    assert wrapped == "alpha\nbeta"


def test_prewrapped_perk_desc_uses_cache(mocker) -> None:
    menu = PerkMenuController()
    font = cast(SmallFontData, object())
    measure_small_text_width = mocker.patch.object(
        perk_menu_controller_module,
        "measure_small_text_width",
        side_effect=lambda _font, text: float(len(text)),
    )
    mocker.patch.object(
        perk_menu_controller_module,
        "perk_display_description",
        side_effect=lambda _perk_id, *, gore_disabled=0, preserve_bugs=False: "alpha beta gamma",
    )

    first = menu._prewrapped_perk_desc(
        PerkId.LONG_DISTANCE_RUNNER,
        font,
        gore_disabled=0,
        preserve_bugs=False,
    )
    count_after_first = measure_small_text_width.call_count
    second = menu._prewrapped_perk_desc(
        PerkId.LONG_DISTANCE_RUNNER,
        font,
        gore_disabled=0,
        preserve_bugs=False,
    )

    assert first == second
    assert measure_small_text_width.call_count == count_after_first
