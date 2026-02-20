from __future__ import annotations

import crimson.modes.components.perk_menu_controller as perk_menu_controller_module
from crimson.gameplay import GameplayState
from crimson.modes.components.perk_menu_controller import PerkMenuContext, PerkMenuController
from crimson.perks.state import PerkSelectionState
from crimson.sim.state_types import PlayerState
from crimson.ui.perk_menu import PerkMenuAssets
from grim.geom import Vec2
from grim.raylib_api import rl


def _dummy_assets() -> PerkMenuAssets:
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


def _dummy_player() -> PlayerState:
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts = [0] * 128
    return player


def test_open_perk_menu_plays_panel_click(mocker) -> None:
    menu = PerkMenuController()
    play_sfx = mocker.Mock()

    mocker.patch.object(perk_menu_controller_module, "perk_selection_current_choices", side_effect=lambda *args, **kwargs: [1])

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    assert menu.open is False
    assert menu.open_if_available(ctx) is True
    assert menu.open is True
    play_sfx.assert_called_once_with("sfx_ui_panelclick")


def test_perk_menu_pick_plays_button_click(mocker) -> None:
    menu = PerkMenuController()
    menu.open = True

    play_sfx = mocker.Mock()
    mocker.patch.object(perk_menu_controller_module, "perk_selection_current_choices", side_effect=lambda *args, **kwargs: [1])
    mocker.patch.object(perk_menu_controller_module, "perk_selection_pick", side_effect=lambda *args, **kwargs: object())

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    mocker.patch.object(perk_menu_controller_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(perk_menu_controller_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(perk_menu_controller_module.rl, "is_mouse_button_pressed", side_effect=lambda _button: False)
    mocker.patch.object(perk_menu_controller_module.rl, "check_collision_point_rec", side_effect=lambda _pos, _rect: False)
    mocker.patch.object(perk_menu_controller_module.rl, "measure_text", side_effect=lambda _text, _size: 10)

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ENTER)

    mocker.patch.object(perk_menu_controller_module.rl, "is_key_pressed", side_effect=_is_key_pressed)

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    menu.handle_input(ctx, dt_frame=0.0, dt_ui_ms=0.0)

    assert [call.args[0] for call in play_sfx.call_args_list] == ["sfx_ui_buttonclick", "sfx_ui_bonus"]
    assert menu.open is False


def test_perk_menu_pick_invokes_on_pick(mocker) -> None:
    on_pick = mocker.Mock()
    menu = PerkMenuController(on_pick=on_pick)
    menu.open = True

    mocker.patch.object(perk_menu_controller_module, "perk_selection_current_choices", side_effect=lambda *args, **kwargs: [1])
    mocker.patch.object(perk_menu_controller_module, "perk_selection_pick", side_effect=lambda *args, **kwargs: object())

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: False)
    mocker.patch.object(perk_menu_controller_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(perk_menu_controller_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(perk_menu_controller_module.rl, "is_mouse_button_pressed", side_effect=lambda _button: False)
    mocker.patch.object(perk_menu_controller_module.rl, "check_collision_point_rec", side_effect=lambda _pos, _rect: False)
    mocker.patch.object(perk_menu_controller_module.rl, "measure_text", side_effect=lambda _text, _size: 10)

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ENTER)

    mocker.patch.object(perk_menu_controller_module.rl, "is_key_pressed", side_effect=_is_key_pressed)

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=None,
    )

    menu.handle_input(ctx, dt_frame=0.0, dt_ui_ms=0.0)

    on_pick.assert_called_once_with(0)


def test_perk_menu_cancel_plays_button_click(mocker) -> None:
    menu = PerkMenuController()
    menu.open = True

    play_sfx = mocker.Mock()
    mocker.patch.object(perk_menu_controller_module, "perk_selection_current_choices", side_effect=lambda *args, **kwargs: [1])

    mocker.patch.object(perk_menu_controller_module, "button_update", side_effect=lambda *args, **kwargs: True)
    mocker.patch.object(perk_menu_controller_module.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(perk_menu_controller_module.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(perk_menu_controller_module.rl, "is_mouse_button_pressed", side_effect=lambda _button: False)
    mocker.patch.object(perk_menu_controller_module.rl, "check_collision_point_rec", side_effect=lambda _pos, _rect: False)
    mocker.patch.object(perk_menu_controller_module.rl, "measure_text", side_effect=lambda _text, _size: 10)
    mocker.patch.object(perk_menu_controller_module.rl, "is_key_pressed", side_effect=lambda _key: False)

    ctx = PerkMenuContext(
        state=GameplayState(),
        perk_state=PerkSelectionState(),
        players=[],
        creatures=[],
        player=_dummy_player(),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=play_sfx,
    )

    menu.handle_input(ctx, dt_frame=0.0, dt_ui_ms=0.0)

    play_sfx.assert_called_once_with("sfx_ui_buttonclick")
    assert menu.open is False


def test_wrap_small_text_native_inserts_newline_at_previous_space(mocker) -> None:
    menu = PerkMenuController()
    mocker.patch.object(
        perk_menu_controller_module,
        "measure_small_text_width",
        side_effect=lambda _font, text, _scale: float(len(text)),
    )
    wrapped = menu._wrap_small_text_native(object(), "alpha beta", 6.0, scale=1.0)  # type: ignore[arg-type]
    assert wrapped == "alpha\nbeta"


def test_prewrapped_perk_desc_uses_cache(mocker) -> None:
    menu = PerkMenuController()
    calls = {"count": 0}

    def _fake_measure(_font, text: str, _scale: float) -> float:
        calls["count"] += 1
        return float(len(text))

    mocker.patch.object(perk_menu_controller_module, "measure_small_text_width", side_effect=_fake_measure)
    mocker.patch.object(
        perk_menu_controller_module,
        "perk_display_description",
        side_effect=lambda _perk_id, *, fx_toggle=0, preserve_bugs=False: "alpha beta gamma",
    )

    first = menu._prewrapped_perk_desc(5, object(), fx_toggle=0, preserve_bugs=False)  # type: ignore[arg-type]
    count_after_first = calls["count"]
    second = menu._prewrapped_perk_desc(5, object(), fx_toggle=0, preserve_bugs=False)  # type: ignore[arg-type]

    assert first == second
    assert calls["count"] == count_after_first
