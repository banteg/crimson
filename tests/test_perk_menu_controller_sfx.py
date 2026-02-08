from __future__ import annotations

from types import SimpleNamespace

import pyray as rl

from crimson.modes.components.perk_menu_controller import PerkMenuContext, PerkMenuController
from crimson.ui.perk_menu import PerkMenuAssets


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
        missing=[],
    )


def test_open_perk_menu_plays_panel_click(monkeypatch) -> None:
    menu = PerkMenuController()

    played: list[str] = []

    def _play_sfx(key: str) -> None:
        played.append(key)

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.perk_selection_current_choices", lambda *args, **kwargs: [1])

    ctx = PerkMenuContext(
        state=SimpleNamespace(),
        perk_state=SimpleNamespace(),
        players=[],
        creatures=[],
        player=SimpleNamespace(perk_counts=[0] * 128),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=_play_sfx,
    )

    assert menu.open is False
    assert menu.open_if_available(ctx) is True
    assert menu.open is True
    assert played == ["sfx_ui_panelclick"]


def test_perk_menu_pick_plays_button_click(monkeypatch) -> None:
    menu = PerkMenuController()
    menu.open = True

    played: list[str] = []

    def _play_sfx(key: str) -> None:
        played.append(key)

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.perk_selection_current_choices", lambda *args, **kwargs: [1])
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.perk_selection_pick", lambda *args, **kwargs: object())

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.button_update", lambda *args, **kwargs: False)  # noqa: ARG005
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.check_collision_point_rec", lambda _pos, _rect: False)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.measure_text", lambda _text, _size: 10)

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ENTER)

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.is_key_pressed", _is_key_pressed)

    ctx = PerkMenuContext(
        state=SimpleNamespace(),
        perk_state=SimpleNamespace(),
        players=[],
        creatures=[],
        player=SimpleNamespace(perk_counts=[0] * 128),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=_play_sfx,
    )

    menu.handle_input(ctx, dt_frame=0.0, dt_ui_ms=0.0)

    assert played == ["sfx_ui_buttonclick", "sfx_ui_bonus"]
    assert menu.open is False


def test_perk_menu_pick_invokes_on_pick(monkeypatch) -> None:
    picked_indices: list[int] = []

    def _on_pick(choice_index: int) -> None:
        picked_indices.append(int(choice_index))

    menu = PerkMenuController(on_pick=_on_pick)
    menu.open = True

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.perk_selection_current_choices", lambda *args, **kwargs: [1])
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.perk_selection_pick", lambda *args, **kwargs: object())

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.button_update", lambda *args, **kwargs: False)  # noqa: ARG005
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.check_collision_point_rec", lambda _pos, _rect: False)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.measure_text", lambda _text, _size: 10)

    def _is_key_pressed(key: int) -> bool:
        return int(key) == int(rl.KeyboardKey.KEY_ENTER)

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.is_key_pressed", _is_key_pressed)

    ctx = PerkMenuContext(
        state=SimpleNamespace(),
        perk_state=SimpleNamespace(),
        players=[],
        creatures=[],
        player=SimpleNamespace(perk_counts=[0] * 128),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=None,
    )

    menu.handle_input(ctx, dt_frame=0.0, dt_ui_ms=0.0)

    assert picked_indices == [0]


def test_perk_menu_cancel_plays_button_click(monkeypatch) -> None:
    menu = PerkMenuController()
    menu.open = True

    played: list[str] = []

    def _play_sfx(key: str) -> None:
        played.append(key)

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.perk_selection_current_choices", lambda *args, **kwargs: [1])

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.button_update", lambda *args, **kwargs: True)  # noqa: ARG005
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.get_screen_width", lambda: 640)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.get_screen_height", lambda: 480)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.check_collision_point_rec", lambda _pos, _rect: False)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.measure_text", lambda _text, _size: 10)
    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.rl.is_key_pressed", lambda _key: False)

    ctx = PerkMenuContext(
        state=SimpleNamespace(),
        perk_state=SimpleNamespace(),
        players=[],
        creatures=[],
        player=SimpleNamespace(perk_counts=[0] * 128),
        game_mode=1,
        player_count=1,
        fx_toggle=0,
        font=None,
        assets=_dummy_assets(),
        mouse=rl.Vector2(0.0, 0.0),
        play_sfx=_play_sfx,
    )

    menu.handle_input(ctx, dt_frame=0.0, dt_ui_ms=0.0)

    assert played == ["sfx_ui_buttonclick"]
    assert menu.open is False


def test_wrap_small_text_native_inserts_newline_at_previous_space(monkeypatch) -> None:
    menu = PerkMenuController()
    monkeypatch.setattr(
        "crimson.modes.components.perk_menu_controller.measure_small_text_width",
        lambda _font, text, _scale: float(len(text)),
    )
    wrapped = menu._wrap_small_text_native(object(), "alpha beta", 6.0, scale=1.0)  # type: ignore[arg-type]
    assert wrapped == "alpha\nbeta"


def test_prewrapped_perk_desc_uses_cache(monkeypatch) -> None:
    menu = PerkMenuController()
    calls = {"count": 0}

    def _fake_measure(_font, text: str, _scale: float) -> float:
        calls["count"] += 1
        return float(len(text))

    monkeypatch.setattr("crimson.modes.components.perk_menu_controller.measure_small_text_width", _fake_measure)
    monkeypatch.setattr(
        "crimson.modes.components.perk_menu_controller.perk_display_description",
        lambda _perk_id, *, fx_toggle=0: "alpha beta gamma",  # noqa: ARG005
    )

    first = menu._prewrapped_perk_desc(5, object(), fx_toggle=0)  # type: ignore[arg-type]
    count_after_first = calls["count"]
    second = menu._prewrapped_perk_desc(5, object(), fx_toggle=0)  # type: ignore[arg-type]

    assert first == second
    assert calls["count"] == count_after_first
