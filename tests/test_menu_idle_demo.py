from __future__ import annotations

from types import SimpleNamespace

from crimson.frontend.menu import MENU_DEMO_IDLE_START_MS, MenuEntry, MenuView


def test_menu_demo_idle_starts_demo(monkeypatch, make_game_state) -> None:
    import crimson.frontend.menu as menu_mod

    state = make_game_state(demo_enabled=True)
    view = MenuView(state)
    view._is_open = True
    view._menu_entries = [MenuEntry(slot=0, row=1, y=0.0)]
    view._timeline_max_ms = 0
    view._timeline_ms = 0
    view._idle_ms = MENU_DEMO_IDLE_START_MS

    monkeypatch.setattr(MenuView, "_hovered_entry_index", lambda self: None)
    monkeypatch.setattr(menu_mod.rl, "is_key_pressed", lambda _key: False)
    monkeypatch.setattr(menu_mod.rl, "is_key_down", lambda _key: False)

    view.update(0.0)
    assert view._closing is True

    view.update(0.1)
    assert view.take_action() == "start_demo"


def test_menu_idle_does_not_start_demo_in_full_version(monkeypatch, make_game_state) -> None:
    import crimson.frontend.menu as menu_mod

    state = make_game_state(demo_enabled=False)
    view = MenuView(state)
    view._is_open = True
    view._menu_entries = [MenuEntry(slot=0, row=1, y=0.0)]
    view._timeline_max_ms = 0
    view._timeline_ms = 0
    view._idle_ms = MENU_DEMO_IDLE_START_MS

    monkeypatch.setattr(MenuView, "_hovered_entry_index", lambda self: None)
    monkeypatch.setattr(menu_mod.rl, "is_key_pressed", lambda _key: False)
    monkeypatch.setattr(menu_mod.rl, "is_key_down", lambda _key: False)

    view.update(0.0)
    assert view.take_action() is None
    assert view._closing is False


def test_menu_idle_resets_on_key_press(monkeypatch, make_game_state) -> None:
    import crimson.frontend.menu as menu_mod

    state = make_game_state(demo_enabled=True)
    view = MenuView(state)
    view._is_open = True
    view._menu_entries = [MenuEntry(slot=0, row=1, y=0.0)]
    view._timeline_max_ms = 0
    view._timeline_ms = 0
    view._idle_ms = 1234

    monkeypatch.setattr(MenuView, "_hovered_entry_index", lambda self: None)
    monkeypatch.setattr(menu_mod.rl, "get_mouse_position", lambda: SimpleNamespace(x=0.0, y=0.0))
    monkeypatch.setattr(menu_mod.rl, "get_key_pressed", lambda: 1)
    monkeypatch.setattr(menu_mod.rl, "is_mouse_button_pressed", lambda _button: False)
    monkeypatch.setattr(menu_mod.rl, "is_key_pressed", lambda _key: False)
    monkeypatch.setattr(menu_mod.rl, "is_key_down", lambda _key: False)

    view.update(0.1)
    assert view._idle_ms == 0
