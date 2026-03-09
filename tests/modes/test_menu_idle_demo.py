from __future__ import annotations

from types import SimpleNamespace

from crimson.screens.chrome.controls import MenuEntry
from crimson.screens.chrome.geometry import MENU_DEMO_IDLE_START_MS
from crimson.screens.menu import MenuView


def test_menu_demo_idle_starts_demo(mocker, make_game_state) -> None:
    import crimson.screens.menu as menu_mod

    state = make_game_state(demo_enabled=True)
    state.resources = SimpleNamespace()
    view = MenuView(state)
    view._chrome.is_open = True
    view._menu_entries = [MenuEntry(slot=0, row=1, y=0.0)]
    view._chrome_state.timeline_max_ms = 0
    view._chrome_state.timeline_ms = 0
    view._list_state.idle_ms = MENU_DEMO_IDLE_START_MS

    mocker.patch.object(MenuView, "_hovered_entry_index", return_value=None)
    mocker.patch.object(menu_mod.rl, "is_key_pressed", return_value=False)
    mocker.patch.object(menu_mod.rl, "is_key_down", return_value=False)

    view.update(0.0)
    assert view._chrome_state.closing is True

    view.update(0.1)
    assert view.take_action() == "start_demo"


def test_menu_idle_does_not_start_demo_in_full_version(mocker, make_game_state) -> None:
    import crimson.screens.menu as menu_mod

    state = make_game_state(demo_enabled=False)
    state.resources = SimpleNamespace()
    view = MenuView(state)
    view._chrome.is_open = True
    view._menu_entries = [MenuEntry(slot=0, row=1, y=0.0)]
    view._chrome_state.timeline_max_ms = 0
    view._chrome_state.timeline_ms = 0
    view._list_state.idle_ms = MENU_DEMO_IDLE_START_MS

    mocker.patch.object(MenuView, "_hovered_entry_index", return_value=None)
    mocker.patch.object(menu_mod.rl, "is_key_pressed", return_value=False)
    mocker.patch.object(menu_mod.rl, "is_key_down", return_value=False)

    view.update(0.0)
    assert view.take_action() is None
    assert view._chrome_state.closing is False


def test_menu_idle_resets_on_key_press(mocker, make_game_state) -> None:
    import crimson.screens.menu as menu_mod

    state = make_game_state(demo_enabled=True)
    state.resources = SimpleNamespace()
    view = MenuView(state)
    view._chrome.is_open = True
    view._menu_entries = [MenuEntry(slot=0, row=1, y=0.0)]
    view._chrome_state.timeline_max_ms = 0
    view._chrome_state.timeline_ms = 0
    view._list_state.idle_ms = 1234

    mocker.patch.object(MenuView, "_hovered_entry_index", return_value=None)
    mocker.patch.object(menu_mod.rl, "get_mouse_position", return_value=SimpleNamespace(x=0.0, y=0.0))
    mocker.patch.object(menu_mod.rl, "get_key_pressed", return_value=1)
    mocker.patch.object(menu_mod.rl, "is_mouse_button_pressed", return_value=False)
    mocker.patch.object(menu_mod.rl, "is_key_pressed", return_value=False)
    mocker.patch.object(menu_mod.rl, "is_key_down", return_value=False)

    view.update(0.1)
    assert view._list_state.idle_ms == 0
