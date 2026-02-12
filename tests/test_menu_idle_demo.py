from __future__ import annotations

from pathlib import Path
import random
import time
from types import SimpleNamespace

from crimson.frontend.menu import MENU_DEMO_IDLE_START_MS, MenuEntry, MenuView
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _make_state(*, tmp_path: Path, demo_enabled: bool) -> GameState:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=demo_enabled,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_menu_demo_idle_starts_demo(monkeypatch, tmp_path: Path) -> None:
    import crimson.frontend.menu as menu_mod

    state = _make_state(tmp_path=tmp_path, demo_enabled=True)
    view = MenuView(state)
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


def test_menu_idle_does_not_start_demo_in_full_version(monkeypatch, tmp_path: Path) -> None:
    import crimson.frontend.menu as menu_mod

    state = _make_state(tmp_path=tmp_path, demo_enabled=False)
    view = MenuView(state)
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


def test_menu_idle_resets_on_key_press(monkeypatch, tmp_path: Path) -> None:
    import crimson.frontend.menu as menu_mod

    state = _make_state(tmp_path=tmp_path, demo_enabled=True)
    view = MenuView(state)
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
