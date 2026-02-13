from __future__ import annotations

from pathlib import Path
import random
import time

import crimson.game.loop_view as loop_view
from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _make_state(tmp_path: Path) -> GameState:
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
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_generateterrain_command_sets_regenerate_request(tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    handlers = _boot_command_handlers(state)

    assert state.terrain_regenerate_requested is False
    handlers["generateterrain"]([])
    assert state.terrain_regenerate_requested is True


def test_game_loop_consumes_terrain_regenerate_request(monkeypatch, tmp_path: Path) -> None:
    class _FakeView:
        called = 0

        def regenerate_terrain_for_console(self) -> None:
            self.called += 1

    calls: list[bool] = []

    def _fake_ensure_menu_ground(*_args, regenerate: bool = False, **_kwargs):
        calls.append(bool(regenerate))
        return None

    monkeypatch.setattr(loop_view, "ensure_menu_ground", _fake_ensure_menu_ground)

    state = _make_state(tmp_path)
    view = GameLoopView(state)
    fake = _FakeView()
    view._front_active = fake
    state.terrain_regenerate_requested = True

    view._handle_console_requests()

    assert state.terrain_regenerate_requested is False
    assert calls == [True]
    assert fake.called == 1
