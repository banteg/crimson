from __future__ import annotations

from pathlib import Path
import random
import time

import pyray as rl

from crimson.game import GameLoopView, GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.terrain_render import GroundRenderer


class _GroundSourceView:
    def __init__(self, ground: GroundRenderer | None) -> None:
        self._ground = ground

    def steal_ground_for_menu(self) -> GroundRenderer | None:
        ground = self._ground
        self._ground = None
        return ground


def _build_state(tmp_path: Path) -> GameState:
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


def test_capture_gameplay_ground_from_active_view(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)

    menu_ground = GroundRenderer(texture=rl.Texture())
    gameplay_ground = GroundRenderer(texture=rl.Texture())
    gameplay_view = _GroundSourceView(gameplay_ground)

    state.menu_ground = menu_ground
    loop._front_active = gameplay_view
    loop._front_stack = []
    loop._gameplay_views = frozenset({gameplay_view})

    loop._capture_gameplay_ground_for_menu()

    assert state.menu_ground is gameplay_ground
    assert gameplay_view.steal_ground_for_menu() is None


def test_capture_gameplay_ground_from_stacked_view(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)

    menu_ground = GroundRenderer(texture=rl.Texture())
    gameplay_ground = GroundRenderer(texture=rl.Texture())
    gameplay_view = _GroundSourceView(gameplay_ground)
    overlay_view = object()

    state.menu_ground = menu_ground
    loop._front_active = overlay_view
    loop._front_stack = [gameplay_view]
    loop._gameplay_views = frozenset({gameplay_view})

    loop._capture_gameplay_ground_for_menu()

    assert state.menu_ground is gameplay_ground
    assert gameplay_view.steal_ground_for_menu() is None
