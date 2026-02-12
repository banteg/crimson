from __future__ import annotations

from pathlib import Path
import random
import time
from typing import Any, cast

import pyray as rl

from crimson.game import GameLoopView, GameState
from crimson.frontend.menu import ensure_menu_ground
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer


class _GroundSourceView:
    def __init__(self, ground: GroundRenderer | None, camera: Vec2 | None = None) -> None:
        self._ground = ground
        self._camera = camera

    def steal_ground_for_menu(self) -> GroundRenderer | None:
        ground = self._ground
        self._ground = None
        return ground

    def menu_ground_camera(self) -> Vec2 | None:
        return self._camera


class _TextureCacheStub:
    def texture(self, _name: str) -> rl.Texture:
        return cast(rl.Texture, rl.Texture())


class _TerrainTextureCacheStub:
    def __init__(self) -> None:
        self._textures = {
            "ter_q1_base": cast(rl.Texture, object()),
            "ter_q1_tex1": cast(rl.Texture, object()),
            "ter_q2_base": cast(rl.Texture, object()),
            "ter_q2_tex1": cast(rl.Texture, object()),
            "ter_q3_base": cast(rl.Texture, object()),
            "ter_q3_tex1": cast(rl.Texture, object()),
            "ter_q4_base": cast(rl.Texture, object()),
            "ter_q4_tex1": cast(rl.Texture, object()),
        }

    def texture(self, name: str) -> rl.Texture | None:
        return self._textures.get(name)


class _RngStub:
    def __init__(self, values: list[int]) -> None:
        self._values = list(values)

    def randrange(self, start: int, stop: int | None = None) -> int:
        if stop is None:
            stop = start
            start = 0
        if not self._values:
            raise AssertionError("rng stub exhausted")
        value = int(self._values.pop(0))
        if not (int(start) <= value < int(stop)):
            raise AssertionError(f"stub value {value} outside range [{start}, {stop})")
        return value


class _AdoptMenuGroundView:
    def __init__(self) -> None:
        self.adopted: GroundRenderer | None = None

    def adopt_menu_ground(self, ground: GroundRenderer | None) -> None:
        self.adopted = ground


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
    gameplay_camera = Vec2(-321.25, -456.5)
    gameplay_view = _GroundSourceView(gameplay_ground, gameplay_camera)

    state.menu_ground = menu_ground
    state.menu_ground_camera = Vec2(-1.0, -1.0)
    loop._front_active = gameplay_view
    loop._front_stack = []
    loop._gameplay_views = frozenset({gameplay_view})

    loop._capture_gameplay_ground_for_menu()

    assert state.menu_ground is gameplay_ground
    assert state.menu_ground_camera == gameplay_camera
    assert gameplay_view.steal_ground_for_menu() is None


def test_capture_gameplay_ground_from_stacked_view(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)

    menu_ground = GroundRenderer(texture=rl.Texture())
    gameplay_ground = GroundRenderer(texture=rl.Texture())
    gameplay_camera = Vec2(-611.0, -322.0)
    gameplay_view = _GroundSourceView(gameplay_ground, gameplay_camera)
    overlay_view = object()

    state.menu_ground = menu_ground
    state.menu_ground_camera = Vec2(-1.0, -1.0)
    loop._front_active = overlay_view
    loop._front_stack = [gameplay_view]
    loop._gameplay_views = frozenset({gameplay_view})

    loop._capture_gameplay_ground_for_menu()

    assert state.menu_ground is gameplay_ground
    assert state.menu_ground_camera == gameplay_camera
    assert gameplay_view.steal_ground_for_menu() is None


def test_regenerate_menu_ground_resets_menu_camera(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.texture_cache = cast(Any, _TextureCacheStub())
    state.menu_ground_camera = Vec2(-100.0, -200.0)

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert state.menu_ground_camera is None


def test_regenerate_menu_ground_unlock_branch_selects_q4_variant(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    cache = _TerrainTextureCacheStub()
    state.texture_cache = cast(Any, cache)
    state.status.quest_unlock_index = 0x28
    # unlock>=40 and first (rand & 7)==3 should pick (6,7,6) i.e. q4 base/tex1/base.
    state.rng = cast(random.Random, _RngStub([3, 1234]))

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert ground.texture is cache.texture("ter_q4_base")
    assert ground.overlay is cache.texture("ter_q4_tex1")
    assert ground.overlay_detail is cache.texture("ter_q4_base")


def test_start_survival_does_not_adopt_existing_menu_ground(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)
    menu_ground = GroundRenderer(texture=rl.Texture())
    adopter = _AdoptMenuGroundView()
    state.menu_ground = menu_ground

    loop._maybe_adopt_menu_ground("start_survival", cast(Any, adopter))

    assert adopter.adopted is None
