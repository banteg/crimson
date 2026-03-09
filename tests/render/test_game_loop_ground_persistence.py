from __future__ import annotations

import time
from pathlib import Path
from typing import cast

from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.persistence import save_status
from crimson.screens.chrome.runtime import ensure_menu_ground
from grim.assets import RuntimeResources, TextureId
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.gameplay_screen import GameplayScreenStub


class _ResourcesStub:
    def __init__(self) -> None:
        self._textures = {
            TextureId.TER_Q1_BASE: rl.Texture(),
            TextureId.TER_Q1_OVERLAY: rl.Texture(),
            TextureId.TER_Q2_BASE: rl.Texture(),
            TextureId.TER_Q2_OVERLAY: rl.Texture(),
            TextureId.TER_Q3_BASE: rl.Texture(),
            TextureId.TER_Q3_OVERLAY: rl.Texture(),
            TextureId.TER_Q4_BASE: rl.Texture(),
            TextureId.TER_Q4_OVERLAY: rl.Texture(),
        }

    def texture(self, texture_id: TextureId) -> rl.Texture | None:
        return self._textures.get(texture_id)


class _RngStub(Crand):
    def __init__(self, values: list[int]) -> None:
        super().__init__(0)
        self._values = list(values)

    def rand(self) -> int:
        if not self._values:
            return 0
        return int(self._values.pop(0))


class _AdoptMenuGroundView:
    def __init__(self) -> None:
        self.adopted: GroundRenderer | None = None

    def adopt_menu_ground(self, ground: GroundRenderer | None) -> None:
        self.adopted = ground

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def update(self, dt: float) -> None:
        _ = dt
        return None

    def draw(self) -> None:
        return None

    def take_action(self) -> str | None:
        return None


class _OverlayView:
    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def update(self, dt: float) -> None:
        _ = dt
        return None

    def draw(self) -> None:
        return None

    def take_action(self) -> str | None:
        return None


def _build_state(tmp_path: Path) -> GameState:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=Crand(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        resources=None,
        audio=None,
        session_start=time.monotonic(),
    )


def test_capture_gameplay_ground_from_active_view(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)

    menu_ground = GroundRenderer(texture=rl.Texture())
    gameplay_ground = GroundRenderer(texture=rl.Texture())
    gameplay_camera = Vec2(-321.25, -456.5)
    gameplay_view = GameplayScreenStub(ground=gameplay_ground, camera=gameplay_camera)

    state.menu_ground = menu_ground
    state.menu_ground_camera = Vec2(-1.0, -1.0)
    loop._front_active = gameplay_view
    loop._front_stack = []

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
    gameplay_view = GameplayScreenStub(ground=gameplay_ground, camera=gameplay_camera)
    overlay_view = _OverlayView()

    state.menu_ground = menu_ground
    state.menu_ground_camera = Vec2(-1.0, -1.0)
    loop._front_active = overlay_view
    loop._front_stack = [gameplay_view]

    loop._capture_gameplay_ground_for_menu()

    assert state.menu_ground is gameplay_ground
    assert state.menu_ground_camera == gameplay_camera
    assert gameplay_view.steal_ground_for_menu() is None


def test_regenerate_menu_ground_resets_menu_camera(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.resources = cast(RuntimeResources, _ResourcesStub())
    state.menu_ground_camera = Vec2(-100.0, -200.0)

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert state.menu_ground_camera is None


def test_regenerate_menu_ground_unlock_branch_selects_q4_variant(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    resources = _ResourcesStub()
    state.resources = cast(RuntimeResources, resources)
    state.status.quest_unlock_index = 0x28
    # unlock>=40 and first (rand & 7)==3 should pick (6,7,6) i.e. q4 base/tex1/base.
    # Remaining draws are consumed by terrain stamping and can be arbitrary.
    state.rng = _RngStub([3, 1234])

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert ground.texture is resources.texture(TextureId.TER_Q4_BASE)
    assert ground.overlay is resources.texture(TextureId.TER_Q4_OVERLAY)
    assert ground.overlay_detail is resources.texture(TextureId.TER_Q4_BASE)


def test_start_survival_does_not_adopt_existing_menu_ground(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)
    menu_ground = GroundRenderer(texture=rl.Texture())
    adopter = _AdoptMenuGroundView()
    state.menu_ground = menu_ground

    loop._maybe_adopt_menu_ground("start_survival", adopter)

    assert adopter.adopted is None
