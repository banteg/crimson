from __future__ import annotations

import time
from pathlib import Path
from typing import cast

from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.persistence import save_status
from crimson.screens.chrome import ensure_menu_ground
from crimson.screens.stack import ScreenEntry
from crimson.sim.bootstrap import advance_unlock_terrain
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

    def _next(self) -> int:
        if not self._values:
            return 0
        return int(self._values.pop(0))

    def rand(self) -> int:
        return self._next()

    def rand_tagged(self, caller: int) -> int:
        _ = caller
        return self._next()


class _OverlayView:
    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def update(self, dt: float) -> None:
        _ = dt

    def draw(self) -> None:
        return None

    def take_action(self) -> None:
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

    menu_texture = rl.Texture()
    gameplay_texture = rl.Texture()
    menu_ground = GroundRenderer(texture=menu_texture, overlay=menu_texture, overlay_detail=menu_texture)
    gameplay_ground = GroundRenderer(
        texture=gameplay_texture,
        overlay=gameplay_texture,
        overlay_detail=gameplay_texture,
    )
    gameplay_camera = Vec2(-321.25, -456.5)
    gameplay_view = GameplayScreenStub(ground=gameplay_ground, camera=gameplay_camera)

    state.menu_ground = menu_ground
    state.menu_ground_camera = Vec2(-1.0, -1.0)
    state.screens.push(ScreenEntry(gameplay_view, resume=gameplay_view.resume, gameplay=gameplay_view))

    loop.navigation.capture_ground()

    assert state.menu_ground is gameplay_ground
    assert state.menu_ground_camera == gameplay_camera
    assert gameplay_view.steal_ground_for_menu() is None


def test_capture_gameplay_ground_from_stacked_view(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)

    menu_texture = rl.Texture()
    gameplay_texture = rl.Texture()
    menu_ground = GroundRenderer(texture=menu_texture, overlay=menu_texture, overlay_detail=menu_texture)
    gameplay_ground = GroundRenderer(
        texture=gameplay_texture,
        overlay=gameplay_texture,
        overlay_detail=gameplay_texture,
    )
    gameplay_camera = Vec2(-611.0, -322.0)
    gameplay_view = GameplayScreenStub(ground=gameplay_ground, camera=gameplay_camera)
    overlay_view = _OverlayView()

    state.menu_ground = menu_ground
    state.menu_ground_camera = Vec2(-1.0, -1.0)
    state.screens.push(ScreenEntry(gameplay_view, resume=gameplay_view.resume, gameplay=gameplay_view))
    state.screens.push(ScreenEntry(overlay_view))

    loop.navigation.capture_ground()

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
    # terrain_generate_random() burns three hidden prelude draws before the
    # unlock-gated variant rolls. The fourth draw is the Q4 unlock branch gate.
    # Remaining draws are consumed by terrain stamping and can be arbitrary.
    state.rng = _RngStub([0, 0, 0, 3, 1234])

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert ground.texture is resources.texture(TextureId.TER_Q4_BASE)
    assert ground.overlay is resources.texture(TextureId.TER_Q4_OVERLAY)
    assert ground.overlay_detail is resources.texture(TextureId.TER_Q4_BASE)


def test_regenerate_menu_ground_uses_mutated_app_rng_and_schedules_terrain_seed(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.resources = cast(RuntimeResources, _ResourcesStub())
    state.status.quest_unlock_index = 0x28
    state.rng.srand(0x1234)
    expected_rng = Crand(int(state.rng.state))
    expected_terrain = advance_unlock_terrain(
        expected_rng,
        unlock_index=int(state.status.quest_unlock_index),
        width=1024,
        height=1024,
    )

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert int(ground._scheduled_seed or -1) == int(expected_terrain.terrain_seed)
    assert int(state.rng.state) == int(expected_rng.state)


def test_existing_menu_ground_ignores_runtime_texture_scale_changes(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.resources = cast(RuntimeResources, _ResourcesStub())

    ground = ensure_menu_ground(state, regenerate=True)
    state.menu_ground_camera = Vec2(-100.0, -200.0)
    before_rng_state = int(state.rng.state)
    before_seed = int(ground._scheduled_seed or -1)

    state.config.display.texture_scale = 0.5

    same_ground = ensure_menu_ground(state)

    assert same_ground is ground
    assert float(same_ground.texture_scale) == 1.0
    assert int(same_ground._scheduled_seed or -1) == before_seed
    assert int(state.rng.state) == before_rng_state
    assert state.menu_ground_camera == Vec2(-100.0, -200.0)
