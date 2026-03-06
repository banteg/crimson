from __future__ import annotations

import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.game_modes import GameMode
from crimson.persistence import save_status
from crimson.screens.menu import ensure_menu_ground
from grim.assets import PaqTextureCache
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer


class _GameplayScreenStub:
    close_requested = False
    default_game_mode_id = GameMode.SURVIVAL

    def bind_status(self, status) -> None:
        _ = status

    def bind_screen_fade(self, fade) -> None:
        _ = fade

    def bind_audio(self, audio, audio_rng) -> None:
        _ = (audio, audio_rng)

    def set_lan_runtime(
        self,
        *,
        enabled: bool,
        role: str,
        expected_players: int,
        connected_players: int,
        waiting_for_players: bool,
    ) -> None:
        _ = (enabled, role, expected_players, connected_players, waiting_for_players)

    def bind_lan_runtime(self, runtime) -> None:
        _ = runtime

    def set_lan_match_start(self, *, seed: int, start_tick: int = 0, status_snapshot=None) -> None:
        _ = (seed, start_tick, status_snapshot)

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        _ = entity_alpha

    def console_elapsed_ms(self) -> float:
        return 0.0

    def regenerate_terrain_for_console(self) -> None:
        return None

    def set_rtx_mode(self, mode) -> None:
        _ = mode

    def set_runtime_updates_per_frame(self, value: int) -> None:
        _ = value

    def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
        return (0, 0, 0, 0.0, 0.0, 0.0)


class _GroundSourceView(_GameplayScreenStub):
    def __init__(self, ground: GroundRenderer | None, camera: Vec2 | None = None) -> None:
        self._ground = ground
        self._camera = camera

    def steal_ground_for_menu(self) -> GroundRenderer | None:
        ground = self._ground
        self._ground = None
        return ground

    def menu_ground_camera(self) -> Vec2 | None:
        return self._camera

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


@dataclass(slots=True)
class _TextureAssetStub:
    texture: rl.Texture | None


class _TextureCacheStub:
    def __init__(self) -> None:
        self._asset = _TextureAssetStub(texture=rl.Texture())

    def texture(self, name: str) -> rl.Texture:
        _ = name
        texture = self._asset.texture
        if texture is None:
            raise AssertionError("texture should be available in this stub")
        return texture

    def get_or_load(self, name: str, rel_path: str) -> _TextureAssetStub:
        _ = (name, rel_path)
        return self._asset


class _TerrainTextureCacheStub:
    def __init__(self) -> None:
        self._textures = {
            "ter_q1_base": rl.Texture(),
            "ter_q1_tex1": rl.Texture(),
            "ter_q2_base": rl.Texture(),
            "ter_q2_tex1": rl.Texture(),
            "ter_q3_base": rl.Texture(),
            "ter_q3_tex1": rl.Texture(),
            "ter_q4_base": rl.Texture(),
            "ter_q4_tex1": rl.Texture(),
        }

    def texture(self, name: str) -> rl.Texture | None:
        return self._textures.get(name)

    def get_or_load(self, name: str, rel_path: str) -> _TextureAssetStub:
        _ = rel_path
        return _TextureAssetStub(texture=self._textures.get(name))


class _RngStub(random.Random):
    def __init__(self, values: list[int]) -> None:
        super().__init__(0)
        self._values = list(values)

    def randrange(self, start: int, stop: int | None = None, step: int = 1) -> int:
        if int(step) != 1:
            raise AssertionError("rng stub only supports step=1")
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
    state.texture_cache = cast(PaqTextureCache, _TextureCacheStub())
    state.menu_ground_camera = Vec2(-100.0, -200.0)

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert state.menu_ground_camera is None


def test_regenerate_menu_ground_unlock_branch_selects_q4_variant(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    cache = _TerrainTextureCacheStub()
    state.texture_cache = cast(PaqTextureCache, cache)
    state.status.quest_unlock_index = 0x28
    # unlock>=40 and first (rand & 7)==3 should pick (6,7,6) i.e. q4 base/tex1/base.
    state.rng = _RngStub([3, 1234])

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

    loop._maybe_adopt_menu_ground("start_survival", adopter)

    assert adopter.adopted is None
