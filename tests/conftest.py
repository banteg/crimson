from __future__ import annotations

import importlib
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

import msgspec
import pytest
from pytest_mock import MockerFixture

from grim.rand import Crand

TESTS_ROOT = Path(__file__).resolve().parent
_TEST_RUNTIME_DIR: Path | None = None
_PREV_CRIMSON_RUNTIME_DIR: str | None = None
_PREV_CRIMSON_BASE_DIR: str | None = None

if TYPE_CHECKING:
    import crimson.modes.replay_playback_mode as replay_playback_mode
    from crimson.game.types import GameState
    from crimson.persistence.save_status import GameStatus
    from crimson.sim.world_state import WorldState
    from grim.audio import AudioState
    from grim.console import ConsoleState
    from grim.raylib_api import rl


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-terrain",
        action="store_true",
        default=False,
        help="run terrain generation/render parity tests",
    )
    parser.addoption(
        "--run-replay-fixtures",
        action="store_true",
        default=False,
        help="run replay fixture integration tests",
    )


def pytest_configure(config: pytest.Config) -> None:
    global _PREV_CRIMSON_RUNTIME_DIR, _PREV_CRIMSON_BASE_DIR, _TEST_RUNTIME_DIR

    _PREV_CRIMSON_RUNTIME_DIR = os.environ.get("CRIMSON_RUNTIME_DIR")
    _PREV_CRIMSON_BASE_DIR = os.environ.get("CRIMSON_BASE_DIR")
    _TEST_RUNTIME_DIR = Path(tempfile.mkdtemp(prefix="crimson-runtime-tests-")).resolve()
    os.environ["CRIMSON_RUNTIME_DIR"] = str(_TEST_RUNTIME_DIR)

    # Ensure the local `src/` tree wins over any other editable install that may exist
    # (e.g. a different git worktree pointing at the same project).
    src_dir = Path(__file__).resolve().parents[1] / "src"
    src_str = str(src_dir)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
    tests_dir = str(TESTS_ROOT)
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    config.addinivalue_line("markers", "terrain: terrain generation/rendering tests (slow, opt-in)")
    config.addinivalue_line("markers", "slow: long-running test")
    config.addinivalue_line("markers", "original_capture: tests for original-capture conversion/replay/parity")
    config.addinivalue_line("markers", "network: network/lan/relay integration tests")
    config.addinivalue_line("markers", "replay_fixture: replay fixture integration tests (slow, opt-in)")


def pytest_unconfigure(config: pytest.Config) -> None:
    _ = config
    global _PREV_CRIMSON_RUNTIME_DIR, _PREV_CRIMSON_BASE_DIR, _TEST_RUNTIME_DIR

    if _PREV_CRIMSON_RUNTIME_DIR is None:
        os.environ.pop("CRIMSON_RUNTIME_DIR", None)
    else:
        os.environ["CRIMSON_RUNTIME_DIR"] = _PREV_CRIMSON_RUNTIME_DIR

    if _PREV_CRIMSON_BASE_DIR is None:
        os.environ.pop("CRIMSON_BASE_DIR", None)
    else:
        os.environ["CRIMSON_BASE_DIR"] = _PREV_CRIMSON_BASE_DIR

    if _TEST_RUNTIME_DIR is not None:
        shutil.rmtree(_TEST_RUNTIME_DIR, ignore_errors=True)

    _PREV_CRIMSON_RUNTIME_DIR = None
    _PREV_CRIMSON_BASE_DIR = None
    _TEST_RUNTIME_DIR = None


def _test_relative_path(item: pytest.Item) -> Path:
    try:
        return item.path.resolve().relative_to(TESTS_ROOT)
    except ValueError:
        return item.path


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        relative_path = _test_relative_path(item)
        file_name = relative_path.name
        top_level_dir = relative_path.parts[0] if relative_path.parts else ""

        if top_level_dir == "original_capture" or file_name.startswith("test_original_capture_"):
            item.add_marker(pytest.mark.original_capture)
            item.add_marker(pytest.mark.slow)
        if top_level_dir == "net":
            item.add_marker(pytest.mark.network)
            item.add_marker(pytest.mark.slow)
        if "terrain" in item.keywords:
            item.add_marker(pytest.mark.slow)

    if config.getoption("--run-terrain"):
        skip_terrain = None
    else:
        skip_terrain = pytest.mark.skip(reason="use --run-terrain to run terrain generation/rendering tests")

    if config.getoption("--run-replay-fixtures"):
        skip_replay_fixtures = None
    else:
        skip_replay_fixtures = pytest.mark.skip(
            reason="use --run-replay-fixtures to run replay fixture integration tests",
        )

    for item in items:
        if skip_terrain is not None and "terrain" in item.keywords:
            item.add_marker(skip_terrain)
        if skip_replay_fixtures is not None and "replay_fixture" in item.keywords:
            item.add_marker(skip_replay_fixtures)


@pytest.fixture
def replay_playback_view() -> tuple["replay_playback_mode.ReplayPlaybackMode", "ConsoleState"]:
    import crimson.modes.replay_playback_mode as replay_playback_mode
    from grim.config import CrimsonConfig
    from grim.console import ConsoleLog, ConsoleState
    from grim.view import ViewContext

    cfg = CrimsonConfig(path=Path("crimson.cfg"), data={})
    console = ConsoleState(base_dir=Path("."), log=ConsoleLog(base_dir=Path(".")))
    view = replay_playback_mode.ReplayPlaybackMode(
        ViewContext(assets_dir=Path("."), preserve_bugs=False),
        replay_path=Path("dummy.crd"),
        config=cfg,
        console=console,
    )
    return view, console


@pytest.fixture
def assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


@pytest.fixture
def make_game_state(tmp_path: Path, assets_dir: Path) -> Callable[..., "GameState"]:
    from crimson.game.types import GameState
    from crimson.persistence import save_status
    from grim.config import ensure_crimson_cfg
    from grim.console import create_console

    def _make(
        *,
        base_dir: Path | None = None,
        assets_root: Path | None = None,
        rng_seed: int = 0,
        demo_enabled: bool = False,
        preserve_bugs: bool = False,
        status: "GameStatus | None" = None,
        audio: "AudioState | None" = None,
        config_updates: Mapping[str, object] | None = None,
        session_start: float | None = None,
        **state_overrides: object,
    ) -> GameState:
        resolved_base_dir = base_dir if base_dir is not None else tmp_path
        resolved_assets_dir = assets_root if assets_root is not None else assets_dir

        cfg = ensure_crimson_cfg(resolved_base_dir)
        if config_updates:
            cfg.data.update(dict(config_updates))

        game_status = status if status is not None else save_status.ensure_game_status(resolved_base_dir)
        state = GameState(
            base_dir=resolved_base_dir,
            assets_dir=resolved_assets_dir,
            rng=Crand(int(rng_seed)),
            config=cfg,
            status=game_status,
            console=create_console(resolved_base_dir, assets_dir=resolved_assets_dir),
            demo_enabled=bool(demo_enabled),
            preserve_bugs=bool(preserve_bugs),
            resources=None,
            audio=audio,
            session_start=time.monotonic() if session_start is None else float(session_start),
        )

        for field_name, value in state_overrides.items():
            if not hasattr(state, field_name):
                raise AttributeError(f"unknown GameState field: {field_name}")
            setattr(state, field_name, value)

        return state

    return _make


@pytest.fixture
def game_state(make_game_state: Callable[..., "GameState"]) -> "GameState":
    return make_game_state()


@pytest.fixture
def make_world_state() -> Callable[..., "WorldState"]:
    from crimson.sim.state_types import PlayerState
    from crimson.sim.world_state import WorldState
    from grim.geom import Vec2

    def _make(
        *,
        world_size: float = 1024.0,
        demo_mode_active: bool = False,
        hardcore: bool = False,
        quest_fail_retry_count: int = 0,
        preserve_bugs: bool = False,
        with_player: bool = True,
        player_index: int = 0,
        player_pos: Vec2 | None = None,
    ) -> WorldState:
        world = WorldState.build(
            world_size=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            hardcore=bool(hardcore),
            quest_fail_retry_count=int(quest_fail_retry_count),
            preserve_bugs=bool(preserve_bugs),
        )
        if with_player:
            pos = player_pos if player_pos is not None else Vec2(512.0, 512.0)
            world.players.append(PlayerState(index=int(player_index), pos=Vec2(float(pos.x), float(pos.y))))
        return world

    return _make


@pytest.fixture
def base_world(make_world_state: Callable[..., "WorldState"]) -> "WorldState":
    return make_world_state()


@pytest.fixture
def default_spawn_env():
    from crimson.creatures.spawn import SpawnEnv

    return SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )


@pytest.fixture
def make_spawn_env(default_spawn_env):
    def _make(**overrides: object):
        return msgspec.structs.replace(default_spawn_env, **overrides)

    return _make


@pytest.fixture
def patch_raylib_module(mocker: MockerFixture) -> Callable[..., None]:
    from grim.raylib_api import rl

    def _patch(
        module: str,
        *,
        screen_width: int = 640,
        screen_height: int = 480,
        mouse_pos: "rl.Vector2 | None" = None,
        is_key_pressed: Callable[[object], bool] | None = None,
    ) -> None:
        target_module = importlib.import_module(module)
        raylib_module = getattr(target_module, "rl")
        default_mouse = mouse_pos if mouse_pos is not None else rl.Vector2(0.0, 0.0)
        key_handler = is_key_pressed if is_key_pressed is not None else (lambda _key: False)

        if hasattr(raylib_module, "get_screen_width"):
            mocker.patch.object(raylib_module, "get_screen_width", side_effect=lambda: int(screen_width))
        if hasattr(raylib_module, "get_screen_height"):
            mocker.patch.object(raylib_module, "get_screen_height", side_effect=lambda: int(screen_height))
        if hasattr(raylib_module, "get_mouse_position"):
            mocker.patch.object(raylib_module, "get_mouse_position", side_effect=lambda: default_mouse)
        if hasattr(raylib_module, "is_mouse_button_pressed"):
            mocker.patch.object(raylib_module, "is_mouse_button_pressed", side_effect=lambda _button: False)
        if hasattr(raylib_module, "check_collision_point_rec"):
            mocker.patch.object(raylib_module, "check_collision_point_rec", side_effect=lambda _pos, _rect: False)
        if hasattr(raylib_module, "is_key_pressed"):
            mocker.patch.object(raylib_module, "is_key_pressed", side_effect=key_handler)

    return _patch
