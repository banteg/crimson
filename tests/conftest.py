from __future__ import annotations

import random
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import pyray as rl

    import crimson.modes.replay_playback_mode as replay_playback_mode
    from crimson.game.types import GameState
    from crimson.persistence.save_status import GameStatus
    from crimson.sim.world_state import WorldState
    from grim.audio import AudioState
    from grim.console import ConsoleState


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-terrain",
        action="store_true",
        default=False,
        help="run terrain generation/render parity tests",
    )


def pytest_configure(config: pytest.Config) -> None:
    # Ensure the local `src/` tree wins over any other editable install that may exist
    # (e.g. a different git worktree pointing at the same project).
    src_dir = Path(__file__).resolve().parents[1] / "src"
    src_str = str(src_dir)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
    config.addinivalue_line("markers", "terrain: terrain generation/rendering tests (slow, opt-in)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-terrain"):
        return
    skip_terrain = pytest.mark.skip(reason="use --run-terrain to run terrain generation/rendering tests")
    for item in items:
        if "terrain" in item.keywords:
            item.add_marker(skip_terrain)


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
            rng=random.Random(int(rng_seed)),
            config=cfg,
            status=game_status,
            console=create_console(resolved_base_dir, assets_dir=resolved_assets_dir),
            demo_enabled=bool(demo_enabled),
            preserve_bugs=bool(preserve_bugs),
            logos=None,
            texture_cache=None,
            audio=audio,
            resource_paq=resolved_assets_dir / "crimson.paq",
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
        difficulty_level: int = 0,
        preserve_bugs: bool = False,
        with_player: bool = True,
        player_index: int = 0,
        player_pos: Vec2 | None = None,
    ) -> WorldState:
        world = WorldState.build(
            world_size=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            hardcore=bool(hardcore),
            difficulty_level=int(difficulty_level),
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
def patch_raylib_module(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    import pyray as rl

    def _patch(
        module: str,
        *,
        screen_width: int = 640,
        screen_height: int = 480,
        mouse_pos: "rl.Vector2 | None" = None,
        is_key_pressed: Callable[[object], bool] | None = None,
    ) -> None:
        default_mouse = mouse_pos if mouse_pos is not None else rl.Vector2(0.0, 0.0)
        key_handler = is_key_pressed if is_key_pressed is not None else (lambda _key: False)

        monkeypatch.setattr(f"{module}.rl.get_screen_width", lambda: int(screen_width), raising=False)
        monkeypatch.setattr(f"{module}.rl.get_screen_height", lambda: int(screen_height), raising=False)
        monkeypatch.setattr(f"{module}.rl.get_mouse_position", lambda: default_mouse, raising=False)
        monkeypatch.setattr(f"{module}.rl.is_mouse_button_pressed", lambda _button: False, raising=False)
        monkeypatch.setattr(f"{module}.rl.check_collision_point_rec", lambda _pos, _rect: False, raising=False)
        monkeypatch.setattr(f"{module}.rl.is_key_pressed", key_handler, raising=False)

    return _patch
