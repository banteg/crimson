from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import crimson.modes.replay_playback_mode as replay_playback_mode
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
