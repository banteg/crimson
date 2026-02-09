from __future__ import annotations

import sys
from pathlib import Path

import pytest


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
