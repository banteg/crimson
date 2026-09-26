"""Opt-in differential tests against the original executable run under Unicorn.

Run with `CRIMSON_NATIVE_ORACLE=1 uv run pytest tests/native_oracle` (outside the
command sandbox: Unicorn's JIT is killed inside it). The executable lives under
the gitignored `game_bins/`.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

_EXE = Path(__file__).resolve().parents[2] / "game_bins" / "crimsonland" / "1.9.93-gog" / "crimsonland.exe"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    reason = None
    if not os.environ.get("CRIMSON_NATIVE_ORACLE"):
        reason = "set CRIMSON_NATIVE_ORACLE=1 to run native-oracle differential tests"
    elif importlib.util.find_spec("unicorn") is None:
        reason = "unicorn is not installed (uv sync --dev)"
    elif not _EXE.is_file():
        reason = f"original executable missing: {_EXE}"
    if reason is None:
        return
    here = Path(__file__).resolve().parent
    for item in items:
        if here in item.path.resolve().parents:
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture
def oracle():
    """A fresh oracle with the game's static initializers run (CRT stdio/locale ones trap and are skipped)."""

    from crimson.dbg.native_oracle import NativeOracle

    oracle = NativeOracle(_EXE)
    oracle.run_static_initializers()
    return oracle
