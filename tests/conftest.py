from __future__ import annotations

import sys
from pathlib import Path


def pytest_configure() -> None:
    # Ensure the local `src/` tree wins over any other editable install that may exist
    # (e.g. a different git worktree pointing at the same project).
    src_dir = Path(__file__).resolve().parents[1] / "src"
    sys.path.insert(0, str(src_dir))

