"""Replay encoding and compatibility, separate from the recording build's identity."""

from __future__ import annotations

import json
import runpy
from functools import lru_cache
from pathlib import Path

REPLAY_FORMAT_VERSION = 32
# Raised whenever a change makes earlier replays play differently. Content fingerprints
# identify builds; only rules decide compatibility (docs/rewrite/watch-replays.md).
REPLAY_RULES = 1


@lru_cache(maxsize=1)
def current_replay_game_version() -> str:
    """Identify Python sources/dependencies, without tying the label to a Git commit.

    A source checkout hashes its current inputs, including uncommitted/new files.
    A distribution carries the same identity in generated metadata, independent of
    Git or the directory it is installed in. Older distributions fall back to semver.
    """
    from . import __version__

    package = Path(__file__).resolve().parent
    root = package.parents[1]
    script = root / "scripts/build_identity.py"
    if package == root / "src/crimson" and script.is_file():
        build = runpy.run_path(str(script))["python_identity"](root)
        return str(build["version"])
    metadata = package / "_build.json"
    if metadata.is_file():
        return str(json.loads(metadata.read_text())["version"])
    return str(__version__)
