"""The version, replay format and rules this build of the port names.

Only the standard library: the recovered game's build compiles these in without importing the simulation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

REPLAY_FORMAT_VERSION = 32
# The simulation rules this build plays: raised whenever a change makes earlier replays play differently. A replay
# plays back only under the rules it was recorded under (docs/rewrite/watch-replays.md).
REPLAY_RULES = 1

_RELEASE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _head_points_at_release_tag(*, version: str, repo_root: Path, git_exe: str) -> bool:
    """Return True when HEAD is tagged as the release version."""

    if _RELEASE_VERSION_RE.fullmatch(str(version)) is None:
        return False

    tags_out = subprocess.check_output(
        [git_exe, "tag", "--points-at", "HEAD"],
        cwd=repo_root,
        stderr=subprocess.DEVNULL,
    )
    tags = {line.strip() for line in tags_out.decode("utf-8", errors="replace").splitlines() if line.strip()}
    return str(version) in tags or f"v{version}" in tags


def _tree_is_dirty(*, repo_root: Path, git_exe: str) -> bool:
    """Return True when game sources differ from HEAD, including new unignored files."""

    out = subprocess.check_output(
        [git_exe, "status", "--porcelain", "--", "src"],
        cwd=repo_root,
        stderr=subprocess.DEVNULL,
    )
    return bool(out.strip())


@lru_cache(maxsize=1)
def current_replay_game_version() -> str:
    """Return replay `game_version`.

    - Release-tagged HEAD: "<version>"
    - Git checkout non-release: "<version>+g<short_sha>"
    - Modified game sources append ".dirty": the commit alone no longer
      identifies the simulation that recorded the replay.
    - No git metadata or an installed package: "<version>"
    """

    from . import __version__

    version = str(__version__)
    try:
        git_exe = shutil.which("git")
        if git_exe is None:
            return version
        repo_root = Path(__file__).resolve().parents[2]
        if not (repo_root / "pyproject.toml").is_file():
            # An installed package: parents[2] is the environment's lib dir, which may sit in an unrelated repo.
            return version
        out = subprocess.check_output(
            [git_exe, "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
        build = out.decode("utf-8", errors="replace").strip()
        if not build:
            return version
        dirty = _tree_is_dirty(repo_root=repo_root, git_exe=git_exe)
        if not dirty and _head_points_at_release_tag(version=version, repo_root=repo_root, git_exe=git_exe):
            return version
        separator = "." if "+" in version else "+"
        return f"{version}{separator}g{build}" + (".dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return version
