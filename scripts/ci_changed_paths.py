"""Classify changed paths for GitHub Actions' always-reported CI gates."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tomllib
from pathlib import Path, PurePosixPath

CORE_DIRS = (
    "crimson-core/",
    "decomp/",
    "third_party/headers/",
    "third_party/sources/",
    "tools/match/include/",
    "tools/native/data_definitions/",
    "src/",
    "crimson-re/",
    "tests/fixtures/replays/",
)
CLIENT_DIRS = (
    "crimson-core/",
    "decomp/",
    "third_party/",
    "tools/match/include/",
    "tools/native/data_definitions/",
)
# The game build compiles in the replay version, format and rules the Python port names; an import
# failure elsewhere in their closure fails pytest first.
CLIENT_FILES = ("src/crimson/replay/types.py",)
DECOMP_DIRS = (
    "decomp/",
    "crimson-re/",
    "tools/match/",
    "tools/native/",
    "third_party/",
    "analysis/",
    "src/",  # The report runs through the Python application's CLI.
)
SERVICE_DIRS = (
    "service/",
    "crimson-core/",
    "decomp/",
    "third_party/headers/",
    "tools/match/include/",
    "tools/native/data_definitions/",
    "src/grim/",
    "tests/fixtures/replays/",
)
PROJECT_FILES = ("pyproject.toml", "crimson-re/pyproject.toml", "uv.lock")
SHARED_FILES = (*PROJECT_FILES, "scripts/ci_changed_paths.py")
DOC_SUFFIXES = {".md", ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp", ".css"}


def relevant(category: str, paths: list[str]) -> bool:
    """Return whether a changed path requires the named suite."""
    if category == "docs-only":
        return bool(paths) and all(
            (path.startswith("docs/") and PurePosixPath(path).suffix.lower() in DOC_SUFFIXES)
            or (len(PurePosixPath(path).parts) == 1 and path.endswith(".md"))
            for path in paths
        )

    directories, files = {
        "core": (CORE_DIRS, (*SHARED_FILES, ".github/workflows/core.yml")),
        "client": (CLIENT_DIRS, (*SHARED_FILES, *CLIENT_FILES, ".github/workflows/client.yml")),
        "decomp": (DECOMP_DIRS, (*SHARED_FILES, ".github/workflows/decomp.yml")),
        "service": (SERVICE_DIRS, (*SHARED_FILES, ".github/workflows/service.yml")),
    }[category]
    return any(path in files or path.startswith(directories) for path in paths)


def _unversioned(text: str) -> dict:
    """A project file's TOML without the workspace's own versions, which a release bumps."""
    data = tomllib.loads(text)
    data.get("project", {}).pop("version", None)
    for package in data.get("package", []):
        if {"editable", "virtual"} & package["source"].keys():
            package.pop("version")
    return data


def version_bump_only(base: str, path: str) -> bool:
    """Whether a project file differs from `base` only in the workspace's own versions."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to classify CI paths")
    before = subprocess.run([git, "show", f"{base}:{path}"], capture_output=True, text=True, check=False)
    if before.returncode or not Path(path).is_file():
        return False
    return _unversioned(before.stdout) == _unversioned(Path(path).read_text())


def changed_paths(base: str) -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to classify CI paths")
    result = subprocess.run(
        [git, "diff", "--name-only", "--no-renames", "-z", base, "HEAD"],
        check=True,
        capture_output=True,
    )
    return [path.decode() for path in result.stdout.split(b"\0") if path]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("category", choices=("docs-only", "core", "client", "decomp", "service"))
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    # A release changes only the version in the project files: no suite builds or runs differently.
    paths = [path for path in changed_paths(args.base) if path not in PROJECT_FILES or not version_bump_only(args.base, path)]
    print(str(relevant(args.category, paths)).lower())


if __name__ == "__main__":
    main()
