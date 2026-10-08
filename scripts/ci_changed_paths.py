"""Classify changed paths for GitHub Actions' always-reported CI gates."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import PurePosixPath

CORE_DIRS = (
    "crimson-core/",
    "decomp/",
    "third_party/headers/",
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
DECOMP_DIRS = (
    "decomp/",
    "crimson-re/",
    "tools/match/",
    "tools/native/",
    "third_party/",
    "analysis/",
)
SERVICE_DIRS = ("service/",)
SHARED_FILES = ("pyproject.toml", "uv.lock", "scripts/ci_changed_paths.py")
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
        "client": (CLIENT_DIRS, ("scripts/ci_changed_paths.py", ".github/workflows/client.yml")),
        "decomp": (DECOMP_DIRS, (*SHARED_FILES, ".github/workflows/decomp.yml")),
        "service": (SERVICE_DIRS, ("scripts/ci_changed_paths.py", ".github/workflows/service.yml")),
    }[category]
    return any(path in files or path.startswith(directories) for path in paths)


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
    print(str(relevant(args.category, changed_paths(args.base))).lower())


if __name__ == "__main__":
    main()
