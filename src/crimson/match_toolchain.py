"""Shared compiler and runner identity for matching and native audits."""

from __future__ import annotations

import hashlib
import os
import shutil
from functools import lru_cache
from pathlib import Path


def file_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_mode


@lru_cache(maxsize=8192)
def _file_sha256(path: Path, identity: tuple[int, int, int, int]) -> str:
    del identity
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_sha256(path: Path) -> str | None:
    try:
        return _file_sha256(path.resolve(), file_identity(path))
    except FileNotFoundError:
        return None


@lru_cache(maxsize=32)
def _tree_sha256(root: Path, files: tuple[tuple[Path, tuple[int, int, int, int]], ...]) -> str:
    digest = hashlib.sha256()
    for path, _identity in files:
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        contents = path.read_bytes()
        digest.update(len(contents).to_bytes(8, "little"))
        digest.update(contents)
    return digest.hexdigest()


def tree_set_sha256(root: Path, trees: tuple[str, ...]) -> str:
    files: list[Path] = []
    for tree_name in trees:
        tree = root / tree_name
        if not tree.is_dir():
            raise ValueError(f"compiler bundle is missing {tree}")
        files.extend(path for path in tree.rglob("*") if path.is_file())
    return _tree_sha256(root, tuple((path, file_identity(path)) for path in sorted(files)))


def resolve_wibo_path(match_root: Path, *, required: bool = True) -> Path | None:
    configured = os.environ.get("WIBO")
    if configured:
        candidate = Path(configured)
        if candidate.is_absolute() or candidate.parent != Path("."):
            resolved = candidate.resolve()
            if resolved.is_file() and os.access(resolved, os.X_OK):
                return resolved
        elif resolved_text := shutil.which(configured):
            return Path(resolved_text).resolve()
    else:
        candidate = match_root / "bin" / "wibo"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
        if resolved_text := shutil.which("wibo"):
            return Path(resolved_text).resolve()
    if required:
        raise ValueError(f"Wibo cannot be resolved or is not executable: {configured or 'wibo'}")
    return None


def scratch_toolchain_fingerprint(compiler: Path, match_root: Path) -> dict[str, object]:
    root = compiler.resolve().parent.parent
    runner = resolve_wibo_path(match_root, required=False)
    # Missing ignored bundles are represented explicitly for read-only CI ledgers.
    return {
        "compiler_trees": {
            tree: tree_set_sha256(root, (tree,)) if (root / tree).is_dir() else None for tree in ("Bin", "Include")
        },
        "runner_sha256": file_sha256(runner) if runner is not None else None,
        "runner_mode": runner.stat().st_mode & 0o7777 if runner is not None else None,
        "cl_environment": {key: os.environ.get(key) for key in ("CL", "_CL_")},
    }
