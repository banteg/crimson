"""Decide which CI suites a change can affect, from what each suite reads.

A suite reads data paths (a trailing `/` names a directory, `*` matches within one path segment) and runs
Python: the port, its tooling and the test support it imports. Its Python inputs are the import closure of
its entry files, followed through every import statement (lazy ones included), so a module no check imports
cannot start that check. `hash` digests a suite's inputs for cache keys that move exactly when they change.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import cache
from pathlib import Path, PurePosixPath

try:
    from .build_identity import core_paths, game_paths
except ImportError:
    from build_identity import core_paths, game_paths

# Where each importable top-level package lives.
PACKAGE_ROOTS = {"crimson": "src", "grim": "src", "crimson_re": "crimson-re/src", "tests": "."}
IMPORT_RE = re.compile(r"\b(?:from|import)\s+((?:crimson_re|crimson|grim|tests)(?:\.\w+)*)")

PROJECT_FILES = ("pyproject.toml", "crimson-re/pyproject.toml", "uv.lock")
SHARED_FILES = (
    *PROJECT_FILES,
    "scripts/ci_changed_paths.py",
    "scripts/ci_gate.py",
    "scripts/ci_benchmark.py",
    ".github/workflows/runtime-build.yml",
)


@dataclass(frozen=True)
class Suite:
    paths: tuple[str, ...]
    python: tuple[str, ...] = ()


# Build/cache identities and path filters share the compile-input inventory.
CORE_BUILD = core_paths()
GAME_BUILD = game_paths()
# The bot corpus: the matrix plays it on the WASM core and compares native with WASM.
CORE_CORPUS = (
    *CORE_BUILD,
    "crimson-core/checks/matrix.mjs",
    "crimson-core/checks/engine.mjs",
    "crimson-core/checks/compare.mjs",
    "crimson-core/checks/compare.test.mjs",
)
CORE_GATE = ("crimson-core/checks/gate.py", "crimson-core/checks/replay.py")
CORE_GAME = ("crimson-core/checks/game_*", "crimson-core/build.py", *CORE_GATE)
CORE_ORACLES = (
    "crimson-core/checks/spawn_batch.*",
    "crimson-core/checks/builder_oracle.py",
    "crimson-core/checks/math_oracle.py",
    "crimson-core/checks/wasmtime_check.py",
)
# The matching and native-link tooling behind `crimson match` and `crimson native`. The decomp report also pins
# the matching code it scores with by content (crimson_re.match_report._input_path), imported or not.
RE_TOOLS = Suite(
    (
        "decomp/",
        "tools/match/",
        "tools/native/",
        "third_party/",
        "analysis/decomp/",
        "analysis/native/",
        "analysis/ghidra/maps/",
        "analysis/ida/raw/",
        "analysis/library_provenance.json",
        "analysis/matching_scope.json",
        "crimson-re/src/crimson_re/match*.py",
        "crimson-re/src/crimson_re/library*.py",
        "crimson-re/src/crimson_re/native_link.py",
        "crimson-re/src/crimson_re/native_reference_link.py",
        "src/crimson/__init__.py",
        "src/crimson/cli/__init__.py",
    ),
    ("crimson-re/src/crimson_re/cli/match.py", "crimson-re/src/crimson_re/cli/native.py"),
)

SUITES = {
    "core-build": Suite(CORE_BUILD),
    "game-build": Suite(GAME_BUILD, ("src/crimson/game_version.py",)),
    "core-corpus": Suite(CORE_CORPUS),
    "core-gate": Suite(
        (
            *CORE_CORPUS,
            *CORE_GATE,
            "crimson-core/results/matrix.json",
            "tests/fixtures/replays/",
            ".github/workflows/core.yml",
        ),
        CORE_GATE,
    ),
    "core-game": Suite(
        (*GAME_BUILD, *CORE_CORPUS, *CORE_GAME, "tests/fixtures/replays/", ".github/workflows/core.yml"),
        CORE_GAME,
    ),
    # The oracles resolve the original executable's symbols from the name and data maps.
    "core-oracles": Suite(
        (
            *CORE_BUILD,
            *CORE_ORACLES,
            "crimson-core/checks/engine.mjs",
            "crimson-core/checks/*_probe.mjs",
            "analysis/ghidra/maps/",
            ".github/workflows/core.yml",
        ),
        CORE_ORACLES,
    ),
    "client": Suite(
        (
            *GAME_BUILD,
            "crimson-core/client/",
            ".github/workflows/client.yml",
            ".github/workflows/core.yml",
            ".github/workflows/deploy.yml",
        ),
        ("crimson-core/build.py", "crimson-core/client/*.py"),
    ),
    "service": Suite(
        (
            *CORE_BUILD,
            "service/",
            ".github/actions/game-art/",
            "tests/fixtures/replays/",
            ".github/workflows/service.yml",
            ".github/workflows/deploy.yml",
            ".github/workflows/core.yml",
        ),
        ("service/scripts/assets.py",),
    ),
    "decomp": Suite((*RE_TOOLS.paths, ".github/workflows/decomp.yml"), RE_TOOLS.python),
    "re-audits": Suite((*RE_TOOLS.paths, ".github/workflows/ci.yml"), RE_TOOLS.python),
    # Unicorn runs the original executable; the support module reads Grim's interface layout.
    "native-oracle": Suite(
        (
            "tests/native_oracle/",
            "analysis/ghidra/maps/",
            "tools/match/include/grim2d_cpp.h",
            ".github/workflows/ci.yml",
        ),
        ("tests/native_oracle/*.py",),
    ),
    "pytest": Suite(
        (
            "src/",
            "crimson-re/",
            "tests/",
            "scripts/",
            ".github/actions/game-art/",
            "decomp/",
            "analysis/",
            "tools/",
            "third_party/",
            ".github/workflows/ci.yml",
        ),
    ),
}
# A job that runs several suites' steps runs when any of them can change.
SUITES["core"] = Suite(
    tuple(dict.fromkeys(p for name in ("core-gate", "core-game", "core-oracles") for p in SUITES[name].paths)),
    tuple(dict.fromkeys(p for name in ("core-gate", "core-game", "core-oracles") for p in SUITES[name].python)),
)


def _git(*args: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to classify CI paths")
    return subprocess.run([git, *args], check=True, capture_output=True).stdout


@cache
def tracked_files() -> tuple[str, ...]:
    return tuple(path.decode() for path in _git("ls-files", "-z").split(b"\0") if path)


def matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if "*" not in pattern:
        return path == pattern
    parts, pattern_parts = PurePosixPath(path).parts, PurePosixPath(pattern).parts
    return len(parts) == len(pattern_parts) and all(map(fnmatchcase, parts, pattern_parts))


def module_file(name: str) -> str | None:
    """The tracked file defining an importable module of the port, its tooling or the tests."""
    root = PACKAGE_ROOTS.get(name.split(".")[0])
    if root is None:
        return None
    base = PurePosixPath(root, *name.split("."))
    return next(
        (str(path) for path in (base.with_suffix(".py"), base / "__init__.py") if str(path) in _tracked_set()), None,
    )


@cache
def _tracked_set() -> frozenset[str]:
    return frozenset(tracked_files())


def _in_package(path: str) -> bool:
    return path.endswith(".py") and any(
        PurePosixPath(path).is_relative_to(PurePosixPath(root, package)) for package, root in PACKAGE_ROOTS.items()
    )


def _module_name(path: str) -> str:
    parts = PurePosixPath(path).with_suffix("").parts
    for package, root in PACKAGE_ROOTS.items():
        prefix = PurePosixPath(root).parts
        if parts[: len(prefix)] == prefix and len(parts) > len(prefix) and parts[len(prefix)] == package:
            name = parts[len(prefix) :]
            return ".".join(name[:-1] if name[-1] == "__init__" else name)
    raise ValueError(f"{path} is not in an importable package")


def _imports(path: str) -> set[str]:
    """Module names a file imports, resolved against its package and expanded to submodules it names."""
    tree = ast.parse(Path(path).read_bytes(), filename=path)
    package = _module_name(path)
    if not path.endswith("__init__.py"):
        package = package.rpartition(".")[0]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                anchor = package.split(".")[: len(package.split(".")) - node.level + 1]
                base = ".".join([*anchor, *([node.module] if node.module else [])])
            else:
                base = node.module or ""
            names.add(base)
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def _with_packages(name: str) -> set[str]:
    parts = name.split(".")
    return {".".join(parts[:i]) for i in range(1, len(parts) + 1)}


@cache
def python_inputs(entry_patterns: tuple[str, ...]) -> frozenset[str]:
    """The tracked files of every module the entry files import, transitively."""
    if not entry_patterns:
        return frozenset()
    entries = [path for path in tracked_files() if any(matches(path, pattern) for pattern in entry_patterns)]
    # A module of an importable package is walked like any import; other files (check scripts, Node checks
    # running Python snippets) name the modules they run.
    pending = {_module_name(path) for path in entries if _in_package(path)}
    pending.update(
        module
        for path in entries
        if not _in_package(path)
        for module in IMPORT_RE.findall(Path(path).read_text(errors="replace"))
    )
    seen: set[str] = set()
    files: set[str] = set()
    while pending:
        name = pending.pop()
        for module in _with_packages(name):
            if module in seen:
                continue
            seen.add(module)
            path = module_file(module)
            if path is not None:
                files.add(path)
                pending.update(_imports(path))
    return frozenset(files)


def inputs(suite: str) -> list[str]:
    spec = SUITES[suite]
    python = python_inputs(spec.python)
    patterns = (*spec.paths, *SHARED_FILES)
    return [path for path in tracked_files() if path in python or any(matches(path, pattern) for pattern in patterns)]


def relevant(suite: str, paths: list[str]) -> bool:
    """Whether a change to `paths` can change what the suite checks."""
    spec = SUITES[suite]
    python = python_inputs(spec.python)
    patterns = (*spec.paths, *SHARED_FILES)
    return any(path in python or any(matches(path, pattern) for pattern in patterns) for path in paths)


def inputs_hash(suite: str) -> str:
    digest = hashlib.sha256()
    for path in inputs(suite):
        digest.update(path.encode() + b"\0" + Path(path).read_bytes() + b"\0")
    return digest.hexdigest()


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
    try:
        before = _git("show", f"{base}:{path}").decode()
    except subprocess.CalledProcessError:
        return False
    return Path(path).is_file() and _unversioned(before) == _unversioned(Path(path).read_text())


def changed_paths(base: str) -> list[str]:
    output = _git("diff", "--name-only", "--no-renames", "-z", base, "HEAD")
    return [path.decode() for path in output.split(b"\0") if path]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    changed = commands.add_parser("changed", help="print <suite>=true|false for GitHub step outputs")
    changed.add_argument("--base", help="the commit to compare HEAD with; every suite runs without one")
    changed.add_argument("suites", nargs="+", choices=SUITES)
    digest = commands.add_parser("hash", help="digest a suite's inputs for a cache key")
    digest.add_argument("suite", choices=SUITES)
    listing = commands.add_parser("inputs", help="list a suite's inputs")
    listing.add_argument("suite", choices=SUITES)
    args = parser.parse_args()

    if args.command == "hash":
        print(inputs_hash(args.suite))
    elif args.command == "inputs":
        print("\n".join(inputs(args.suite)))
    else:
        # A release changes only the version in the project files: no suite builds or runs differently.
        paths = (
            None
            if not args.base or re.fullmatch(r"0+", args.base)
            else [
                path
                for path in changed_paths(args.base)
                if path not in PROJECT_FILES or not version_bump_only(args.base, path)
            ]
        )
        for suite in args.suites:
            # Without a base (a new branch, a manual run) every suite runs.
            print(f"{suite}={str(paths is None or relevant(suite, paths)).lower()}")


if __name__ == "__main__":
    main()
