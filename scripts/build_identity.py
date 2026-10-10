"""Content identities for Python, recovered modules and their clients.

These are build identities, not replay compatibility versions. Git provenance is
recorded beside the identity and never enters its fingerprint or compiled label.
Only the standard library, so CI can plan cache keys before installing compilers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ZIG_VERSION = "0.17.0"

# The verifier compiles this manifest, not the recovered presentation or the game-only host includes.
# Keep directory patterns for headers and patches: adding either can affect an existing compilation.
CORE_BUILD = (
    "scripts/build_identity.py",
    "crimson-core/build.py",
    "crimson-core/adapter.py",
    "crimson-core/data.py",
    "crimson-core/sources.json",
    "crimson-core/schema.json",
    "crimson-core/host/host.cpp",
    "crimson-core/host/grim.inc",
    "crimson-core/host/*.h",
    "crimson-core/host/*.zig",
    "crimson-core/abi/",
    "crimson-core/patches/",
    "crimson-core/seams/",
    "third_party/headers/",
    "tools/match/include/",
    "tools/native/data_definitions/crimsonland.exe.json",
)
# The game discovers recovered sources and constructors in these trees, scans every host file for reset
# ownership, and links its own platform layer and vendor libraries. New files in those trees count too.
GAME_BUILD = (
    *CORE_BUILD,
    "crimson-core/game.py",
    "crimson-core/game/",
    "crimson-core/host/",
    "decomp/1.9/crimsonland/",
    "decomp/1.9/grim/",
    "third_party/sources/",
    "tools/native/data_definitions/grim.dll.json",
)


def core_paths(root: Path = ROOT) -> tuple[str, ...]:
    return (*CORE_BUILD, *json.loads((root / "crimson-core/sources.json").read_text()))


def game_paths(root: Path = ROOT) -> tuple[str, ...]:
    return (*GAME_BUILD, *core_paths(root), "src/crimson/game_version.py")


def matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    parts, wanted = PurePosixPath(path).parts, PurePosixPath(pattern).parts
    return len(parts) == len(wanted) and all(map(fnmatchcase, parts, wanted))


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(root: Path, patterns: tuple[str, ...]) -> dict[str, str]:
    paths: set[str] = set()
    for pattern in patterns:
        candidates = (root / pattern).rglob("*") if pattern.endswith("/") else root.glob(pattern)
        paths.update(
            path.relative_to(root).as_posix()
            for path in candidates
            if path.is_file() and not any(part == "__pycache__" for part in path.parts)
            and path.name != "_build.json" and path.suffix not in {".pyc", ".pyo"}
        )
    return {path: file_hash(root / path) for path in sorted(paths)}


def version_label(version: str, fingerprint: str) -> str:
    label = f"{version}{'.' if '+' in version else '+'}build.{fingerprint[:24]}"
    if len(label) > 63 or not label.isascii():
        raise ValueError("Build label does not fit replay recorder metadata")
    return label


def fingerprint(identity: dict[str, Any]) -> str:
    payload = {key: identity[key] for key in ("schema", "kind", "recipe", "inputs")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def provenance(root: Path, paths: dict[str, str]) -> dict[str, Any]:
    git = shutil.which("git")
    if git is None:
        return {"commit": None, "dirty": None}
    try:
        tracked = set(subprocess.check_output([git, "ls-files", "-z", "--", "pyproject.toml", *paths], cwd=root, stderr=subprocess.DEVNULL).decode().split("\0"))
        if "pyproject.toml" not in tracked:
            return {"commit": None, "dirty": None}
        commit = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
        changed = subprocess.run([git, "diff", "--quiet", "HEAD", "--", "pyproject.toml", *paths], cwd=root, check=False)
        if changed.returncode not in (0, 1):
            raise OSError("Cannot inspect build inputs")
        dirty = bool(set(paths) - tracked) or changed.returncode == 1
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}
    return {"commit": commit, "dirty": dirty}


def identity(kind: str, root: Path, paths: tuple[str, ...], recipe: dict[str, Any]) -> dict[str, Any]:
    inputs = source_hashes(root, paths)
    result = {"schema": 1, "kind": kind, "inputs": inputs, "recipe": recipe}
    result["fingerprint"] = fingerprint(result)
    result["version"] = version_label(recipe["version"], result["fingerprint"])
    result["origin"] = provenance(root, inputs)
    return result


def project_version(root: Path) -> str:
    return tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]


def python_identity(root: Path = ROOT) -> dict[str, Any]:
    return identity("python", root, ("src/crimson/", "src/grim/", "scripts/build_identity.py", "build_backend.py", "pyproject.toml", "uv.lock"), {"version": project_version(root)})


def output(command: str, *args: str) -> str:
    executable = shutil.which(command)
    if executable is None:
        raise RuntimeError(f"{command} is required to identify this build")
    return subprocess.check_output([executable, *args], text=True).strip()


def compiler_version(command: str) -> str:
    # InstalledDir is machine-local and does not name the compiler's code.
    return "\n".join(line for line in output(command, "--version").splitlines() if not line.startswith("InstalledDir:"))


def tool_version(command: str) -> str:
    match = re.search(r"\d+\.\d+\.\d+", output(command, "--version"))
    if match is None:
        raise ValueError(f"Cannot identify {command} version")
    return match.group()


def runtime_identity(target: str, root: Path = ROOT) -> dict[str, Any]:
    recipe = {"target": target, "zig": ZIG_VERSION, "python": f"{platform.python_version_tuple()[0]}.{platform.python_version_tuple()[1]}", "version": project_version(root)}
    if target == "native":
        recipe["clang"] = compiler_version("clang++")
        recipe["platform"] = f"{platform.system()}-{platform.machine()}"
    return identity(target, root, game_paths(root) if target == "game" else core_paths(root), recipe)


def read_manifest(path: Path) -> dict[str, Any]:
    result = json.loads(path.read_text())
    if result.get("schema") != 1 or result.get("fingerprint") != fingerprint(result):
        raise ValueError(f"Invalid build identity: {path}")
    if result.get("version") != version_label(result["recipe"]["version"], result["fingerprint"]):
        raise ValueError(f"Invalid build label: {path}")
    return result


def check_artifacts(manifest: dict[str, Any], directory: Path) -> None:
    for name, digest in manifest["artifacts"].items():
        if not name or "/" in name or "\\" in name or name in {".", ".."}:
            raise ValueError("Invalid build artifact path")
        if file_hash(directory / name) != digest:
            raise ValueError(f"Changed build artifact: {name}")


def client_identity(target: str, root: Path = ROOT, *, wabt: str | None = None, emscripten: str | None = None) -> dict[str, Any]:
    game = read_manifest(root / "crimson-core/build/game/game.wasm.build.json")
    if game["kind"] != "game" or set(game["artifacts"]) != {"game.wasm"}:
        raise ValueError("Client requires a game-module build manifest")
    check_artifacts(game, root / "crimson-core/build/game")
    recipe = {"target": target, "wabt": wabt or tool_version("wasm2c"), "game": game["artifacts"]["game.wasm"], "version": game["recipe"]["version"]}
    if target == "web":
        recipe["emscripten"] = emscripten or tool_version("emcc")
    else:
        recipe["clang"] = compiler_version("clang++")
        recipe["sdl"] = output("pkg-config", "--modversion", "sdl3")
        recipe["platform"] = f"{platform.system()}-{platform.machine()}"
    result = identity("client", root, ("crimson-core/client/", "scripts/build_identity.py"), recipe)
    result["game"] = game
    return result


def write_manifest(path: Path, result: dict[str, Any], artifacts: list[Path]) -> None:
    result["artifacts"] = {artifact.name: file_hash(artifact) for artifact in artifacts}
    path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    runtime = commands.add_parser("runtime")
    runtime.add_argument("target", choices=("native", "wasm", "game"))
    client = commands.add_parser("client")
    client.add_argument("target", choices=("native", "web"))
    client.add_argument("--wabt")
    client.add_argument("--emscripten")
    for command in (runtime, client):
        command.add_argument("--github-output", type=Path)
    check = commands.add_parser("check")
    check.add_argument("manifest", type=Path)
    check.add_argument("expected")
    args = parser.parse_args()
    if args.command == "check":
        result = read_manifest(args.manifest)
        if result["fingerprint"] != args.expected:
            raise ValueError("Restored build has another input identity")
        check_artifacts(result, args.manifest.parent)
        return
    result = runtime_identity(args.target) if args.command == "runtime" else client_identity(args.target, wabt=args.wabt, emscripten=args.emscripten)
    print(result["fingerprint"])
    if args.github_output:
        with args.github_output.open("a") as stream:
            stream.write(f"fingerprint={result['fingerprint']}\nzig_version={ZIG_VERSION}\n")
            if args.command == "runtime":
                binary = {"native": "core", "wasm": "core.wasm", "game": "game.wasm"}[args.target]
                stream.write(f"binary={binary}\n")


if __name__ == "__main__":
    main()
