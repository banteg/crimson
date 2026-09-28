"""
Unpack every build in decomp/builds.json into its game tree.

Each build names a pinned package and a `tree` directory under game_bins/. The
package is checked against its SHA-256, unpacked as data (no installer runs),
stripped of any Reflexive Arcade wrapper, and moved into the tree. Every pinned
image must then sit at `<tree>/<name>` with its pinned SHA-256.

Package formats:
  directory   the package is the tree
  zip         a ZIP holding one top-level directory
  inno        an Inno Setup installer, optionally behind a Reflexive loader
  zip+inno    a ZIP holding one such installer
  rutracker   a RuTracker Reflexive repack, unpacked by `reflexive extract`

Requires innoextract, and reflexive (github.com/banteg/reflexive) for wrapped
builds.

Usage:
  uv run scripts/unpack_game_bins.py              # unpack missing trees, verify all
  uv run scripts/unpack_game_bins.py 1.9.8        # only the named builds
  uv run scripts/unpack_game_bins.py --force      # replace existing trees
  uv run scripts/unpack_game_bins.py --reflexive "uvx --from git+https://github.com/banteg/reflexive reflexive"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "decomp" / "builds.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _only_child(path: Path) -> Path:
    children = list(path.iterdir())
    return children[0] if len(children) == 1 and children[0].is_dir() else path


def _embedded_pe_offsets(data: bytes) -> list[int]:
    offsets = []
    for match in re.finditer(rb"MZ", data):
        start = match.start()
        pe = int.from_bytes(data[start + 0x3C : start + 0x40], "little")
        if pe < 0x1000 and data[start + pe : start + pe + 4] == b"PE\0\0":
            offsets.append(start)
    return offsets


def _innoextract(installer: Path, work: Path) -> Path:
    """Extract an Inno installer, carving it out of a Reflexive loader if needed."""
    innoextract = shutil.which("innoextract")
    if innoextract is None:
        raise SystemExit("innoextract is required to unpack Inno Setup packages")
    data = installer.read_bytes()
    for offset in _embedded_pe_offsets(data):
        candidate = work / f"setup_{offset:x}.exe"
        candidate.write_bytes(data[offset:])
        out = work / f"inno_{offset:x}"
        result = subprocess.run(
            [innoextract, "-s", "-d", str(out), str(candidate)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return out / "app"
    raise SystemExit(f"{installer.name}: no Inno Setup installer found")


def _stage(package: Path, fmt: str, work: Path, reflexive: list[str]) -> Path:
    match fmt:
        case "zip":
            with zipfile.ZipFile(package) as archive:
                archive.extractall(work / "zip")
            return _only_child(work / "zip")
        case "inno":
            return _innoextract(package, work)
        case "zip+inno":
            with zipfile.ZipFile(package) as archive:
                (member,) = [name for name in archive.namelist() if name.lower().endswith(".exe")]
                installer = work / Path(member).name
                installer.write_bytes(archive.read(member))
            return _innoextract(installer, work)
        case "rutracker":
            out = work / "rutracker"
            subprocess.run([*reflexive, "extract", str(package), str(out)], check=True)
            return out
    raise SystemExit(f"{package.name}: unknown package format {fmt!r}")


def _unwrap(tree: Path, work: Path, reflexive: list[str]) -> Path:
    if not any(tree.glob("*.RWG")):
        return tree
    roots = work / "roots"
    roots.mkdir()
    shutil.move(tree, roots / "game")
    out = work / "unwrapped"
    subprocess.run(
        [*reflexive, "unwrap", "--extracted-root", str(roots), "--output-root", str(out), "game"],
        check=True,
    )
    return out / "game"


def _verify(build: dict, tree: Path) -> list[str]:
    errors = []
    for image in build["images"]:
        path = tree / image["name"]
        if not path.is_file():
            errors.append(f"{build['id']}: missing {path.relative_to(ROOT)}")
        elif (digest := _sha256(path)) != image["sha256"]:
            errors.append(f"{build['id']}: {image['name']} has sha256 {digest}, expected {image['sha256']}")
    return errors


def _unpack(build: dict, tree: Path, reflexive: list[str]) -> None:
    package = build["package"]
    path = ROOT / package["path"]
    if (digest := _sha256(path)) != package["sha256"]:
        raise SystemExit(f"{build['id']}: {path.name} has sha256 {digest}, expected {package['sha256']}")
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        staged = _unwrap(_stage(path, package["format"], work, reflexive), work, reflexive)
        if tree.exists():
            shutil.rmtree(tree)
        tree.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(staged, tree)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("builds", nargs="*", help="build ids to unpack (default: all)")
    parser.add_argument("--force", action="store_true", help="replace existing trees")
    parser.add_argument("--reflexive", default="reflexive", help="command that runs the reflexive CLI")
    args = parser.parse_args()

    builds = json.loads(MANIFEST.read_text())["builds"]
    unknown = set(args.builds) - {build["id"] for build in builds}
    if unknown:
        raise SystemExit(f"unknown builds: {', '.join(sorted(unknown))}")

    errors = []
    for build in builds:
        if args.builds and build["id"] not in args.builds:
            continue
        tree = ROOT / build["tree"]
        if build["package"]["format"] != "directory" and (args.force or _verify(build, tree)):
            print(f"{build['id']}: unpacking {build['package']['path']} -> {build['tree']}", flush=True)
            _unpack(build, tree, shlex.split(args.reflexive))
        build_errors = _verify(build, tree)
        errors += build_errors
        if not build_errors:
            print(f"{build['id']}: ok {build['tree']}", flush=True)
    if errors:
        raise SystemExit("\n".join(errors))


if __name__ == "__main__":
    main()
