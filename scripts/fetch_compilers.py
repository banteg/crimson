"""
Install the pinned MSVC bundles listed in tools/match/compilers.json.

Each archive is downloaded from the decomp.me release, checked against its
SHA-256, cached next to the install, and extracted to
tools/match/compilers/<name>/. Installed compilers are verified member by
member against the pinned archive; a mismatch is an error, and missing
compilers are installed.

Usage:
  uv run scripts/fetch_compilers.py            # install or verify every compiler
  uv run scripts/fetch_compilers.py msvc6.5    # only the named ones
  uv run scripts/fetch_compilers.py --check    # verify, never install
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path

MATCH_ROOT = Path(__file__).resolve().parents[1] / "tools" / "match"
MANIFEST = MATCH_ROOT / "compilers.json"
COMPILERS = MATCH_ROOT / "compilers"


def _archive(name: str, source: str, sha256: str) -> bytes:
    cached = COMPILERS / f"{name}.tar.gz"
    data = cached.read_bytes() if cached.is_file() else b""
    if hashlib.sha256(data).hexdigest() != sha256:
        with urllib.request.urlopen(f"{source}/{name}.tar.gz") as response:
            data = response.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != sha256:
            raise SystemExit(f"{name}: downloaded archive has sha256 {digest}, expected {sha256}")
        COMPILERS.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
    return data


def _differences(root: Path, data: bytes) -> list[str]:
    problems = []
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = root / member.name
            expected = archive.extractfile(member).read()
            if not path.is_file():
                problems.append(f"missing {member.name}")
            elif path.read_bytes() != expected:
                problems.append(f"differs {member.name}")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="compiler names from tools/match/compilers.json")
    parser.add_argument("--check", action="store_true", help="verify installed compilers; do not install missing ones")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    names = args.names or list(manifest["compilers"])
    unknown = sorted(set(names) - manifest["compilers"].keys())
    if unknown:
        raise SystemExit(f"unknown compilers: {', '.join(unknown)}")
    failed = False
    for name in names:
        root = COMPILERS / name
        installed = (root / "Bin" / "CL.EXE").is_file() or (root / "Bin" / "cl.exe").is_file()
        if args.check and not installed:
            print(f"{name}: not installed")
            failed = True
            continue
        data = _archive(name, manifest["source"], manifest["compilers"][name]["sha256"])
        if installed:
            problems = _differences(root, data)
            print(f"{name}: {'ok' if not problems else f'{len(problems)} files differ from the pinned archive'}")
            for problem in problems[:10]:
                print(f"  {problem}")
            failed |= bool(problems)
            continue
        root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(root, filter="data")
        print(f"{name}: installed")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
