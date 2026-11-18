"""Install the pinned 1.9.93 test inputs used by contributors and CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://paq.crimson.banteg.xyz/v1.9.93"


def install(dest: Path, expected: str) -> None:
    def digest(path: Path) -> str:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()

    if dest.exists():
        if dest.is_file() and digest(dest) == expected:
            return
        raise SystemExit(f"{dest} differs from the repository pin. Move it aside before fetching the test copy.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    curl = shutil.which("curl")
    if curl is None:
        raise SystemExit("Install curl to download missing test inputs.")
    url = f"{BASE}/{dest.name}?sha256={expected}"
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        candidate = Path(tmp) / dest.name
        subprocess.run([curl, "--fail", "--silent", "--show-error", "--location", "--retry", "3",
                        "--retry-all-errors", "--output", str(candidate), url], check=True)
        if digest(candidate) != expected:
            raise SystemExit(f"{dest.name}: downloaded SHA-256 differs from the repository pin")
        candidate.replace(dest)
    print(f"Installed {dest.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=["art", "originals", "packs"], help="install one group of inputs")
    group = parser.parse_args().only
    if group in (None, "art", "packs"):
        version = json.loads((ROOT / "src/crimson/assets_version.json").read_text())
        files = {"crimson.paq": version["current"]}
        if group == "packs":
            files.update(version["audio"])
        for name, digest in files.items():
            install(ROOT / "artifacts/assets" / name, digest)
    if group in (None, "originals"):
        provenance = json.loads((ROOT / "analysis/library_provenance.json").read_text())
        for image in provenance["artifacts"]:
            install(ROOT / image["path"], image["sha256"])


if __name__ == "__main__":
    main()
