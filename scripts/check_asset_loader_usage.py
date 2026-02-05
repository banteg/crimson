from __future__ import annotations

import argparse
import re
from pathlib import Path


PATTERNS = (
    re.compile(r"^\s*def _resolve_asset\b", re.MULTILINE),
    re.compile(r"^\s*def _load_from_cache\b", re.MULTILINE),
    re.compile(r"^\s*def _load_from_path\b", re.MULTILINE),
)


def iter_python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if path.is_file())


def find_violations(root: Path, allowlist: set[Path]) -> list[str]:
    violations: list[str] = []
    for path in iter_python_files(root):
        rel = path.relative_to(root.parent)
        if rel in allowlist:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in PATTERNS:
            if pattern.search(text):
                violations.append(f"{rel}: {pattern.pattern}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail if legacy asset loader helpers are reintroduced.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("src"),
        help="root directory to scan (default: src)",
    )
    args = parser.parse_args()
    root = args.root
    allowlist = {Path("src/grim/assets.py")}

    violations = find_violations(root, allowlist)
    if violations:
        for entry in violations:
            print(entry)
        print("Asset loader helpers are forbidden; use grim.assets.TextureLoader instead.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
