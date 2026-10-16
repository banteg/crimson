from __future__ import annotations

import re
from pathlib import Path

from crimson_re import match as matchlib

ROOT = matchlib.REPO_ROOT
INCLUDE_DIRS = (ROOT / "tools/match/include", ROOT / "third_party/headers")
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
GUARD_RE = re.compile(r"^\s*#\s*(?:el)?if\b.*\bCL_BUILD\b", re.MULTILINE)


def _resolve(name: str, near: Path) -> Path | None:
    return next((path for path in (near.parent / name, *(root / name for root in INCLUDE_DIRS)) if path.is_file()), None)


def _reaches_cl_build(path: Path, text: str, seen: set[Path]) -> bool:
    for name in INCLUDE_RE.findall(text):
        if Path(name).name == "cl_build.h":
            return True
        header = _resolve(name, path)
        if header is not None and header not in seen:
            seen.add(header)
            if _reaches_cl_build(header, header.read_text(encoding="utf-8", errors="replace"), seen):
                return True
    return False


def test_every_cl_build_guard_sees_the_canonical_default() -> None:
    # An undefined CL_BUILD evaluates to 0, so a relational guard would pick the
    # 1.9.8 branch for the canonical build. cl_build.h must precede every guard.
    files = [
        path
        for root in (ROOT / "decomp", *INCLUDE_DIRS)
        for path in sorted(root.rglob("*"))
        if path.suffix in {".c", ".cpp", ".h", ".inc"} and path.name != "cl_build.h"
    ]
    missing = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        guard = GUARD_RE.search(text)
        if guard and not _reaches_cl_build(path, text[: guard.start()], set()):
            missing.append(path.relative_to(ROOT).as_posix())
    assert not missing
