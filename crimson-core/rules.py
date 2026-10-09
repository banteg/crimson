"""The ranked rules: `patches/NN-*.patch` fix original bug NN of docs/rewrite/original-bugs.md.

The game module also applies `game/patches/NN-*.patch`, the fixes that only change what is drawn, so they leave the
verifier untouched.

Each patch is a unified diff against the adapted copy of a recovered source (as written to build/), keeping the
native code behind `portable_preserve_bugs`. Hunks are matched by their exact old text, which must occur once;
line numbers are ignored because adapters shift them.
"""

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATCHES = HERE / "patches"
GAME_PATCHES = HERE / "game" / "patches"
_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def load_patches(*folders: Path) -> dict[str, list[tuple[str, str, str]]]:
    """(patch name, old text, new text) hunks by source stem."""

    hunks: dict[str, list[tuple[str, str, str]]] = {}
    for patch in sorted(path for folder in folders for path in folder.glob("*.patch")):
        lines = patch.read_text().splitlines(keepends=True)
        stem = None
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.startswith("+++ "):
                stem = Path(line[4:].split()[0]).stem
                continue
            match = _HUNK.match(line)
            if not match:
                continue
            old_count, new_count = (int(n) if n is not None else 1 for n in match.groups())
            old: list[str] = []
            new: list[str] = []
            while len(old) < old_count or len(new) < new_count:
                tag, body = lines[i][:1], lines[i][1:]
                i += 1
                if tag in " -":
                    old.append(body)
                if tag in " +":
                    new.append(body)
            if stem is None:
                raise SystemExit(f"{patch.name}: hunk before a +++ header")
            hunks.setdefault(stem, []).append((patch.name, "".join(old), "".join(new)))
    return hunks


def apply_patches(stem: str, txt: str, hunks: dict[str, list[tuple[str, str, str]]]) -> str:
    patched = False
    for name, old, new in hunks.get(stem, ()):
        if txt.count(old) != 1:
            raise SystemExit(f"{name}: hunk for {stem} matches {txt.count(old)} times; audit the patch")
        txt = txt.replace(old, new)
        patched = True
    return '#include "rules.h"\n' + txt if patched else txt
