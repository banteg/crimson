from __future__ import annotations

from collections import defaultdict
import re
from pathlib import Path

from crimson.atlas import GRID_SIZE_BY_CODE, SPRITE_TABLE

ROOT = Path(__file__).resolve().parents[1]
C_PATH = ROOT / "output/crimsonland.exe_decompiled.c"
STRINGS_PATH = ROOT / "output/crimsonland.exe_strings.txt"

ADDR_RE = re.compile(r"^([0-9A-Fa-f]{8}):\s+(.*)$")
SYM_ADDR_RE = re.compile(r"_([0-9A-Fa-f]{8})")

LOAD_RE = re.compile(
    r"(?P<var>[A-Za-z0-9_]+)\s*=\s*(?:FUN_0042a670|FUN_0042a700|\(\*\*\(code \*\*\)\(\*DAT_0048083c \+ 0xc0\)\))\(s_[A-Za-z0-9_]+_(?P<addr>[0-9A-Fa-f]{8})\)"
)

SET_TEX_RE = re.compile(r"\+ 0xc4\)\)\((?P<var>[^,\)]+)")
SET_UV_RE = re.compile(r"\+ 0x104\)\)\((?P<grid>[^,]+),(?P<idx>[^\)]+)\)")
TABLE_RE = re.compile(r"FUN_0042e0a0\((?P<idx>[^\)]+)\)")


def parse_strings() -> dict[str, str]:
    addr_to_str: dict[str, str] = {}
    with STRINGS_PATH.open() as fh:
        for line in fh:
            m = ADDR_RE.match(line.strip())
            if not m:
                continue
            addr = m.group(1).lower()
            addr_to_str[addr] = m.group(2)
    return addr_to_str


def resolve_path(name: str) -> str:
    if "\\" in name or "/" in name or "." in name:
        return name
    for ext in (".jaz", ".tga", ".png", ".bmp", ".jpg"):
        candidate = ROOT / "game" / f"{name}{ext}"
        if candidate.exists():
            return str(candidate.relative_to(ROOT))
    return name


def parse_texture_symbols(addr_to_str: dict[str, str]) -> dict[str, str]:
    var_to_path: dict[str, str] = {}
    with C_PATH.open() as fh:
        for line in fh:
            m = LOAD_RE.search(line)
            if not m:
                continue
            addr = m.group("addr").lower()
            path = addr_to_str.get(addr)
            if not path:
                continue
            var_to_path[m.group("var")] = resolve_path(path)
    return var_to_path


def normalize_int(token: str) -> str:
    token = token.strip()
    if token.startswith("0x"):
        try:
            return str(int(token, 16))
        except ValueError:
            return token
    try:
        return str(int(token))
    except ValueError:
        return token


def sort_key(token: str) -> tuple[int, int | str]:
    try:
        return (0, int(token, 0))
    except ValueError:
        return (1, token)


def main() -> None:
    addr_to_str = parse_strings()
    var_to_path = parse_texture_symbols(addr_to_str)
    atlas_calls: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"direct": set(), "table": set()}
    )

    current: str | None = None
    with C_PATH.open() as fh:
        for line in fh:
            m = SET_TEX_RE.search(line)
            if m:
                var = m.group("var").strip()
                current = var if var in var_to_path else None

            if current is None:
                continue

            m = SET_UV_RE.search(line)
            if m:
                grid = normalize_int(m.group("grid"))
                idx = normalize_int(m.group("idx"))
                atlas_calls[current]["direct"].add(f"{grid},{idx}")

            m = TABLE_RE.search(line)
            if m:
                idx = normalize_int(m.group("idx"))
                atlas_calls[current]["table"].add(idx)

    print("Atlas usage by texture variable:\n")
    for var in sorted(atlas_calls):
        path = var_to_path.get(var, "?")
        direct = sorted(atlas_calls[var]["direct"])
        table = sorted(atlas_calls[var]["table"], key=sort_key)
        if not direct and not table:
            continue
        print(f"{var} -> {path}")
        if direct:
            print(f"  direct grid,index: {', '.join(direct)}")
        if table:
            resolved = []
            for idx in table:
                try:
                    entry = SPRITE_TABLE[int(idx, 0)]
                except (ValueError, IndexError):
                    resolved.append(idx)
                    continue
                grid = GRID_SIZE_BY_CODE.get(entry[0], "?")
                resolved.append(f"{idx} (grid {grid})")
            print(f"  table indices: {', '.join(resolved)}")
        print()


if __name__ == "__main__":
    main()
