from __future__ import annotations

from collections import defaultdict
import argparse
import json
import re
from pathlib import Path

from crimson.atlas import GRID_SIZE_BY_CODE, SPRITE_TABLE

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_C_PATH = ROOT / "source/decompiled/crimsonland.exe_decompiled.c"
DEFAULT_STRINGS_PATH = ROOT / "source/decompiled/crimsonland.exe_strings.txt"
DEFAULT_ASSETS_ROOT = ROOT / "assets" / "crimson"

ADDR_RE = re.compile(r"^([0-9A-Fa-f]{8}):\s+(.*)$")
LOAD_RE = re.compile(
    r"(?P<var>[A-Za-z0-9_]+)\s*=\s*(?:"
    r"FUN_0042a670|FUN_0042a700|texture_get_or_load|texture_get_or_load_alt"
    r"|\(\*\*\(code \*\*\)\(\*DAT_0048083c \+ 0xc0\)\)"
    r")\(s_[A-Za-z0-9_]+_(?P<addr>[0-9A-Fa-f]{8})\)"
)

CALL_TEX_MARKER = "+ 0xc4))("
CALL_UV_MARKER = "+ 0x104))("
TABLE_MARKER = "FUN_0042e0a0("


def parse_strings(path: Path) -> dict[str, str]:
    addr_to_str: dict[str, str] = {}
    with path.open() as fh:
        for line in fh:
            m = ADDR_RE.match(line.strip())
            if not m:
                continue
            addr = m.group(1).lower()
            addr_to_str[addr] = m.group(2)
    return addr_to_str


def resolve_path(name: str, assets_root: Path) -> str:
    normalized = name.replace("\\", "/")
    path = Path(normalized)
    candidates: list[Path] = []
    if path.suffix:
        candidates.append(assets_root / path)
        if path.suffix.lower() == ".jaz":
            candidates.append(assets_root / path.with_suffix(".png"))
    else:
        for ext in (".png", ".jaz", ".tga", ".bmp", ".jpg"):
            candidates.append(assets_root / f"{normalized}{ext}")
            candidates.append(assets_root / "game" / f"{normalized}{ext}")
    for candidate in candidates:
        if candidate.exists():
            return str(candidate.relative_to(ROOT))
    if not path.suffix and "/" not in normalized:
        for ext in (".png", ".jaz", ".tga", ".bmp", ".jpg"):
            matches = sorted(assets_root.rglob(f"{normalized}{ext}"))
            if matches:
                return str(matches[0].relative_to(ROOT))
    return normalized


def parse_texture_symbols(addr_to_str: dict[str, str], c_path: Path, assets_root: Path) -> dict[str, str]:
    var_to_path: dict[str, str] = {}
    with c_path.open() as fh:
        for line in fh:
            m = LOAD_RE.search(line)
            if not m:
                continue
            addr = m.group("addr").lower()
            path = addr_to_str.get(addr)
            if not path:
                continue
            var_to_path[m.group("var")] = resolve_path(path, assets_root)
    return var_to_path


def normalize_value(token: str) -> int | str:
    token = token.strip()
    if not token:
        return ""
    try:
        return int(token, 0)
    except ValueError:
        return token


def sort_key(token: int | str) -> tuple[int, int | str]:
    if isinstance(token, int):
        return (0, token)
    return (1, str(token))


def split_args(raw: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in raw:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def extract_call_args(line: str, marker: str) -> list[str] | None:
    idx = line.find(marker)
    if idx == -1:
        return None
    start = idx + len(marker)
    depth = 0
    end = None
    for i in range(start, len(line)):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                end = i
                break
            depth -= 1
    if end is None:
        return None
    return split_args(line[start:end])


def strip_cast(token: str) -> str:
    cleaned = token.strip()
    while cleaned.startswith("(") and ")" in cleaned:
        closing = cleaned.find(")")
        cleaned = cleaned[closing + 1 :].strip()
    return cleaned.lstrip("*& ")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan decompiled code for atlas usage.")
    parser.add_argument("--c-path", type=Path, default=DEFAULT_C_PATH)
    parser.add_argument("--strings-path", type=Path, default=DEFAULT_STRINGS_PATH)
    parser.add_argument(
        "--assets-root",
        type=Path,
        default=DEFAULT_ASSETS_ROOT,
        help="assets root for path resolution",
    )
    parser.add_argument("--output-json", type=Path, help="write JSON manifest to this path")
    args = parser.parse_args()

    addr_to_str = parse_strings(args.strings_path)
    var_to_path = parse_texture_symbols(addr_to_str, args.c_path, args.assets_root)
    atlas_calls: dict[str, dict[str, set[tuple[int | str, int | str]] | set[int | str]]] = defaultdict(
        lambda: {"direct": set(), "table": set()}
    )

    current: str | None = None
    with args.c_path.open() as fh:
        for line in fh:
            tex_args = extract_call_args(line, CALL_TEX_MARKER)
            if tex_args:
                var = strip_cast(tex_args[0])
                current = var if var in var_to_path else None

            if current is None:
                continue

            uv_args = extract_call_args(line, CALL_UV_MARKER)
            if uv_args and len(uv_args) >= 2:
                grid = normalize_value(strip_cast(uv_args[0]))
                idx = normalize_value(strip_cast(uv_args[1]))
                atlas_calls[current]["direct"].add((grid, idx))

            table_args = extract_call_args(line, TABLE_MARKER)
            if table_args:
                idx = normalize_value(strip_cast(table_args[0]))
                atlas_calls[current]["table"].add(idx)

    textures: list[dict[str, object]] = []
    print("Atlas usage by texture variable:\n")
    for var in sorted(atlas_calls):
        path = var_to_path.get(var, "?")
        direct = sorted(atlas_calls[var]["direct"], key=lambda t: (sort_key(t[0]), sort_key(t[1])))
        table = sorted(atlas_calls[var]["table"], key=sort_key)
        if not direct and not table:
            continue
        print(f"{var} -> {path}")
        if direct:
            rendered = []
            for grid, idx in direct:
                rendered.append(f"{grid},{idx}")
            print(f"  direct grid,index: {', '.join(rendered)}")
        if table:
            resolved = []
            for idx in table:
                if isinstance(idx, int) and 0 <= idx < len(SPRITE_TABLE):
                    entry = SPRITE_TABLE[idx]
                    grid = GRID_SIZE_BY_CODE.get(entry[0], "?")
                    resolved.append(f"{idx} (grid {grid})")
                else:
                    resolved.append(str(idx))
            print(f"  table indices: {', '.join(resolved)}")
        print()

        textures.append(
            {
                "var": var,
                "texture": path,
                "direct": [{"grid": grid, "index": idx} for grid, idx in direct],
                "table_indices": table,
            }
        )

    if args.output_json:
        payload = {"textures": textures}
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
