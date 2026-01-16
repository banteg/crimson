from __future__ import annotations

import argparse
import json
from collections import deque
from pathlib import Path
from typing import Iterable


def load_functions(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "callGraph" in data:
        graph = data.get("callGraph", {})
        return {name: {"name": name, "calls": entry.get("calls", [])} for name, entry in graph.items()}
    if isinstance(data, dict):
        functions = data.get("functions", [])
    else:
        functions = data
    return {fn["name"]: fn for fn in functions}


def load_by_address(path: Path) -> dict[int, dict]:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "callGraph" in data:
        return {}
    if isinstance(data, dict):
        functions = data.get("functions", [])
    else:
        functions = data
    by_addr: dict[int, dict] = {}
    for fn in functions:
        addr = fn.get("address", "")
        if not addr:
            continue
        if addr.startswith("0x"):
            addr = addr[2:]
        by_addr[int(addr, 16)] = fn
    return by_addr


def trace(
    functions: dict[str, dict],
    entry: str,
    max_depth: int = 3,
    skip_external: bool = False,
) -> list[tuple[int, str, list[str]]]:
    results: list[tuple[int, str, list[str]]] = []
    seen: set[str] = set()
    queue = deque([(entry, 0)])

    while queue:
        name, depth = queue.popleft()
        if name in seen:
            continue
        seen.add(name)
        fn = functions.get(name)
        if not fn:
            continue
        calls = [c for c in fn.get("calls", []) if isinstance(c, str)]
        if skip_external:
            calls = [c for c in calls if c in functions]
        results.append((depth, name, calls))
        if depth >= max_depth:
            continue
        for callee in calls:
            if callee in functions:
                queue.append((callee, depth + 1))
    return results


def format_tree(rows: Iterable[tuple[int, str, list[str]]]) -> str:
    lines: list[str] = []
    for depth, name, calls in rows:
        indent = "  " * depth
        if calls:
            lines.append(f"{indent}- {name} -> {', '.join(calls[:8])}{' ...' if len(calls) > 8 else ''}")
        else:
            lines.append(f"{indent}- {name}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Trace call graph from entrypoint")
    parser.add_argument(
        "functions_json",
        type=Path,
        nargs="?",
        default=Path("source/decompiled/crimsonland.exe_functions.json"),
        help="functions.json path",
    )
    parser.add_argument("--entry", type=str, default="entry")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--skip-external", action="store_true")
    parser.add_argument("--out", type=Path, help="write output to file")
    args = parser.parse_args()

    functions = load_functions(args.functions_json)
    if args.entry not in functions:
        raise SystemExit(f"entry not found: {args.entry}")
    rows = trace(functions, args.entry, args.depth, args.skip_external)
    output = format_tree(rows)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
