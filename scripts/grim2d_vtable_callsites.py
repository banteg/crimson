from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable


FUNC_HEADER_RE = re.compile(r"^/\*\s+(?P<name>[^\s]+)\s+@\s+[0-9A-Fa-f]+\s+\*/\s*$")
ASSIGN_ALIAS_RE = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(int\))?\*DAT_0048083c\b"
)
ALIAS_PROP_RE = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(int\))?(?P<src>[A-Za-z_][A-Za-z0-9_]*)\b"
)
CALLSITE_RE = re.compile(
    r"\(\*\*\(code \*\*\)\((?P<base>[^)]+?)\+\s*(?P<offset>0x[0-9A-Fa-f]+)\)\)"
)


def iter_callsites(lines: list[str]) -> list[dict[str, object]]:
    callsites: list[dict[str, object]] = []
    current_func = "<unknown>"
    aliases: set[str] = set()

    for idx, line in enumerate(lines, start=1):
        header_match = FUNC_HEADER_RE.match(line)
        if header_match:
            current_func = header_match.group("name")
            aliases = set()
            continue

        assign_match = ASSIGN_ALIAS_RE.search(line)
        if assign_match:
            aliases.add(assign_match.group("var"))
        else:
            prop_match = ALIAS_PROP_RE.search(line)
            if prop_match and prop_match.group("src") in aliases:
                aliases.add(prop_match.group("var"))

        match = CALLSITE_RE.search(line)
        if not match:
            continue

        base = match.group("base").strip()
        offset = match.group("offset").lower()
        base_clean = base.replace("(", "").replace(")", "").replace(" ", "")

        if "DAT_0048083c" in base:
            is_grim = True
        else:
            is_grim = any(base_clean == alias for alias in aliases)

        if not is_grim:
            continue

        callsites.append(
            {
                "offset_hex": offset,
                "function": current_func,
                "line": idx,
                "base_expr": base,
                "line_text": line.rstrip(),
            }
        )

    return callsites


def summarize(callsites: Iterable[dict[str, object]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for entry in callsites:
        offset = str(entry["offset_hex"])
        data = summary.setdefault(offset, {"callsites": 0, "unique_functions": 0})
        data["callsites"] += 1
    for offset, data in summary.items():
        funcs = {entry["function"] for entry in callsites if entry["offset_hex"] == offset}
        data["unique_functions"] = len(funcs)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect Grim2D vtable callsites from decompiled EXE.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("source/decompiled/crimsonland.exe_decompiled.c"),
        help="decompiled EXE path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("source/decompiled/grim2d_vtable_callsites.json"),
        help="output JSON path",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=Path("source/decompiled/grim2d_vtable_callsites_summary.json"),
        help="summary JSON path",
    )
    args = parser.parse_args()

    lines = args.input.read_text().splitlines()
    callsites = iter_callsites(lines)
    summary = summarize(callsites)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(callsites, indent=2) + "\n")
    args.summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
