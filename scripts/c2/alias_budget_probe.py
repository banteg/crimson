"""Probe how close a function is to the 0x400 alias-class budget (diagnostic only; no match credit).

A class id is handed out per symbol (`assign_symbol_alias_classes` 0x1071921c: locals, parameters,
inline-expansion locals, compiler temporaries and referenced globals), then per pointer root in class
order (`alias_class_for_symbol_set` 0x1075d456). Once `g_alias_class_count` reaches 0x400 every new root
gets class 1, which conflicts with everything. A store or call of class 1 inside a `lea` pointer's live
stretch makes `has_intervening_base_definition` 0x10731a50 return 1, so
`forward_substitute_single_def_ranges` 0x107306c1 keeps the pointer in a register.

For each requested N the script writes a variant of the scratch with N calls of a code-free inline helper
(`int t = v; return t;`, two symbol classes per call, no instructions) at the start of FUNCTION's body,
compiles it through field_records.py's preserving observer and prints the match ratio, the final class
count, the first pointer class, and the pointer roots that collapsed to class 1 (last roots collapse
first). N = 0 reports the unmodified scratch. C++ scratches only (the calls are statements placed
before the first declaration).

    uv run python scripts/c2/alias_budget_probe.py <scratch-dir> --out <new-dir> --expansions 0 244 245 256

The variants are diagnostics of the budget mechanism, not recoverable source.
See tools/match/c2/compiler/unfolded-field-pointers.md.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import field_records

HELPER = "static __inline int alias_budget_probe_id(int value)\n{\n    int copy = value;\n    return copy;\n}\n\n"


def variant(scratch: Path, out: Path, count: int) -> Path:
    config = (scratch / "scratch.conf").read_text()
    source_name = re.search(r"^SOURCE=(.+)$", config, re.MULTILINE).group(1).strip()
    function = re.search(r"^FUNCTION=(.+)$", config, re.MULTILINE).group(1).strip()
    text = (scratch / source_name).read_text()
    if count:
        head = re.search(rf"^[^\n;]*\b{re.escape(function)}\s*\([^)]*\)\s*\n\{{\n", text, re.MULTILINE)
        if head is None:
            raise SystemExit(f"cannot find the definition of {function}")
        calls = "".join(f"    alias_budget_probe_id({i});\n" for i in range(count))
        text = text[: head.start()] + HELPER + text[head.start() : head.end()] + calls + text[head.end() :]
    target = out / f"n{count}" / "scratch"
    target.mkdir(parents=True, exist_ok=False)
    (target / source_name).write_text(text)
    (target / "scratch.conf").write_text(config)
    return target


def summary(rows: list[dict], function: str) -> tuple[int, int | None, list[str]]:
    rows = [r for r in rows if function in r["function"]]
    first: dict[str, int] = {}
    for r in rows:
        if r["kind"] == "class":
            first.setdefault(r["base"] or f"sym{r['root_id']:#x}", r["result"])
    count = max((r["class_count"] for r in rows), default=0)
    real = [c for c in first.values() if c != 1]
    return count, min(real) if real else None, [k for k, v in first.items() if v == 1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the variants and traces")
    parser.add_argument("--expansions", type=int, nargs="+", default=[0])
    args = parser.parse_args()
    function = re.search(r"^FUNCTION=(.+)$", (args.scratch / "scratch.conf").read_text(), re.MULTILINE).group(1).strip()
    for count in args.expansions:
        scratch = variant(args.scratch.resolve(), args.out.resolve(), count)
        manifest, data = field_records.run(scratch, scratch.parent / "trace", None)
        classes, first_pointer, collapsed = summary(field_records.decode(data), function)
        print(
            f"N={count:<4} ratio {manifest['metrics']['ratio']:.4%}  classes {classes:#x}"
            f"  first pointer class {first_pointer}  collapsed ({len(collapsed)}): {', '.join(collapsed)}",
        )


if __name__ == "__main__":
    main()
