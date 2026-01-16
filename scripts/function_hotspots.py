from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def load_functions(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        return data.get("functions", [])
    if isinstance(data, list):
        return data
    raise ValueError(f"unsupported JSON format: {type(data)}")


def analyze(functions: list[dict]) -> list[dict]:
    in_counts = Counter()
    for fn in functions:
        for callee in fn.get("calls", []):
            in_counts[callee] += 1

    rows = []
    for fn in functions:
        name = fn.get("name", "")
        rows.append(
            {
                "name": name,
                "address": fn.get("address", ""),
                "signature": fn.get("signature", ""),
                "in_calls": in_counts.get(name, 0),
                "out_calls": len(fn.get("calls", [])),
            }
        )
    rows.sort(key=lambda r: (r["in_calls"], r["out_calls"]), reverse=True)
    return rows


def write_csv(rows: list[dict], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["in_calls", "out_calls", "address", "name", "signature"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="List hotspot functions by call frequency")
    parser.add_argument(
        "inputs",
        nargs="*",
        type=Path,
        help="functions.json files to analyze",
    )
    parser.add_argument("--top", type=int, default=30, help="number of rows to show")
    parser.add_argument(
        "--only-fun",
        action="store_true",
        help="only include FUN_* functions",
    )
    parser.add_argument("--output", type=Path, help="write CSV to this path")
    args = parser.parse_args()

    inputs = args.inputs
    if not inputs:
        inputs = [
            Path("source/decompiled/crimsonland.exe_functions.json"),
            Path("source/decompiled/grim.dll_functions.json"),
        ]

    for path in inputs:
        functions = load_functions(path)
        rows = analyze(functions)
        if args.only_fun:
            rows = [row for row in rows if row["name"].startswith("FUN_")]
        rows = rows[: args.top]
        if args.output:
            output = args.output
            if output.is_dir():
                output = output / f"{path.stem}_hotspots.csv"
            write_csv(rows, output)
        print(path.name)
        for row in rows:
            print(
                f"{row['in_calls']:>4} {row['out_calls']:>4} {row['address']} {row['name']} {row['signature']}"
            )
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
