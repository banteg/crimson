from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class MapProgress:
    name: str
    total: int
    by_program: dict[str, int]
    with_signatures: int | None
    with_comments: int
    duplicate_names: int


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def load_name_map(path: Path) -> list[dict]:
    data = _load_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("entries"), list):
            return data["entries"]
        if isinstance(data.get("functions"), list):
            return data["functions"]
    raise ValueError(f"unsupported name map format: {type(data)}")


def load_data_map(path: Path) -> list[dict]:
    data = _load_json(path)
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        return data["entries"]
    if isinstance(data, list):
        return data
    raise ValueError(f"unsupported data map format: {type(data)}")


def count_by_program(entries: Iterable[dict]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for entry in entries:
        program = entry.get("program", "")
        if program:
            counts[program] += 1
    return dict(counts)


def count_duplicates(entries: Iterable[dict]) -> int:
    per_program: dict[str, Counter[str]] = {}
    for entry in entries:
        program = entry.get("program", "")
        name = entry.get("name", "")
        if not program or not name:
            continue
        per_program.setdefault(program, Counter())[name] += 1
    return sum(1 for counter in per_program.values() for count in counter.values() if count > 1)


def compute_progress(name: str, entries: list[dict], include_signatures: bool) -> MapProgress:
    by_program = count_by_program(entries)
    with_signatures = None
    if include_signatures:
        with_signatures = sum(1 for entry in entries if entry.get("signature"))
    with_comments = sum(1 for entry in entries if entry.get("comment"))
    duplicate_names = count_duplicates(entries)
    return MapProgress(
        name=name,
        total=len(entries),
        by_program=by_program,
        with_signatures=with_signatures,
        with_comments=with_comments,
        duplicate_names=duplicate_names,
    )


def format_count(value: int | None) -> str:
    return "n/a" if value is None else str(value)


def build_markdown_table(progress: Iterable[MapProgress]) -> list[str]:
    lines = [
        "| Map | Total entries | crimsonland.exe | grim.dll | With signatures | With comments | Duplicate names |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in progress:
        lines.append(
            "| {name} | {total} | {crimson} | {grim} | {sigs} | {comments} | {dupes} |".format(
                name=item.name,
                total=item.total,
                crimson=item.by_program.get("crimsonland.exe", 0),
                grim=item.by_program.get("grim.dll", 0),
                sigs=format_count(item.with_signatures),
                comments=item.with_comments,
                dupes=item.duplicate_names,
            )
        )
    return lines


def emit_table(progress: Iterable[MapProgress]) -> None:
    for line in build_markdown_table(progress):
        print(line)


def emit_json(progress: Iterable[MapProgress]) -> None:
    payload = []
    for item in progress:
        payload.append(
            {
                "map": item.name,
                "total": item.total,
                "by_program": item.by_program,
                "with_signatures": item.with_signatures,
                "with_comments": item.with_comments,
                "duplicate_names": item.duplicate_names,
            }
        )
    print(json.dumps(payload, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize name/data map progress.")
    parser.add_argument(
        "--name-map",
        type=Path,
        default=Path("analysis/ghidra/maps/name_map.json"),
        help="path to name_map.json",
    )
    parser.add_argument(
        "--data-map",
        type=Path,
        default=Path("analysis/ghidra/maps/data_map.json"),
        help="path to data_map.json",
    )
    parser.add_argument(
        "--format",
        choices=("md", "json"),
        default="md",
        help="output format",
    )
    args = parser.parse_args()

    name_entries = load_name_map(args.name_map)
    data_entries = load_data_map(args.data_map)
    progress = [
        compute_progress("Name map", name_entries, include_signatures=True),
        compute_progress("Data map", data_entries, include_signatures=False),
    ]

    if args.format == "json":
        emit_json(progress)
    else:
        emit_table(progress)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
