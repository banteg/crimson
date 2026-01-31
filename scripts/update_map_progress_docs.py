from __future__ import annotations

import argparse
from pathlib import Path

import map_progress


def replace_block(text: str, start_marker: str, end_marker: str, new_lines: list[str]) -> str:
    lines = text.splitlines()
    try:
        start_index = lines.index(start_marker)
        end_index = lines.index(end_marker)
    except ValueError as exc:
        raise ValueError("map progress markers not found in docs") from exc
    if end_index < start_index:
        raise ValueError("map progress markers are out of order")
    updated = lines[:start_index] + [start_marker, *new_lines, end_marker] + lines[end_index + 1 :]
    return "\n".join(updated) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Update map progress section in docs.")
    parser.add_argument(
        "--metrics",
        type=Path,
        default=Path("docs/metrics.md"),
        help="metrics doc to update",
    )
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
        "--crimsonland-decompiled",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_decompiled.c"),
        help="path to crimsonland.exe decompiled C",
    )
    parser.add_argument(
        "--grim-decompiled",
        type=Path,
        default=Path("analysis/ghidra/raw/grim.dll_decompiled.c"),
        help="path to grim.dll decompiled C",
    )
    args = parser.parse_args()

    name_entries = map_progress.load_name_map(args.name_map)
    data_entries = map_progress.load_data_map(args.data_map)
    progress = [
        map_progress.compute_progress("Name map", name_entries, include_signatures=True),
        map_progress.compute_progress("Data map", data_entries, include_signatures=False),
    ]
    table_lines = map_progress.build_markdown_table(progress)

    metrics_path = args.metrics
    metrics_text = metrics_path.read_text(encoding="utf-8")
    metrics_text = replace_block(
        metrics_text,
        "<!-- map-progress:start -->",
        "<!-- map-progress:end -->",
        table_lines,
    )

    crimson_text = args.crimsonland_decompiled.read_text(encoding="utf-8", errors="ignore")
    grim_text = args.grim_decompiled.read_text(encoding="utf-8", errors="ignore")
    crimson_cov = map_progress.compute_data_map_coverage(data_entries, crimson_text, "crimsonland.exe")
    grim_cov = map_progress.compute_data_map_coverage(data_entries, grim_text, "grim.dll")
    total_cov = map_progress.combine_coverages([crimson_cov, grim_cov])
    coverage_lines = map_progress.build_coverage_table([crimson_cov, grim_cov, total_cov])
    metrics_text = replace_block(
        metrics_text,
        "<!-- data-map-coverage:start -->",
        "<!-- data-map-coverage:end -->",
        coverage_lines,
    )
    metrics_path.write_text(metrics_text, encoding="utf-8")
    print(f"Updated {metrics_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
