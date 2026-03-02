#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from crimson.schema_inventory import inventory_as_json, list_struct_classes, summarize_inventory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Inventory msgspec.Struct classes and likely duplicates.')
    parser.add_argument('--source-root', type=Path, default=Path('src'), help='Root directory to scan (default: src)')
    parser.add_argument(
        '--json-output',
        type=Path,
        default=None,
        help='Optional path to write full JSON inventory payload.',
    )
    parser.add_argument(
        '--print-json',
        action='store_true',
        help='Print the full JSON inventory payload to stdout.',
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = Path(args.source_root)

    structs = list_struct_classes(source_root=source_root)
    summary = summarize_inventory(structs=structs)

    print(f'TOTAL {summary.total_structs}')
    for bucket, count in summary.counts_by_bucket.items():
        print(f'BUCKET_{bucket.upper()} {count}')

    print(f'DUP_NAMES {len(summary.duplicate_names)}')
    for name, entries in summary.duplicate_names.items():
        locs = '; '.join(f'{item.path}:{item.lineno}' for item in entries)
        print(f'{name} | {locs}')

    payload = inventory_as_json(summary=summary, structs=structs)
    if args.json_output is not None:
        out = Path(args.json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload + '\n', encoding='utf-8')
    if bool(args.print_json):
        print(payload)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
