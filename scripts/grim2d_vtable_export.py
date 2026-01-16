from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


CALLING_CONVENTIONS = {"__cdecl", "__stdcall", "__thiscall", "__fastcall"}


def parse_hex(value: str | None) -> int | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    try:
        return int(text, 16)
    except ValueError:
        return None


def load_functions(path: Path) -> dict[int, dict[str, Any]]:
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        funcs = data.get("functions", [])
    else:
        funcs = data
    mapping: dict[int, dict[str, Any]] = {}
    for fn in funcs:
        addr = parse_hex(fn.get("address"))
        if addr is None:
            continue
        mapping[addr] = fn
    return mapping


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_signature(signature: str) -> tuple[str | None, int | None]:
    sig = signature.strip()
    if not sig:
        return None, None
    if "(" not in sig:
        return None, None
    head, tail = sig.split("(", 1)
    head = head.strip()
    if not head:
        return None, None
    parts = head.split()
    if len(parts) < 2:
        return None, None
    ret_parts = [p for p in parts[:-1] if p not in CALLING_CONVENTIONS]
    return_type = " ".join(ret_parts).strip() or None

    params = tail.rsplit(")", 1)[0].strip()
    if not params or params == "void":
        param_count = 0
    else:
        param_count = len([p for p in params.split(",") if p.strip()])
    return return_type, param_count


def normalize_signature(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip()


def update_entry_names(rows: list[dict[str, str]], functions: dict[int, dict[str, Any]]) -> None:
    for row in rows:
        addr = parse_hex(row.get("func_addr"))
        if addr is None:
            continue
        fn = functions.get(addr)
        if not fn:
            continue
        name = fn.get("name") or row.get("func_name")
        if name:
            row["func_name"] = name


def update_map_rows(rows: list[dict[str, str]], functions: dict[int, dict[str, Any]]) -> None:
    for row in rows:
        addr = parse_hex(row.get("func_addr"))
        if addr is None:
            continue
        fn = functions.get(addr)
        if not fn:
            continue
        name = fn.get("name")
        signature = normalize_signature(fn.get("signature"))
        if name:
            row["func_name"] = name
        if signature:
            row["signature"] = signature
            return_type, param_count = parse_signature(signature)
            if return_type:
                row["return_type"] = return_type
            if param_count is not None:
                row["param_count"] = str(param_count)


def sample_list(value: str | None) -> list[str]:
    if not value:
        return []
    items = [v.strip() for v in value.split(";") if v.strip()]
    return items


def int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def to_json_calls(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        output.append(
            {
                "offset_hex": row.get("offset_hex", ""),
                "offset_dec": int_or_none(row.get("offset_dec")),
                "callsites": int_or_none(row.get("callsites")) or 0,
                "unique_functions": int_or_none(row.get("unique_functions")) or 0,
                "sample_calls": sample_list(row.get("sample_calls")),
            }
        )
    return output


def to_json_entries(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        output.append(
            {
                "index": int_or_none(row.get("index")),
                "offset_hex": row.get("offset_hex", ""),
                "offset_dec": int_or_none(row.get("offset_dec")),
                "func_addr": row.get("func_addr") or None,
                "func_name": row.get("func_name") or "",
                "section": row.get("section") or "",
            }
        )
    return output


def to_json_map(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        output.append(
            {
                "offset_hex": row.get("offset_hex", ""),
                "offset_dec": int_or_none(row.get("offset_dec")),
                "callsites": int_or_none(row.get("callsites")) or 0,
                "unique_functions": int_or_none(row.get("unique_functions")) or 0,
                "sample_calls": sample_list(row.get("sample_calls")),
                "func_addr": row.get("func_addr") or None,
                "section": row.get("section") or "",
                "func_name": row.get("func_name") or "",
                "func_size": int_or_none(row.get("func_size")),
                "calling_convention": row.get("calling_convention") or "",
                "return_type": row.get("return_type") or "",
                "param_count": int_or_none(row.get("param_count")),
                "signature": row.get("signature") or "",
                "source_type": row.get("source_type") or "",
            }
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert Grim2D vtable CSVs to JSON and refresh names.")
    parser.add_argument(
        "--functions",
        type=Path,
        default=Path("source/decompiled/grim.dll_functions.json"),
        help="grim.dll functions JSON",
    )
    parser.add_argument(
        "--calls",
        type=Path,
        default=Path("source/decompiled/grim2d_vtable_calls.csv"),
        help="calls CSV path",
    )
    parser.add_argument(
        "--entries",
        type=Path,
        default=Path("source/decompiled/grim2d_vtable_entries.csv"),
        help="entries CSV path",
    )
    parser.add_argument(
        "--map",
        type=Path,
        default=Path("source/decompiled/grim2d_vtable_map.csv"),
        help="map CSV path",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("source/decompiled"),
        help="output directory for JSON files",
    )
    parser.add_argument(
        "--update-csv",
        action="store_true",
        help="rewrite CSVs with refreshed names/signatures",
    )
    args = parser.parse_args()

    functions = load_functions(args.functions)

    call_rows = read_csv(args.calls)
    entry_rows = read_csv(args.entries)
    map_rows = read_csv(args.map)

    update_entry_names(entry_rows, functions)
    update_map_rows(map_rows, functions)

    if args.update_csv:
        write_csv(
            args.entries,
            entry_rows,
            ["index", "offset_hex", "offset_dec", "func_addr", "func_name", "section"],
        )
        write_csv(
            args.map,
            map_rows,
            [
                "offset_hex",
                "offset_dec",
                "callsites",
                "unique_functions",
                "sample_calls",
                "func_addr",
                "section",
                "func_name",
                "func_size",
                "calling_convention",
                "return_type",
                "param_count",
                "signature",
                "source_type",
            ],
        )

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "grim2d_vtable_calls.json").write_text(
        json.dumps(to_json_calls(call_rows), indent=2) + "\n"
    )
    (output_dir / "grim2d_vtable_entries.json").write_text(
        json.dumps(to_json_entries(entry_rows), indent=2) + "\n"
    )
    (output_dir / "grim2d_vtable_map.json").write_text(
        json.dumps(to_json_map(map_rows), indent=2) + "\n"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
