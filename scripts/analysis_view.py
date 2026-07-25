from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NAME_MAP = ROOT / "analysis" / "ghidra" / "maps" / "name_map.json"
ANNOTATIONS = ROOT / "analysis" / "annotations" / "functions.json"
GHIDRA_OVERLAY = ROOT / "analysis" / "overlays" / "ghidra_local_renames.json"
CALL_CONVENTIONS = {
    "__cdecl",
    "__fastcall",
    "__stdcall",
    "__thiscall",
    "__usercall",
    "__vectorcall",
}
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TYPE_SPACE_RE = re.compile(r"\s+")
TYPE_ONLY_TOKENS = {
    "__int8",
    "__int16",
    "__int32",
    "__int64",
    "bool",
    "char",
    "double",
    "float",
    "int",
    "long",
    "short",
    "uchar",
    "uint",
    "ulong",
    "ulonglong",
    "ushort",
    "void",
}
TYPE_ALIASES = (
    ("unsigned __int64", "u64"),
    ("unsigned long long", "u64"),
    ("ulonglong", "u64"),
    ("__int64", "i64"),
    ("long long", "i64"),
    ("unsigned __int32", "unsigned int"),
    ("__int32", "int"),
    ("unsigned __int16", "unsigned short"),
    ("__int16", "short"),
    ("unsigned __int8", "unsigned char"),
    ("__int8", "char"),
    ("uchar", "unsigned char"),
    ("ushort", "unsigned short"),
    ("uint", "unsigned int"),
    ("ulong", "unsigned long"),
)


@dataclass(frozen=True)
class Prototype:
    return_type: str
    calling_convention: str | None
    name: str
    params: tuple[str, ...]

    @property
    def has_varargs(self) -> bool:
        return any(param == "..." for param in self.params)


@dataclass(frozen=True)
class ToolReport:
    tool: str
    total: int
    mapped: int
    missing: tuple[dict[str, Any], ...]
    name_mismatches: tuple[tuple[dict[str, Any], dict[str, Any]], ...]
    signature_mismatches: tuple[tuple[dict[str, Any], dict[str, Any]], ...]

    @property
    def boundary_ok(self) -> bool:
        return not self.missing and not self.name_mismatches


def normalize_address(value: object) -> int:
    text = str(value).strip()
    if not text:
        raise ValueError("empty address")
    return int(text, 16)


def format_address(value: int) -> str:
    return f"0x{value:08x}"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_rows(path: Path) -> list[dict[str, Any]]:
    payload = load_json(path)
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("entries", payload.get("functions", []))
    else:
        raise TypeError(f"unsupported JSON root in {path}")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise TypeError(f"expected a list of objects in {path}")
    return rows


def load_function_metadata(path: Path, program: str, name: str) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise TypeError(f"expected an object in {path}")
    if str(payload.get("program", "")).lower() != program.lower():
        return {}
    functions = payload.get("functions", {})
    if not isinstance(functions, dict):
        raise TypeError(f"expected a functions object in {path}")
    metadata = functions.get(name, {})
    if not isinstance(metadata, dict):
        raise TypeError(f"expected function metadata for {name} in {path}")
    return metadata


def curated_rows(path: Path, program: str) -> list[dict[str, Any]]:
    return [
        row
        for row in load_rows(path)
        if str(row.get("program", "")).lower() == program.lower()
        and row.get("address")
        and row.get("name")
    ]


def split_args(raw: str) -> tuple[str, ...]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for char in raw:
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        if char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return tuple(args)


def parse_prototype(signature: str) -> Prototype | None:
    text = signature.strip().rstrip(";")
    if not text.endswith(")") or "(" not in text:
        return None
    left = text.find("(")
    right = text.rfind(")")
    if right < left:
        return None
    prefix = text[:left].strip()
    params_raw = text[left + 1 : right].strip()
    tokens = prefix.split()
    if len(tokens) < 2:
        return None
    name = tokens[-1]
    if not IDENT_RE.fullmatch(name):
        return None
    if name.lower() in TYPE_ONLY_TOKENS:
        return None
    calling_convention = next(
        (convention for convention in CALL_CONVENTIONS if convention in tokens[:-1]),
        None,
    )
    return_tokens = [
        token
        for token in tokens[:-1]
        if token not in CALL_CONVENTIONS
    ]
    if not return_tokens:
        return None
    params = () if not params_raw or params_raw == "void" else split_args(params_raw)
    return Prototype(
        return_type=" ".join(return_tokens),
        calling_convention=calling_convention,
        name=name,
        params=params,
    )


def normalize_type(value: str) -> str:
    text = TYPE_SPACE_RE.sub(" ", value.strip().lower())
    for source, replacement in TYPE_ALIASES:
        text = re.sub(rf"\b{re.escape(source)}\b", replacement, text)
    text = re.sub(r"\s*\*\s*", "*", text)
    return text


def prototype_shape(signature: str) -> tuple[str, int, bool] | None:
    prototype = parse_prototype(signature)
    if prototype is not None:
        return (
            normalize_type(prototype.return_type),
            len(prototype.params),
            prototype.has_varargs,
        )
    text = signature.strip().rstrip(";")
    if not text.endswith(")") or "(" not in text:
        return None
    left = text.find("(")
    right = text.rfind(")")
    if right < left:
        return None
    return_type = text[:left].strip()
    for convention in CALL_CONVENTIONS:
        return_type = return_type.replace(convention, "")
    return_type = TYPE_SPACE_RE.sub(" ", return_type).strip()
    if not return_type:
        return None
    params_raw = text[left + 1 : right].strip()
    params = () if not params_raw or params_raw == "void" else split_args(params_raw)
    return normalize_type(return_type), len(params), "..." in params


def snapshot_path(tool: str, program: str) -> Path:
    if tool == "ida":
        return ROOT / "analysis" / "ida" / "raw" / program / "functions.json"
    if tool == "ghidra":
        return ROOT / "analysis" / "ghidra" / "raw" / f"{program}_functions.json"
    raise ValueError(f"unsupported tool: {tool}")


def load_snapshot(tool: str, program: str) -> list[dict[str, Any]]:
    path = snapshot_path(tool, program)
    if not path.exists():
        raise FileNotFoundError(f"{tool} snapshot not found: {path}")
    return load_rows(path)


def load_binja_live(program: str) -> list[dict[str, Any]]:
    target = f"{program}.bndb"
    command = [
        "bn",
        "function",
        "list",
        "--target",
        target,
        "--format",
        "json",
        "--no-spill",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, list) or not all(isinstance(row, dict) for row in payload):
        raise TypeError("unexpected Binary Ninja function-list response")
    return payload


def compare_rows(
    tool: str,
    canonical: list[dict[str, Any]],
    observed: list[dict[str, Any]],
) -> ToolReport:
    observed_by_address = {
        normalize_address(row["address"]): row
        for row in observed
        if row.get("address")
    }
    missing: list[dict[str, Any]] = []
    name_mismatches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    signature_mismatches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    mapped = 0
    for expected in canonical:
        actual = observed_by_address.get(normalize_address(expected["address"]))
        if actual is None:
            missing.append(expected)
            continue
        mapped += 1
        if str(actual.get("name", "")) != str(expected["name"]):
            name_mismatches.append((expected, actual))
        expected_signature = str(expected.get("signature", "")).strip()
        actual_signature = str(actual.get("signature", "")).strip()
        if expected_signature and actual_signature:
            expected_shape = prototype_shape(expected_signature)
            actual_shape = prototype_shape(actual_signature)
            if expected_shape is not None and actual_shape != expected_shape:
                signature_mismatches.append((expected, actual))
    return ToolReport(
        tool=tool,
        total=len(canonical),
        mapped=mapped,
        missing=tuple(missing),
        name_mismatches=tuple(name_mismatches),
        signature_mismatches=tuple(signature_mismatches),
    )


def resolve_entry(
    rows: list[dict[str, Any]],
    query: str,
) -> dict[str, Any]:
    try:
        query_address = normalize_address(query)
    except ValueError:
        query_address = None
    for row in rows:
        if query_address is not None and normalize_address(row["address"]) == query_address:
            return row
        names = [str(row["name"]), *(str(alias) for alias in row.get("aliases", []))]
        if query in names:
            return row
    raise LookupError(f"function not found in name map: {query}")


def print_observed(tool: str, entry: dict[str, Any], program: str) -> None:
    address = normalize_address(entry["address"])
    observed = {
        normalize_address(row["address"]): row
        for row in load_snapshot(tool, program)
        if row.get("address")
    }.get(address)
    if observed is None:
        print(f"{tool}: missing from {snapshot_path(tool, program).relative_to(ROOT)}")
        return
    print(f"{tool}: {observed.get('name', '<unnamed>')} @ {format_address(address)}")
    signature = str(observed.get("signature", "")).strip()
    if signature:
        print(f"  {signature}")


def command_show(args: argparse.Namespace) -> int:
    rows = curated_rows(args.name_map, args.program)
    entry = resolve_entry(rows, args.query)
    address = normalize_address(entry["address"])
    name = str(entry["name"])
    print(f"canonical: {name} @ {format_address(address)}")
    if entry.get("signature"):
        print(f"  {entry['signature']}")
    if entry.get("comment"):
        print(f"  {entry['comment']}")
    annotations = load_function_metadata(ANNOTATIONS, args.program, name)
    notes = annotations.get("notes", [])
    if notes:
        print("annotations:")
        for note in notes:
            print(f"  - {note}")
    overlay = load_function_metadata(GHIDRA_OVERLAY, args.program, name)
    if overlay:
        print("ghidra local overlay:")
        for source, replacement in overlay.items():
            print(f"  {source} -> {replacement}")
    print()
    print("binary-ninja:")
    print(
        f"  bn decompile {format_address(address)}"
        f" --target {args.program}.bndb",
    )
    for tool in ("ida", "ghidra"):
        try:
            print_observed(tool, entry, args.program)
        except FileNotFoundError as error:
            print(f"{tool}: {error}")
    return 0


def print_report(report: ToolReport, detail_limit: int) -> None:
    status = "ok" if report.boundary_ok else "drift"
    print(
        f"{report.tool}: {status}; mapped {report.mapped}/{report.total}; "
        f"missing {len(report.missing)}; name mismatches {len(report.name_mismatches)}; "
        f"signature-shape mismatches {len(report.signature_mismatches)}",
    )
    details = [
        *(f"missing {row['name']} @ {row['address']}" for row in report.missing),
        *(
            f"name {expected['name']} != {actual.get('name')} @ {expected['address']}"
            for expected, actual in report.name_mismatches
        ),
        *(
            f"signature {expected['name']} @ {expected['address']}"
            for expected, _actual in report.signature_mismatches
        ),
    ]
    for detail in details[:detail_limit]:
        print(f"  {detail}")
    if len(details) > detail_limit:
        print(f"  ... {len(details) - detail_limit} more")


def command_check(args: argparse.Namespace) -> int:
    canonical = curated_rows(args.name_map, args.program)
    reports: list[ToolReport] = []
    for tool in ("ida", "ghidra"):
        reports.append(compare_rows(tool, canonical, load_snapshot(tool, args.program)))
    if args.binja_live:
        reports.insert(0, compare_rows("binary-ninja", canonical, load_binja_live(args.program)))
    for report in reports:
        print_report(report, args.detail_limit)
    boundary_drift = any(not report.boundary_ok for report in reports)
    signature_drift = any(report.signature_mismatches for report in reports)
    return int(boundary_drift or (args.strict_signatures and signature_drift))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve and compare address-keyed Binary Ninja, IDA, and Ghidra views.",
    )
    parser.add_argument("--name-map", type=Path, default=DEFAULT_NAME_MAP)
    subparsers = parser.add_subparsers(dest="command", required=True)

    show = subparsers.add_parser("show", help="resolve one curated function")
    show.add_argument("query", help="canonical name, alias, or address")
    show.add_argument("--program", default="crimsonland.exe")
    show.set_defaults(handler=command_show)

    check = subparsers.add_parser("check", help="compare structured snapshots")
    check.add_argument("--program", default="crimsonland.exe")
    check.add_argument("--binja-live", action="store_true")
    check.add_argument("--strict-signatures", action="store_true")
    check.add_argument("--detail-limit", type=int, default=12)
    check.set_defaults(handler=command_check)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
