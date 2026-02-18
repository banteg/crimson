from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AST_GREP_INLINE_RULE = "\n".join(
    (
        "id: c-fn",
        "language: C",
        "rule:",
        "  kind: function_definition",
    ),
)

ADDRESS_COMMENT_RE = re.compile(r"/\*\s*([A-Za-z0-9_]+)\s*@\s*([0-9A-Fa-f]{8})\s*\*/")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    start: int
    end: int
    start_line: int
    end_line: int
    address: str | None
    text: str


@dataclass(frozen=True)
class NameMapEntry:
    address: str
    name: str
    signature: str | None


@dataclass(frozen=True)
class CallGraph:
    by_name: dict[str, list[str]]
    name_by_address: dict[str, str]


def _normalize_address(value: str) -> str | None:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return None
    if not re.fullmatch(r"[0-9a-f]+", raw):
        return None
    return f"0x{raw.zfill(8)}"


def _safe_symbol_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _run_ast_grep_functions(source: Path) -> list[dict[str, Any]]:
    cmd = [
        "sg",
        "scan",
        str(source),
        "--inline-rules",
        AST_GREP_INLINE_RULE,
        "--json=stream",
    ]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _parse_function_name(signature_line: str) -> str:
    head = signature_line.split("(", 1)[0]
    tokens = IDENTIFIER_RE.findall(head)
    if not tokens:
        raise ValueError(f"could not parse function name from signature: {signature_line!r}")
    return tokens[-1]


def _address_for_function(raw_text: str, fn_name: str, fn_start: int) -> tuple[str | None, int | None]:
    prefix = raw_text[:fn_start]
    matches = list(ADDRESS_COMMENT_RE.finditer(prefix))
    if not matches:
        return None, None
    near_matches = [m for m in matches if fn_start - m.start() <= 800]
    if not near_matches:
        return None, None

    for match in reversed(near_matches):
        name, address = match.group(1), match.group(2)
        if name == fn_name:
            return address, match.start()

    last = near_matches[-1]
    return last.group(2), last.start()


def _apply_signature_override(text: str, signature: str | None) -> str:
    if not signature:
        return text
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("/*"):
            continue
        if "(" in stripped and stripped.endswith(")"):
            lines[idx] = signature
            return "\n".join(lines) + "\n"
        return text
    return text


def _apply_identifier_renames(text: str, mapping: dict[str, str]) -> str:
    valid_items: list[tuple[str, str]] = []
    for old, new in mapping.items():
        if old == new:
            continue
        if IDENTIFIER_RE.fullmatch(old) is None:
            continue
        if IDENTIFIER_RE.fullmatch(new) is None:
            continue
        valid_items.append((old, new))
    if not valid_items:
        return text

    valid_items.sort(key=lambda item: len(item[0]), reverse=True)
    by_old = dict(valid_items)
    pattern = re.compile(r"\b(" + "|".join(re.escape(old) for old, _ in valid_items) + r")\b")
    return pattern.sub(lambda m: by_old[m.group(1)], text)


def build_function_slices(source: Path) -> dict[str, FunctionSlice]:
    raw = source.read_text()
    rows = _run_ast_grep_functions(source)
    out: dict[str, FunctionSlice] = {}
    for row in rows:
        signature = str(row["text"]).splitlines()[0]
        name = _parse_function_name(signature)
        rng = row["range"]
        start = int(rng["byteOffset"]["start"])
        end = int(rng["byteOffset"]["end"])
        start_line = int(rng["start"]["line"])
        end_line = int(rng["end"]["line"])
        address, comment_start = _address_for_function(raw, name, start)
        text_start = comment_start if comment_start is not None else start
        text = raw[text_start:end].strip() + "\n"
        out[name] = FunctionSlice(
            name=name,
            start=text_start,
            end=end,
            start_line=start_line,
            end_line=end_line,
            address=address,
            text=text,
        )
    return out


def load_call_graph(functions_json: Path) -> CallGraph:
    obj = json.loads(functions_json.read_text())
    rows = obj if isinstance(obj, list) else obj.get("functions", [])
    by_name: dict[str, list[str]] = {}
    name_by_address: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", ""))
        if not name:
            continue
        calls = [str(x) for x in row.get("calls", []) if isinstance(x, str)]
        by_name[name] = calls
        addr = _normalize_address(str(row.get("address", "")))
        if addr is not None:
            name_by_address[addr] = name
    return CallGraph(by_name=by_name, name_by_address=name_by_address)


def load_name_map(path: Path | None, program: str) -> tuple[dict[str, NameMapEntry], dict[str, str]]:
    if path is None or not path.exists():
        return {}, {}
    obj = json.loads(path.read_text())
    rows = obj if isinstance(obj, list) else obj.get("entries", [])
    by_address: dict[str, NameMapEntry] = {}
    address_by_name: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        entry_program = row.get("program")
        if isinstance(entry_program, str) and entry_program and entry_program != program:
            continue
        address = _normalize_address(str(row.get("address", "")))
        name = str(row.get("name", "")).strip()
        if address is None or not name:
            continue
        signature_raw = row.get("signature")
        signature = str(signature_raw).strip() if isinstance(signature_raw, str) and signature_raw.strip() else None
        by_address[address] = NameMapEntry(address=address, name=name, signature=signature)
        address_by_name[name] = address
    return by_address, address_by_name


def load_local_renames(path: Path | None, output_dir: Path) -> tuple[dict[str, dict[str, str]], Path | None]:
    candidate = path or (output_dir / "work" / "local_renames.json")
    if not candidate.exists():
        return {}, None
    obj = json.loads(candidate.read_text())
    data = obj.get("functions") if isinstance(obj, dict) and isinstance(obj.get("functions"), dict) else obj
    if not isinstance(data, dict):
        raise TypeError(f"local rename file must be an object: {candidate}")

    out: dict[str, dict[str, str]] = {}
    for key, renames in data.items():
        if not isinstance(key, str) or not isinstance(renames, dict):
            continue
        normalized: dict[str, str] = {}
        for old, new in renames.items():
            if not isinstance(old, str) or not isinstance(new, str):
                continue
            old = old.strip()
            new = new.strip()
            if not old or not new or old == new:
                continue
            normalized[old] = new
        if normalized:
            out[key] = normalized
    return out, candidate


def resolve_targets(
    requested_targets: list[str],
    graph: CallGraph,
    name_map_address_by_name: dict[str, str],
) -> tuple[list[str], dict[str, str], list[str]]:
    resolved: list[str] = []
    resolved_by_request: dict[str, str] = {}
    unresolved: list[str] = []

    for target in requested_targets:
        if target in graph.by_name:
            resolved.append(target)
            resolved_by_request[target] = target
            continue

        target_addr = _normalize_address(target)
        if target_addr is not None and target_addr in graph.name_by_address:
            resolved_name = graph.name_by_address[target_addr]
            resolved.append(resolved_name)
            resolved_by_request[target] = resolved_name
            continue

        mapped_addr = name_map_address_by_name.get(target)
        if mapped_addr is not None and mapped_addr in graph.name_by_address:
            resolved_name = graph.name_by_address[mapped_addr]
            resolved.append(resolved_name)
            resolved_by_request[target] = resolved_name
            continue

        unresolved.append(target)

    return _dedupe_keep_order(resolved), resolved_by_request, unresolved


def expand_targets(targets: list[str], graph: dict[str, list[str]], call_depth: int) -> set[str]:
    wanted: set[str] = set(targets)
    if call_depth <= 0:
        return wanted
    queue: deque[tuple[str, int]] = deque((name, 0) for name in targets)
    while queue:
        name, depth = queue.popleft()
        if depth >= call_depth:
            continue
        for callee in graph.get(name, []):
            if callee in wanted:
                continue
            wanted.add(callee)
            queue.append((callee, depth + 1))
    return wanted


def _sort_key(fn: FunctionSlice) -> tuple[int, int, str]:
    if fn.address is None:
        return (1, fn.start, fn.name)
    return (0, int(fn.address, 16), fn.name)


def _rename_mapping_for_function(
    fn: FunctionSlice,
    mapped_name: str,
    local_renames: dict[str, dict[str, str]],
) -> dict[str, str]:
    keys: list[str] = [fn.name, mapped_name]
    normalized_addr = _normalize_address(fn.address or "")
    if normalized_addr is not None:
        keys.extend(
            [
                normalized_addr,
                normalized_addr[2:],
                normalized_addr.upper(),
                normalized_addr[2:].upper(),
            ],
        )

    merged: dict[str, str] = {}
    for key in keys:
        mapping = local_renames.get(key)
        if mapping is None:
            continue
        merged.update(mapping)
    return merged


def write_extraction(
    source: Path,
    out_dir: Path,
    requested_targets: list[str],
    resolved_targets: list[str],
    resolved_by_request: dict[str, str],
    unresolved_targets: list[str],
    call_depth: int,
    graph: CallGraph,
    extracted: list[FunctionSlice],
    missing: list[str],
    name_map_by_address: dict[str, NameMapEntry],
    name_map_path: Path | None,
    local_renames: dict[str, dict[str, str]],
    local_renames_path: Path | None,
) -> None:
    functions_dir = out_dir / "functions"
    work_dir = out_dir / "work"
    functions_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    extracted_by_name = {fn.name: fn for fn in extracted}

    display_name_by_canonical: dict[str, str] = {}

    for fn in extracted:
        normalized_addr = _normalize_address(fn.address or "")
        map_entry = name_map_by_address.get(normalized_addr) if normalized_addr is not None else None
        display_name = map_entry.name if map_entry is not None else fn.name
        display_name_by_canonical[fn.name] = display_name
        signature = map_entry.signature if map_entry is not None else None

        rendered_text = _apply_signature_override(fn.text, signature)
        addr_for_path = fn.address.lower() if fn.address else f"line_{fn.start_line:05d}"
        out_path = functions_dir / f"{addr_for_path}_{_safe_symbol_name(display_name)}.c"

        header = [
            f"/* source: {source} */",
            f"/* function_original: {fn.name} */",
            f"/* function_mapped: {display_name} */",
            f"/* address: {normalized_addr} */" if normalized_addr is not None else "/* address: unknown */",
            f"/* byte_range: [{fn.start}, {fn.end}) */",
            "",
        ]
        out_path.write_text("\n".join(header) + rendered_text)

    for target in resolved_targets:
        fn = extracted_by_name.get(target)
        if fn is None:
            continue

        mapped_name = display_name_by_canonical.get(fn.name, fn.name)
        addr_for_path = fn.address.lower() if fn.address else f"line_{fn.start_line:05d}"
        work_path = work_dir / f"{addr_for_path}_{_safe_symbol_name(mapped_name)}.work.c"

        normalized_addr = _normalize_address(fn.address or "")
        map_entry = name_map_by_address.get(normalized_addr) if normalized_addr is not None else None
        signature = map_entry.signature if map_entry is not None else None
        rendered_text = _apply_signature_override(fn.text, signature)

        if work_path.exists():
            work_text = work_path.read_text()
        else:
            header = [
                f"/* WORK COPY: {mapped_name} */",
                "/*",
                "  Use this file for variable renames and section comments.",
                "  Keep branch labels and address anchors intact for parity tracing.",
                "*/",
                "",
            ]
            work_text = "\n".join(header) + rendered_text

        rename_map = _rename_mapping_for_function(fn, mapped_name, local_renames)
        next_text = _apply_identifier_renames(work_text, rename_map)
        if next_text != work_text:
            work_path.write_text(next_text)
        elif not work_path.exists():
            work_path.write_text(next_text)

    callgraph_lines: list[str] = []
    callgraph_lines.append("# direct callgraph")
    callgraph_lines.append("")
    for requested in requested_targets:
        resolved = resolved_by_request.get(requested)
        if resolved is None:
            callgraph_lines.append(f"{requested} (unresolved)")
            callgraph_lines.append("")
            continue
        fn = extracted_by_name.get(resolved)
        display_name = display_name_by_canonical.get(resolved, resolved)
        addr = _normalize_address(fn.address or "") if fn is not None else None
        callgraph_lines.append(f"{requested} -> {display_name} ({addr or 'unknown'})")
        for callee in graph.by_name.get(resolved, []):
            marker = "extracted" if callee in extracted_by_name else "missing"
            callee_display = display_name_by_canonical.get(callee, callee)
            callgraph_lines.append(f"  -> {callee_display} [{marker}]")
        callgraph_lines.append("")
    (out_dir / "callgraph.txt").write_text("\n".join(callgraph_lines))

    lines: list[str] = []
    lines.append("# decompile hotspot extraction")
    lines.append("")
    lines.append("This folder is analysis-only and does not alter runtime code.")
    lines.append("")
    lines.append(f"- source: `{source}`")
    lines.append(f"- extracted functions: `{len(extracted)}`")
    lines.append(f"- requested targets: `{', '.join(requested_targets)}`")
    lines.append(f"- resolved targets: `{', '.join(resolved_targets) if resolved_targets else '(none)'}`")
    if unresolved_targets:
        lines.append(f"- unresolved targets: `{', '.join(unresolved_targets)}`")
    lines.append(f"- call depth: `{call_depth}`")
    if name_map_path is not None and name_map_path.exists():
        lines.append(f"- name map: `{name_map_path}`")
    else:
        lines.append("- name map: `(none)`")
    if local_renames_path is not None and local_renames_path.exists():
        lines.append(f"- local renames: `{local_renames_path}`")
    else:
        lines.append("- local renames: `(none)`")
    if missing:
        lines.append(f"- missing extracted functions: `{', '.join(missing)}`")
    lines.append("- direct callgraph: `callgraph.txt`")
    lines.append("")
    lines.append("## Files")
    lines.append("")
    for fn in extracted:
        mapped_name = display_name_by_canonical.get(fn.name, fn.name)
        addr = _normalize_address(fn.address or "") or "unknown"
        file_name = f"{fn.address.lower() if fn.address else f'line_{fn.start_line:05d}'}_{_safe_symbol_name(mapped_name)}.c"
        lines.append(f"- `{functions_dir / file_name}` ({addr})")
    lines.append("")
    lines.append("## Suggested workflow")
    lines.append("")
    lines.append("- Keep `functions/` as the immutable extraction baseline.")
    lines.append("- Use `work/` for variable renames and comments (safe to edit).")
    lines.append("- Start with `work/renaming_guide.md` for consistent first-pass renames.")
    lines.append("- Keep address labels and branch ids intact when annotating parity-sensitive logic.")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract decompiled C functions into one-file-per-function artifacts")
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_decompiled.c"),
        help="decompiled C source file",
    )
    parser.add_argument(
        "--functions-json",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_functions.json"),
        help="function call graph JSON from Ghidra export",
    )
    parser.add_argument(
        "--name-map",
        type=Path,
        default=Path("analysis/ghidra/maps/name_map.json"),
        help="optional name_map.json used for mapped names/signatures",
    )
    parser.add_argument(
        "--program",
        default="crimsonland.exe",
        help="program key used when filtering name_map entries",
    )
    parser.add_argument(
        "--local-renames",
        type=Path,
        help="optional JSON file for local variable renames (default: <output>/work/local_renames.json if present)",
    )
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        help="target function name or address (repeatable)",
    )
    parser.add_argument(
        "--call-depth",
        type=int,
        default=0,
        help="include direct/transitive callees up to this depth",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="output directory for extraction artifacts",
    )
    args = parser.parse_args()

    slices = build_function_slices(args.source)
    graph = load_call_graph(args.functions_json)
    name_map_by_address, name_map_address_by_name = load_name_map(args.name_map, program=str(args.program))
    local_renames, local_renames_path = load_local_renames(args.local_renames, output_dir=args.output)

    resolved_targets, resolved_by_request, unresolved_targets = resolve_targets(
        requested_targets=args.target,
        graph=graph,
        name_map_address_by_name=name_map_address_by_name,
    )
    wanted = expand_targets(resolved_targets, graph.by_name, args.call_depth)

    extracted: list[FunctionSlice] = []
    missing: list[str] = []
    for name in sorted(wanted):
        fn = slices.get(name)
        if fn is None:
            missing.append(name)
            continue
        extracted.append(fn)

    extracted.sort(key=_sort_key)
    write_extraction(
        source=args.source,
        out_dir=args.output,
        requested_targets=args.target,
        resolved_targets=resolved_targets,
        resolved_by_request=resolved_by_request,
        unresolved_targets=unresolved_targets,
        call_depth=int(args.call_depth),
        graph=graph,
        extracted=extracted,
        missing=missing,
        name_map_by_address=name_map_by_address,
        name_map_path=args.name_map,
        local_renames=local_renames,
        local_renames_path=local_renames_path,
    )

    print(f"wrote {len(extracted)} functions to {args.output}")
    if unresolved_targets:
        print(f"unresolved targets ({len(unresolved_targets)}): {', '.join(unresolved_targets)}")
    if missing:
        print(f"missing ({len(missing)}): {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
