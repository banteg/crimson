from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast


GHIDRA_HEADER_RE = re.compile(r"^/\*\s+(?P<name>[^\s]+)\s+@\s+(?P<addr>[0-9A-Fa-f]+)\s+\*/\s*$")
IDA_HEADER_RE = re.compile(r"^//\s+(?P<name>.+?)\s+@\s+0x(?P<addr>[0-9A-Fa-f]+)\s*$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

CALL_CONVS = {
    "__cdecl",
    "__stdcall",
    "__fastcall",
    "__thiscall",
    "__usercall",
    "__vectorcall",
}

UNAFF_RE = re.compile(r"\bunaff_[A-Za-z0-9]+\b")
CONCAT_RE = re.compile(r"\bCONCAT[0-9]+\b")
SUB_RE = re.compile(r"\bSUB[0-9]+\b")
IN_REG_RE = re.compile(r"\bin_[A-Z]+\b")
EXTRAOUT_RE = re.compile(r"\bextraout_[A-Z]+\b")


@dataclass(frozen=True)
class Prototype:
    return_type: str
    calling_convention: str | None
    name: str
    params: list[str]

    @property
    def has_varargs(self) -> bool:
        return any(param.strip() == "..." for param in self.params)

    def params_excluding_this(self) -> list[str]:
        if self.calling_convention != "__thiscall":
            return list(self.params)
        return list(self.params[1:]) if self.params else []


@dataclass
class FuncInfo:
    address: int
    header_name: str
    prototype_line: str | None
    proto: Prototype | None


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_name_map(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, list):
        if not all(isinstance(item, dict) for item in data):
            raise ValueError("unsupported name map format: expected list of objects")
        return cast(list[dict[str, Any]], data)
    if isinstance(data, dict):
        obj = cast(dict[str, Any], data)
        entries = obj.get("entries")
        if isinstance(entries, list):
            if not all(isinstance(item, dict) for item in entries):
                raise ValueError("unsupported name map format: entries must be objects")
            return cast(list[dict[str, Any]], entries)
        functions = obj.get("functions")
        if isinstance(functions, list):
            if not all(isinstance(item, dict) for item in functions):
                raise ValueError("unsupported name map format: functions must be objects")
            return cast(list[dict[str, Any]], functions)
    raise ValueError(f"unsupported name map format: {type(data)}")


def split_args(raw: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in raw:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def parse_prototype(line: str) -> Prototype | None:
    stripped = line.strip().rstrip()
    if not stripped.endswith(")"):
        return None
    if "(" not in stripped or ")" not in stripped:
        return None
    lpar = stripped.find("(")
    rpar = stripped.rfind(")")
    if rpar < lpar:
        return None

    prefix = stripped[:lpar].strip()
    params_raw = stripped[lpar + 1 : rpar].strip()

    tokens = prefix.split()
    if len(tokens) < 2:
        return None

    name = tokens[-1]
    if not IDENT_RE.match(name):
        return None
    before = tokens[:-1]

    calling_convention: str | None = None
    ret_tokens: list[str] = []
    for token in before:
        cc_found = None
        for cc in CALL_CONVS:
            if cc in token:
                cc_found = cc
                token = token.replace(cc, "")
                break
        if cc_found:
            calling_convention = cc_found
        token = token.strip()
        if token:
            ret_tokens.append(token)

    return_type = " ".join(ret_tokens).strip()
    if not return_type:
        return None

    if not params_raw or params_raw == "void":
        params: list[str] = []
    else:
        params = split_args(params_raw)

    return Prototype(
        return_type=return_type,
        calling_convention=calling_convention,
        name=name,
        params=params,
    )


def parse_ghidra_decompiled(path: Path) -> dict[int, FuncInfo]:
    functions: dict[int, FuncInfo] = {}
    current_addr: int | None = None
    current_name: str | None = None
    current_proto: str | None = None
    current_proto_obj: Prototype | None = None

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        header = GHIDRA_HEADER_RE.match(line)
        if header:
            if current_addr is not None and current_name is not None:
                functions[current_addr] = FuncInfo(
                    address=current_addr,
                    header_name=current_name,
                    prototype_line=current_proto,
                    proto=current_proto_obj,
                )
            current_addr = int(header.group("addr"), 16)
            current_name = header.group("name")
            current_proto = None
            current_proto_obj = None
            continue

        if current_addr is None:
            continue
        if current_proto_obj is not None:
            continue

        candidate = line.strip()
        if not candidate or candidate.startswith("/*"):
            continue
        proto = parse_prototype(candidate)
        if proto:
            current_proto = candidate
            current_proto_obj = proto

    if current_addr is not None and current_name is not None:
        functions[current_addr] = FuncInfo(
            address=current_addr,
            header_name=current_name,
            prototype_line=current_proto,
            proto=current_proto_obj,
        )
    return functions


def parse_ida_decompiled(path: Path) -> dict[int, FuncInfo]:
    functions: dict[int, FuncInfo] = {}
    current_addr: int | None = None
    current_name: str | None = None
    current_proto: str | None = None
    current_proto_obj: Prototype | None = None

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        header = IDA_HEADER_RE.match(line)
        if header:
            if current_addr is not None and current_name is not None:
                functions[current_addr] = FuncInfo(
                    address=current_addr,
                    header_name=current_name,
                    prototype_line=current_proto,
                    proto=current_proto_obj,
                )
            current_addr = int(header.group("addr"), 16)
            current_name = header.group("name")
            current_proto = None
            current_proto_obj = None
            continue

        if current_addr is None:
            continue
        if current_proto_obj is not None:
            continue

        candidate = line.strip()
        if not candidate or candidate.startswith("//"):
            continue
        proto = parse_prototype(candidate)
        if proto:
            current_proto = candidate
            current_proto_obj = proto

    if current_addr is not None and current_name is not None:
        functions[current_addr] = FuncInfo(
            address=current_addr,
            header_name=current_name,
            prototype_line=current_proto,
            proto=current_proto_obj,
        )
    return functions


def iter_simple_calls(text: str) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if not (ch.isalpha() or ch == "_"):
            i += 1
            continue

        start = i
        i += 1
        while i < n and (text[i].isalnum() or text[i] == "_"):
            i += 1
        name = text[start:i]

        j = i
        while j < n and text[j].isspace():
            j += 1
        if j >= n or text[j] != "(":
            continue

        depth = 1
        k = j + 1
        while k < n and depth:
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
            k += 1
        if depth:
            break
        close = k - 1

        m = close + 1
        while m < n and text[m].isspace():
            m += 1
        if m < n and text[m] == "{":
            i = m
            continue

        args = text[j + 1 : close]
        calls.append((name, args))
        i = close + 1
    return calls


def score_args(args: str) -> dict[str, int]:
    return {
        "unaff": len(UNAFF_RE.findall(args)),
        "concat": len(CONCAT_RE.findall(args)),
        "sub": len(SUB_RE.findall(args)),
        "in_reg": len(IN_REG_RE.findall(args)),
        "extraout": len(EXTRAOUT_RE.findall(args)),
    }


def sum_score(counts: dict[str, int]) -> int:
    return (
        counts.get("unaff", 0) * 5
        + counts.get("concat", 0) * 3
        + counts.get("sub", 0) * 1
        + counts.get("in_reg", 0) * 2
        + counts.get("extraout", 0) * 2
    )


def normalize_addr(text: str) -> int:
    value = text.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return int(value, 16)


def build_call_index(ghidra_decompiled_path: Path) -> dict[str, dict[str, int]]:
    text = ghidra_decompiled_path.read_text(encoding="utf-8", errors="ignore")
    totals: dict[str, dict[str, int]] = {}
    for name, args in iter_simple_calls(text):
        if name.startswith("CONCAT") or name.startswith("SUB"):
            continue
        per = totals.setdefault(
            name,
            {
                "calls": 0,
                "calls_with_unaff": 0,
                "calls_with_concat": 0,
                "calls_with_sub": 0,
                "args_unaff": 0,
                "args_concat": 0,
                "args_sub": 0,
                "args_in_reg": 0,
                "args_extraout": 0,
                "score": 0,
            },
        )
        per["calls"] += 1
        counts = score_args(args)
        if counts["unaff"]:
            per["calls_with_unaff"] += 1
        if counts["concat"]:
            per["calls_with_concat"] += 1
        if counts["sub"]:
            per["calls_with_sub"] += 1
        per["args_unaff"] += counts["unaff"]
        per["args_concat"] += counts["concat"]
        per["args_sub"] += counts["sub"]
        per["args_in_reg"] += counts["in_reg"]
        per["args_extraout"] += counts["extraout"]
        per["score"] += sum_score(counts)
    return totals


def load_ghidra_functions(path: Path) -> dict[int, dict]:
    data = load_json(path)
    if not isinstance(data, list):
        raise ValueError("expected Ghidra functions export to be a list")
    by_addr: dict[int, dict[str, Any]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        obj = cast(dict[str, Any], item)
        addr_raw = str(obj.get("address", "")).strip()
        if not addr_raw:
            continue
        try:
            addr = normalize_addr(addr_raw)
        except ValueError:
            continue
        by_addr[addr] = obj
    return by_addr


def compute_in_calls(functions: dict[int, dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in functions.values():
        raw_calls = item.get("calls", [])
        calls = raw_calls if isinstance(raw_calls, list) else []
        for callee in calls:
            if isinstance(callee, str) and callee:
                counts[callee] += 1
    return dict(counts)


def format_addr(addr: int) -> str:
    return f"0x{addr:08x}"


def format_signature_from_ida(
    header_name: str,
    ida: Prototype,
    current_map_sig: str | None,
) -> str | None:
    if ida.calling_convention in {"__usercall"}:
        return None

    ida_params = ida.params_excluding_this()

    if current_map_sig:
        map_proto = parse_prototype(current_map_sig)
    else:
        map_proto = None

    if map_proto:
        map_params = map_proto.params_excluding_this()
        if len(map_params) == len(ida_params) and map_proto.has_varargs == ida.has_varargs:
            if map_proto.return_type != ida.return_type:
                return f"{ida.return_type} {header_name}({', '.join(map_params) if map_params else 'void'})"
            return None

    param_text = ", ".join(ida_params) if ida_params else "void"
    return f"{ida.return_type} {header_name}({param_text})"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare IDA/Ghidra decompile signatures and rank Ghidra callsites by decompiler artifacts."
    )
    parser.add_argument(
        "--ghidra-decompiled",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_decompiled.c"),
        help="path to Ghidra decompiled C",
    )
    parser.add_argument(
        "--ida-decompiled",
        type=Path,
        default=Path("analysis/ida/raw/crimsonland.exe/crimsonland.exe_decompiled.c"),
        help="path to IDA decompiled C",
    )
    parser.add_argument(
        "--ghidra-functions",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_functions.json"),
        help="path to Ghidra functions.json (calls list)",
    )
    parser.add_argument(
        "--name-map",
        type=Path,
        default=Path("analysis/ghidra/maps/name_map.json"),
        help="path to analysis/ghidra/maps/name_map.json",
    )
    parser.add_argument("--top", type=int, default=25, help="number of rows to show")
    parser.add_argument(
        "--prefix",
        type=str,
        default="",
        help="only include functions with this name prefix",
    )
    args = parser.parse_args()

    ghidra_funcs = parse_ghidra_decompiled(args.ghidra_decompiled)
    ida_funcs = parse_ida_decompiled(args.ida_decompiled)

    ghidra_fn_meta = load_ghidra_functions(args.ghidra_functions)
    in_calls = compute_in_calls(ghidra_fn_meta)

    name_entries = load_name_map(args.name_map)
    map_by_addr: dict[int, dict] = {}
    for entry in name_entries:
        if entry.get("program", "").lower() != "crimsonland.exe":
            continue
        address = entry.get("address", "")
        if not address:
            continue
        try:
            addr_int = normalize_addr(str(address))
        except ValueError:
            continue
        map_by_addr[addr_int] = entry

    call_index = build_call_index(args.ghidra_decompiled)

    @dataclass(frozen=True)
    class ReportRow:
        score: int
        in_calls: int
        callsites: int
        unaff_callsites: int
        concat_callsites: int
        addr: int
        name: str

    rows: list[ReportRow] = []
    for addr, meta in ghidra_fn_meta.items():
        name = str(meta.get("name", ""))
        if args.prefix and not name.startswith(args.prefix):
            continue
        calls = call_index.get(name)
        if not calls:
            continue
        score = int(calls.get("score", 0))
        if score <= 0:
            continue
        rows.append(
            ReportRow(
                score=score,
                in_calls=int(in_calls.get(name, 0)),
                callsites=int(calls.get("calls", 0)),
                unaff_callsites=int(calls.get("calls_with_unaff", 0)),
                concat_callsites=int(calls.get("calls_with_concat", 0)),
                addr=addr,
                name=name,
            )
        )

    rows.sort(key=lambda row: (row.score, row.in_calls, row.callsites), reverse=True)
    rows = rows[: args.top]

    for row in rows:
        addr = row.addr
        name = row.name
        print(
            "{score:>5} in={in_calls:<3} callsites={calls:<4} unaff_calls={calls_with_unaff:<4} concat_calls={calls_with_concat:<4} {addr} {name}".format(
                score=row.score,
                in_calls=row.in_calls,
                calls=row.callsites,
                calls_with_unaff=row.unaff_callsites,
                calls_with_concat=row.concat_callsites,
                addr=format_addr(addr),
                name=name,
            )
        )

        map_sig = map_by_addr.get(addr, {}).get("signature")
        if map_sig:
            print(f"  map:   {map_sig}")

        gh = ghidra_funcs.get(addr)
        if gh and gh.prototype_line:
            print(f"  ghidra:{gh.prototype_line}")

        ida = ida_funcs.get(addr)
        if ida and ida.prototype_line:
            print(f"  ida:   {ida.prototype_line}")

        if ida and ida.proto:
            suggestion = format_signature_from_ida(
                header_name=name,
                ida=ida.proto,
                current_map_sig=map_sig,
            )
            if suggestion:
                print(f"  suggest: {suggestion}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
