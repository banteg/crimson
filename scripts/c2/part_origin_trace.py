"""Show when each float operand's symbol record was created, and so how it sorts (diagnostic only; no match credit).

VC6 C2 orders the two operands of a commutative float add/mul by their packed cost; for two register-candidate
symbols that is the slot id (`id << 5` for locals, parameters, inline copies and aggregate parts below 0x800;
`id << 6` mod 0x10000 for class-3 temporaries), and the higher id is loaded first (x87-scheduling.md section 5).
A slot id is handed out when the record is created, so the order of two operands is the order in which their
records were created. Records come from three places, and this tool tells them apart:

    reader     the IL reader, at the first IL reference in source order (named locals, and the parts of a
               scalarized aggregate named explicitly, e.g. `m.basis_right.y` makes the part `^m+4 z60`, then
               the field `^m+4 z4`);
    inline #k  expansion k of the inliner (inline_expand_calls 0x107181a8): formal copies (from the pool-B
               LIFO free list, so usually a recycled low id) and offset-0 members of `this`, which
               symbol_get_part 0x10703ba0 finds or creates;
    <stage>    a globopt stage: canonicalization creates the `^m+off` part of a folded `this + off` address,
               value numbering / CSE (cse1) create the field record `^m+off z4` it dereferences.

The scratch runs through Crimson's preserving observer (`crimson match c2-trace`: whole COFF, replay and
missing-stream checks unchanged) with IL dumps at the reader (function_prepare_temps 0x107180fd), at every
inliner recursion and formal substitution, and at the globopt stages of `il_stage_trace.py --preset globopt`.
For every float add/sub/mul/div tuple on the chosen C2 lines at lowering entry it prints each symbol operand
with its class, parent+offset, name, sort key and origin.

    uv run python scripts/c2/part_origin_trace.py <crimson-scratch> --out <new-dir> --lines 160-170
    # a snail-mail scratch, run from the snail-mail checkout:
    uv run python ../crimson/scripts/c2/part_origin_trace.py --snail <scratch> --out <new-dir> --lines 160-170
    uv run python scripts/c2/part_origin_trace.py --reuse <trace-dir> --lines 160-170

See tools/match/c2/compiler/scale-operand-rank.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import il_stage_trace as ist

BASE = 0x10700000
PREPARE = (0x107580FA, 0x107180FD, "reader", False, 3)
INLINE = (
    (0x1071888B, 0x107181A8, "inline", False, 3),
    (0x10718940, 0x1075C9B0, "formals", False, 3),
)
FLOAT_OPS = {"16d": "fadd", "16e": "fsub", "16f": "fmul", "175": "fdiv"}
SYMBOL = re.compile(r"#(\d+)c(\d+)(\^(\d+)\+(\d+))?z(\d+)[^\]' ]*('_?(\w+))?")


def profile(c2):
    stock = c2.load_profile()
    first = {"site": PREPARE[0] - BASE, "target": PREPARE[1] - BASE, "return": False, "mode": 3, "name": "reader"}
    hooks = [first] + [
        dict(h, mode=3 if i in ist.STOCK_NAMES else 0, name=ist.STOCK_NAMES.get(i, f"pass@{h['target'] + BASE:#x}"))
        for i, h in enumerate(stock["hooks"][:12])
    ]
    hooks += [
        {"site": site - BASE, "target": target - BASE, "return": ret, "mode": mode, "name": name}
        for site, target, name, ret, mode in (*INLINE, *ist.PRESETS["globopt"])
    ]
    return {**stock, "name": stock["name"] + "-part-origin", "hooks": hooks}


def trace(c2, iv, scratch: Path, out: Path):
    prof = profile(c2)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: prof
    c2.observer_source = ist.observer_source(iv)
    c2.decode_trace = iv.decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


def first_function(events):
    """Events of the first compiled function: from its reader dump up to (not including) the next one."""
    selected = []
    for event in events:
        if event["name"] == "reader" and selected:
            break
        if event["name"] == "reader" or selected:
            selected.append(event)
    return selected


def origins(events) -> dict[int, str]:
    """Symbol id -> the first dump it appears in (reader, inline #k (call line), or a globopt stage)."""
    seen: dict[int, str] = {}
    expansion = 0
    for event in events:
        tuples = [line for line in event["body"].splitlines() if line.startswith("T ")]
        if event["name"] == "inline":
            expansion += 1
        if not tuples:
            continue
        if event["name"] in ("inline", "formals"):
            label = f"inline #{expansion}"
        else:
            label = ist.stage_name(event)
        for line in tuples:
            for match in SYMBOL.finditer(line):
                seen.setdefault(int(match.group(1)), label)
    return seen


def sort_key(sid: int, cls: int) -> str:
    """Packed cost of a symbol leaf (x87-scheduling.md section 5): locals id<<5, temporaries id<<6."""
    if cls == 3:
        return f"{0x10000 | (sid << 6) & 0xFFFF:#x}"
    value = (sid >> 16) ^ (sid & 0xFFFF)
    return f"{0x10000 | (((value & 0x7FF) << 5) ^ ((value << 5) >> 16)):#x}"


def describe(match, seen, leaf: bool) -> str:
    sid, cls = int(match.group(1)), int(match.group(2))
    part = f" ^{int(match.group(4)):#x}+{match.group(5)} z{match.group(6)}" if match.group(3) else ""
    name = f" '{match.group(8)}'" if match.group(8) else ""
    key = f" key {sort_key(sid, cls)}" if leaf else ""
    return f"{sid:#x} c{cls}{part}{name}{key} from {seen.get(sid, '?')}"


def report(events, lines: tuple[int, int]):
    events = first_function(events)
    seen = origins(events)
    lower = next(event for event in events if event["name"] == "lower")
    for line in lower["body"].splitlines():
        m = ist.TUPLE.match(line)
        if not m or m.group(2) not in FLOAT_OPS or not lines[0] <= int(m.group(5)) <= lines[1]:
            continue
        operands = ist.OPERAND.findall(m.group(7))
        print(f"L{m.group(5)} {FLOAT_OPS[m.group(2)]}")
        for operand in operands[1:]:
            # Kind 2 is a symbol leaf keyed by its id; kind 1 is a computed value, costed as its expression.
            symbols = [s for s in SYMBOL.finditer(operand[5]) if int(s.group(1))]
            kind = {"1": "value", "2": "symbol", "3": "address", "6": "memory", "7": "constant"}.get(operand[1])
            text = "; ".join(describe(s, seen, operand[1] == "2") for s in symbols) or operand[5][:60]
            print(f"    {kind or 'kind' + operand[1]:8} {text}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reuse", type=Path, help="Re-render an existing trace directory")
    parser.add_argument("--snail", action="store_true", help="Trace a snail-mail scratch through its adapter")
    parser.add_argument("--match-root", type=Path, help="snail-mail: compile against another tools/match root")
    parser.add_argument("--lines", required=True, help="C2 line-label range A-B (as printed by sched_trace.py)")
    args = parser.parse_args()
    lines = tuple(int(x) for x in args.lines.split("-"))
    if args.reuse:
        out = args.reuse
    else:
        if args.scratch is None or args.out is None:
            parser.error("scratch and --out are required")
        c2, iv = ist.load_modules(args.snail, args.match_root)
        result = trace(c2, iv, args.scratch, args.out)
        print(json.dumps({k: result[k] for k in ("function", "metrics", "events")}))
        out = args.out
    events = ist.decode((out / "observed/phases.bin").read_bytes(), ist.result_profile(out))
    report(events, lines)


if __name__ == "__main__":
    main()
