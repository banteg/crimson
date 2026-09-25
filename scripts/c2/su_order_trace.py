"""Trace VC6 C2 Sethi-Ullman evaluation-order decisions (diagnostic only; no match credit).

`emit_tree_as_tuples` (C2 0x1070e114) re-linearizes each simplified expression tree. For a reorderable
binary node (compare, sub, shift, ...; `is_reorderable_binary_opcode` 0x1070e560) with a non-float type it
calls `compare_operand_cost_desc` 0x1070f6ae(A, B) on the two operands' packed cost keys
(`need<<24 | size<<16 | hash16`) and emits B's subtree first when key(B) > key(A). This tool hooks both call
sites (0x1070e320 for substitutable nodes, 0x10792d4a for materialized roots) and prints every decision with
the decoded keys and each operand's defining tuple, so two calls compared with `==` show which call is
emitted first and why. The simplifier runs twice (before and after globopt); the second decision is final.

Runs through Crimson's preserving observer (`crimson match c2-trace`: whole-COFF, replay and missing-stream
controls unchanged).

    uv run python scripts/c2/su_order_trace.py <crimson-scratch> --out <new-dir> [--lines A-B]
    # a snail-mail scratch, run from the snail-mail checkout (it provides the `snail` package):
    uv run python ../crimson/scripts/c2/su_order_trace.py --snail <scratch> --out <new-dir> [--calls]
    uv run python scripts/c2/su_order_trace.py --reuse <trace-dir> [--lines A-B] [--calls]

See tools/match/c2/compiler/call-operand-order.md.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import il_stage_trace as stage

HOOKS = (
    (0x1070E320, 0x1070F6AE, "su_node"),
    (0x10792D4A, 0x1070F6AE, "su_root"),
)
MODE = 4
# Mode 4 prints, at entry of compare_operand_cost_desc(ecx=A, edx=B), each operand's packed key, the
# operand itself and, for a temp or symbol with a defining tuple, that tuple's opcode, line and sources.
DECISION = r"""
    if (modes[index] == 4 && phase < 100) {
        unsigned long k, p, d;
        for (k = 0; k < 2; ++k) {
            p = k ? r[5] : r[6];
            s(k ? "B key=" : "A key="); hx(W(p, 0xc)); s(" "); operand(p, 0);
            if (*(unsigned char *)(p + 8) >= 1 && *(unsigned char *)(p + 8) <= 2 && W(p, 0x14)
                && (d = W(W(p, 0x14), 0x14))) {
                s(" def op="); hx(W(d, 4) & 0xffff); s(" ln="); dec(*(unsigned short *)(d + 0x10));
                s(" src: "); chain(W(d, 0x18));
            }
            s("\n");
        }
    }
"""
ANCHOR = "    if (modes[index] == 2 && phase >= 100 && r[7])"
OPERAND_LINE = re.compile(r"^([AB]) key=([0-9a-f]+) (.*?)(?: def op=(\w+) ln=(\d+) src: (.*))?$")


def install(preset: str = "su") -> None:
    stage.PRESETS[preset] = tuple((site, target, name, False, MODE) for site, target, name in HOOKS)
    stock = stage.observer_source

    def patched(iv):
        if ANCHOR not in iv.OBSERVER:
            raise RuntimeError("observer anchor not found; iv_trace.OBSERVER changed")
        if DECISION not in iv.OBSERVER:
            iv.OBSERVER = iv.OBSERVER.replace(ANCHOR, DECISION + ANCHOR)
        return stock(iv)

    stage.observer_source = patched


def split_key(key: int) -> str:
    return f"need={key >> 24} size={(key >> 16) & 0xFF} hash={key & 0xFFFF:#06x}"


def decisions(events):
    """Yield (ordinal, hook name, [(side, key, operand, def op, def line, def sources)])."""
    ordinal = 0
    for event in events:
        if not event["name"].startswith("su_"):
            continue
        sides = []
        for line in event["body"].strip().splitlines():
            m = OPERAND_LINE.match(line.strip())
            if m:
                side, key, operand, op, ln, src = m.groups()
                sides.append((side, int(key, 16), operand, op, int(ln) if ln else None, src or ""))
        if len(sides) == 2:
            yield ordinal, event["name"], sides
            ordinal += 1


def report(events, lines: tuple[int, int] | None, calls_only: bool) -> None:
    for ordinal, name, sides in decisions(events):
        def_lines = [ln for *_, ln, _ in sides if ln is not None]
        if lines and not any(lines[0] <= ln <= lines[1] for ln in def_lines):
            continue
        if calls_only and not all(op == "184" for _, _, _, op, _, _ in sides):
            continue
        (_, key_a, *_), (_, key_b, *_) = sides
        first = "B" if key_b > key_a else "A"
        print(f"#{ordinal} {name}: emits {first} first (B first iff key(B) > key(A), unsigned)")
        for side, key, operand, op, ln, src in sides:
            where = f" def op={op} ln={ln} src: {src}" if op else ""
            print(f"  {side} {key:#010x} [{split_key(key)}] {operand}{where}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reuse", type=Path, help="Re-render an existing trace directory")
    parser.add_argument("--snail", action="store_true", help="Trace a snail-mail scratch through its adapter")
    parser.add_argument("--match-root", type=Path, help="snail-mail: compile against another tools/match root")
    parser.add_argument("--lines", help="only decisions whose operand defs carry a C2 line label in A-B")
    parser.add_argument("--calls", action="store_true", help="only decisions between two call subtrees")
    args = parser.parse_args()
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    install()
    if args.reuse:
        out = args.reuse
    else:
        if args.scratch is None or args.out is None:
            parser.error("scratch and --out are required")
        c2, iv = stage.load_modules(args.snail, args.match_root)
        result = stage.trace(c2, iv, args.scratch, args.out, "su")
        print("metrics:", result["metrics"])
        out = args.out
    events = stage.decode((out / "observed/phases.bin").read_bytes(), stage.result_profile(out))
    report(events, lines, args.calls)


if __name__ == "__main__":
    main()
