"""Trace the commutative operand sort of the VC6 C2 expression pass (diagnostic only; no match credit).

`compute_tree_cost_and_sort` 0x1070d90c sorts the flattened operand list (node+0x18) of every commutative
node (add, mul, and, or, xor, ...) by calling `merge_sort_operand_list` 0x1070f584 with
`compare_operand_cost_desc` 0x1070f6ae at 0x1070da8d: stable, unsigned descending on the packed key
`need<<24 | size<<16 | hash16` kept at operand+0x0c. This tool hooks that call (entry and return) through
Crimson's preserving observer (`crimson match c2-trace`) and prints, for each sorted node, its opcode, C2 line
label and the operand list with keys before (PRE) and after (POST) the sort. The expression pass runs before
and after globopt; the last event for a line is the final order. See tools/match/c2/compiler/pu-factor-order.md.

    uv run python scripts/c2/sort_trace.py <crimson-scratch> --out <new-dir> [--lines A-B]
    uv run python scripts/c2/sort_trace.py --reuse <trace-dir> [--lines A-B]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import il_stage_trace as stage

SITE = 0x1070DA8D  # call merge_sort_operand_list in compute_tree_cost_and_sort
TARGET = 0x1070F584
MODE = 5
# ebx = the commutative node, ecx = operand list at entry, eax = sorted list at return.
BODY = r"""
    if (modes[index] == 5) {
        unsigned long p, k = 0, node = r[4];
        p = phase < 100 ? r[6] : r[7];
        s(phase < 100 ? "PRE" : "POST"); s(" op="); hx(W(node, 4) & 0xffff);
        s(" ln="); dec(*(unsigned short *)(node + 0x10)); s("\n");
        while (p && k < 24) { s("  key="); hx(W(p, 0xc)); s(" "); operand(p, 0); s("\n"); p = W(p, 0); ++k; }
    }
"""
ANCHOR = "    if (modes[index] == 2 && phase >= 100 && r[7])"
HEAD = re.compile(r"(PRE|POST) op=(\w+) ln=(\d+)")
KEY = re.compile(r"^\s+key=([0-9a-f]+) (.*)$")


def install() -> None:
    stage.PRESETS["sort"] = ((SITE, TARGET, "sort", True, MODE),)
    stock = stage.observer_source

    def patched(iv):
        if ANCHOR not in iv.OBSERVER:
            raise RuntimeError("observer anchor not found; iv_trace.OBSERVER changed")
        if BODY not in iv.OBSERVER:
            iv.OBSERVER = iv.OBSERVER.replace(ANCHOR, BODY + ANCHOR)
        return stock(iv)

    stage.observer_source = patched


def split_key(key: int) -> str:
    return f"need={key >> 24} size={(key >> 16) & 0xFF} hash={key & 0xFFFF:#06x}"


def report(events, lines: tuple[int, int] | None) -> None:
    for event in events:
        if event["name"] != "sort":
            continue
        body = event["body"]
        head = HEAD.search(body)
        if not head or (lines and not lines[0] <= int(head.group(3)) <= lines[1]):
            continue
        op = stage.OPNAMES.get(head.group(2), head.group(2))
        print(f"{head.group(1)} {op} ln{head.group(3)}")
        for line in body[head.end() :].splitlines():
            m = KEY.match(line)
            if m:
                key = int(m.group(1), 16)
                print(f"  {key:#010x} [{split_key(key)}] {m.group(2)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reuse", type=Path, help="Re-render an existing trace directory")
    parser.add_argument("--lines", help="only nodes whose C2 line label is in A-B")
    args = parser.parse_args()
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    install()
    if args.reuse:
        out = args.reuse
    else:
        if args.scratch is None or args.out is None:
            parser.error("scratch and --out are required")
        c2, iv = stage.load_modules(False, None)
        result = stage.trace(c2, iv, args.scratch, args.out, "sort")
        print("metrics:", result["metrics"])
        out = args.out
    events = stage.decode((out / "observed/phases.bin").read_bytes(), stage.result_profile(out))
    report(events, lines)


if __name__ == "__main__":
    main()
