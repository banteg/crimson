"""Show why VC6 C2 forward propagation keeps or moves each single-use definition, without changing output.

`forward_propagate_definitions` (C2 0x10711afa) moves the expression tree of a single-use variable
definition to its use. Before moving, it runs `range_free_of_conflicts` (0x10742ad4) on the use's
own expression (call site 0x10712713) and, unless the definition is the tuple right before the use,
on every tuple between the two (call site 0x107125d8). A range fails when `operands_may_alias` (0x10702771) says a tuple in it writes an
operand that the definition's tree reads (or reads what the definition writes). A failed range leaves
the definition where C1 put it; for float values that is what keeps a lane on the x87 stack.

The scratch runs through `crimson match c2-trace`'s preserving harness (whole-COFF, replay and
missing-stream checks unchanged). The report lists every range check with the definition, the use,
the verdict and the operand pairs that aliased. `ln` is C1's line record for the definition (inlined
code carries a line near the call site); `--lines` filters on it.

    uv run python scripts/c2/fwdprop_trace.py <scratch-dir> --out <new-dir> [--lines A-B]
    uv run python scripts/c2/fwdprop_trace.py --report-only <trace-dir> [--lines A-B]

Only the pinned msvc6.5 C2 is supported (the profile hash is checked by crimson).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import iv_trace

from crimson import match_c2 as c2

# (call site VA, callee VA, name, return hook, mode)
HOOKS = (
    (0x10712713, 0x10742AD4, "range_use", True, 4),
    (0x107125D8, 0x10742AD4, "range_between", True, 4),
    (0x10742B0A, 0x10702771, "may_alias@src_vs_dst", True, 5),
    (0x10742B47, 0x10702771, "may_alias@dst_vs_src", True, 5),
    (0x10742B65, 0x10702771, "may_alias@dst_vs_dst", True, 5),
)

# Replaces iv_trace's observe(): modes 4 and 5 print one compact record, other hooks keep the stock
# behaviour (function tracking only, no IL dumps).
OBSERVE = r"""
static unsigned long alias_a, alias_b;

static void tup(unsigned long node)
{
    if (!node) { s("nil\n"); return; }
    s("T "); hx(node); s(" op="); hx(W(node, 4) & 0xffff); s(" k="); hx(*(unsigned char *)(node + 8));
    s(" ty="); hx(*(unsigned short *)(node + 10)); s(" ln="); dec(*(unsigned short *)(node + 0x10));
    if (*(unsigned char *)(node + 9) & 1) { s(" | "); chain(W(node, 0x1c)); s("<= "); chain(W(node, 0x18)); }
    s("\n");
}

static void __cdecl observe(unsigned long phase, unsigned long *r)
{
    unsigned long index = phase >= 100 ? phase - 100 : phase;
    if (phase < 12) { saved_function = r[6]; return; }
    if (modes[index] == 5) {
        if (phase < 100) { alias_a = r[6]; alias_b = r[5]; return; }
        if (!r[7]) return;
        s("EVENT "); dec(phase); s(" fn="); hx(saved_function); s("\nA "); operand(alias_a, 0);
        s("\nB "); operand(alias_b, 0); s("\nEND\n"); flush();
        return;
    }
    if (modes[index] == 4) {
        s("EVENT "); dec(phase); s(" fn="); hx(saved_function);
        if (phase < 100) {
            s("\nDEF "); tup(r[10]);
            s("START "); tup(r[6]);
            s("USE "); tup(r[5] ? W(r[5], 0) : 0);
        } else {
            s(" ok="); hx(r[7]); s("\n");
        }
        s("END\n"); flush();
    }
}
"""


def observer_source(profile):
    source = iv_trace.observer_source(profile)
    start = source.index("static void __cdecl observe")
    end = source.index("__declspec(naked)", start)
    return source[:start] + OBSERVE + source[end:]


def trace(scratch: Path, out: Path):
    profile = iv_trace.profile_with_hooks(HOOKS)
    profile["hooks"] = [dict(h, mode=0) if i < 12 else h for i, h in enumerate(profile["hooks"])]
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: profile
    c2.observer_source = observer_source
    c2.decode_trace = iv_trace.decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


LINE = re.compile(r" ln=(\d+)")


def report(events, lines=None):
    """One block per range check: definition, use, verdict and the aliasing operand pairs."""
    out, current = [], None
    for e in events:
        body = e["body"]
        if e["name"].startswith("range_"):
            if e["boundary"] == "entry":
                rows = dict(line.split(" ", 1) for line in body.splitlines() if line)
                ln = int(LINE.search(rows.get("DEF", " ln=0")).group(1))
                current = {"check": e["name"], "rows": rows, "ln": ln, "alias": []}
            else:
                ok = e["head"].split("ok=")[1].split()[0] != "0"
                if current and (lines is None or lines[0] <= current["ln"] <= lines[1]):
                    out.append(f"ln {current['ln']} {current['check']}: {'free' if ok else 'CONFLICT'}")
                    for key in ("DEF", "USE"):
                        out.append(f"    {key.lower()}: {iv_trace.pretty_tuple(current['rows'][key])}")
                    for a, b in current["alias"]:
                        out.append(f"    alias: {iv_trace.pretty_operand(a)}  ~  {iv_trace.pretty_operand(b)}")
                current = None
        elif current is not None:
            rows = dict(line.split(" ", 1) for line in body.splitlines() if line)
            current["alias"].append((rows.get("A", ""), rows.get("B", "")))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path, nargs="?")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--lines", help="only definitions on source lines A-B")
    parser.add_argument("--report-only", type=Path)
    args = parser.parse_args()
    if args.report_only:
        out = args.report_only
    else:
        if not args.scratch or not args.out:
            parser.error("scratch and --out are required")
        result = trace(args.scratch, args.out)
        print(json.dumps({"out": str(args.out), "events": result["events"], "metrics": result["metrics"]}))
        out = args.out
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    events = json.loads((out / "snapshots.json").read_text())
    text = "\n".join(report(events, lines)) + "\n"
    (out / "fwdprop-report.txt").write_text(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
