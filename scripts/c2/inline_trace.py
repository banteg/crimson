"""Observe VC6 C2 call-site inlining (P2/inline.c) on a scratch, without changing its output.

Runs the scratch through `crimson match c2-trace`'s preserving harness (whole-COFF, replay and
missing-stream controls unchanged) with the readable IL observer from `iv_trace.py`. Hooks:

- `function_prepare_temps` (0x107180fd, called per function from 0x107580fa): IL before inlining;
- the first pass boundary (0x107130cb): IL after inlining;
- the inliner's top-level and recursive calls to `inline_expand_calls` (0x107181a8), and its call to
  `inline_substitute_formals` (0x1075c9b0). `inline_expand_calls` takes the function in ecx, the
  depth in edx and the size budget as its first stack argument, so every expansion's depth is visible.

`--report` prints, per compiled function, the call tuples before inlining, the number of
expansions at each depth, and whether calls survive into the first pass.

    uv run python scripts/c2/inline_trace.py <scratch-dir> --out <new-dir> [--report]
    uv run python scripts/c2/inline_trace.py --report-only <trace-dir>

Diagnostic only; see tools/match/c2/compiler/array-constructors.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import iv_trace

from crimson import match_c2 as c2

BASE = 0x10700000
PREPARE = (0x107580FA, 0x107180FD, "function_prepare_temps")
HOOKS = (
    (0x10718134, 0x107181A8, "inline_expand_calls@top", False, 0),
    (0x1071888B, 0x107181A8, "inline_expand_calls@recurse", False, 0),
    (0x10718940, 0x1075C9B0, "inline_substitute_formals", False, 0),
)
# The IV observer treats hook 12 as a loop entry; inlining has no loop argument.
OBSERVER = iv_trace.OBSERVER.replace("    if (phase == 12) saved_loop = r[6];\n", "")
CALL_OPS = {"184", "187"}


def profile():
    stock = c2.load_profile()
    first = {"site": PREPARE[0] - BASE, "target": PREPARE[1] - BASE, "return": False, "mode": 3, "name": PREPARE[2]}
    passes = [
        dict(h, mode=3 if i == 0 else 0, name=f"pass@{h['target'] + BASE:#x}")
        for i, h in enumerate(stock["hooks"][:11])
    ]
    extra = [
        {"site": site - BASE, "target": target - BASE, "return": ret, "mode": mode, "name": name}
        for site, target, name, ret, mode in HOOKS
    ]
    return {**stock, "name": stock["name"] + "-inline-trace", "hooks": [first, *passes, *extra]}


def observer_source(prof):
    stock = iv_trace.STOCK_OBSERVER_SOURCE(prof)
    wrappers = stock[stock.index("__declspec(naked)") : stock.index("void __stdcall start")]
    header = stock[: stock.index("#include")]
    modes = "static unsigned long modes[] = {" + ",".join(str(h["mode"]) for h in prof["hooks"]) + "};\n"
    body = OBSERVER.replace("/* GENERATED_HOOKS */", wrappers)
    return header + body.replace("static char buf[65536];", modes + "static char buf[65536];")


def trace(scratch: Path, out: Path):
    prof = profile()
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: prof
    c2.observer_source = observer_source
    c2.decode_trace = iv_trace.decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


def calls(body):
    return [line for line in body.splitlines() if line.startswith("T ") and line.split()[2][3:] in CALL_OPS]


def report(events):
    functions = []
    for event in events:
        if event["name"] == PREPARE[2]:
            functions.append({"before": event, "expansions": [], "after": None})
        elif not functions:
            continue
        elif event["name"].startswith("inline_expand_calls"):
            depth = int(event["head"].split(" edx=")[1].split()[0], 16)
            functions[-1]["expansions"].append((event["name"].split("@")[1], depth))
        elif event["name"] == "pass@0x107130cb" and functions[-1]["after"] is None:
            functions[-1]["after"] = event
    for number, fn in enumerate(functions):
        head = fn["before"]["head"]
        print(f"function {number} fn={head.split('fn=')[1].split()[0]}")
        for line in calls(fn["before"]["body"]):
            print("  call before inlining:", line[:160])
        recursive = [depth for kind, depth in fn["expansions"] if kind == "recurse"]
        print(f"  inline_expand_calls: {len(fn['expansions'])} events, recursive depths {recursive}")
        if fn["after"] is not None:
            remaining = calls(fn["after"]["body"])
            print(f"  calls at first pass: {len(remaining)}")
            for line in remaining:
                print("   ", line[:160])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--report-only", type=Path)
    args = parser.parse_args()
    if args.report_only:
        prof = json.loads((args.report_only / "profile.json").read_text())
        report(iv_trace.decode((args.report_only / "observed/phases.bin").read_bytes(), prof))
        return
    if args.scratch is None or args.out is None:
        parser.error("scratch and --out are required")
    result = trace(args.scratch, args.out)
    print(json.dumps({k: result[k] for k in ("function", "metrics", "events")}))
    if args.report:
        prof = json.loads((args.out / "profile.json").read_text())
        report(iv_trace.decode((args.out / "observed/phases.bin").read_bytes(), prof))


if __name__ == "__main__":
    main()
