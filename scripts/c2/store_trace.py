"""Follow every store to one stack symbol through the pinned VC6 C2 back end, without changing its output.

The scratch runs through `crimson match c2-trace`'s preserving harness (whole-COFF, replay and
missing-stream checks unchanged) with the readable-IL observer of `iv_trace.py`. The IL is dumped at
entry and return of `pass_mark_register_candidates` 0x107284d8 (register promotion), at the stock pass
boundaries, and at entry to every post-allocation pass (`--detail` adds the steps inside
`build_live_ranges` and global colouring, including every store-back and demotion call).

The report prints one line per dump with the selected symbols' reference counts: memory stores
(kind-2 destinations), register definitions (kind-1), memory reads, register reads and address
operands. The tuples are printed whenever the counts change, so the pass that creates, promotes,
demotes or forwards a reference is the one between the two dumps. A line is flagged when there are
more memory stores than right after promotion.

    uv run python scripts/c2/store_trace.py <scratch-dir> --out <new-dir> --symbol NAME [--symbol NAME ...]
    uv run python scripts/c2/store_trace.py <scratch-dir> --out <new-dir> --detail --symbol NAME
    uv run python scripts/c2/store_trace.py --report-only <trace-dir> --symbol NAME [--verbose]

`NAME` is a front-end symbol name with its leading underscore (`_spread`) or `#id` for unnamed
symbols such as inlined parameters (find the id in `snapshots.json`). Parts of a symbol (field or
typed views, `#id^parent+offset`) are included. Only the pinned msvc6.5 C2 is supported (the profile
hash is checked by crimson).
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

# Driver call sites not already in the stock profile. The stock boundaries (narrow byte lanes,
# address modes, lowering, parameter homes, live ranges, local colouring, ...) are dumped at entry.
PROMOTION_HOOKS = (
    (0x1075825C, 0x107284D8, "pass_mark_register_candidates", True, 1),
    (0x107583B2, 0x1072FB58, "global_color_registers", False, 3),
)

# --detail: steps inside build_live_ranges 0x10726d75 and global colouring 0x1072fb58, dumped at entry.
DETAIL_HOOKS = tuple(
    (site, target, name, False, 3)
    for site, target, name in (
        (0x10726E00, 0x10727BD3, "assign_candidate_indices"),
        (0x10726E59, 0x1072E5B9, "sub_1072e5b9"),
        (0x10726E60, 0x1072E7CB, "insert_upward_exposed_reloads"),
        (0x10726E83, 0x1072ED0D, "compute_reaching_def_webs"),
        (0x10726EA6, 0x1072F55D, "create_web_live_ranges"),
        (0x10726EAE, 0x10726FC6, "solve_block_liveness#2"),
        (0x1072FC41, 0x10725B42, "prune_low_use_live_ranges"),
        (0x1072FCB7, 0x107388F3, "rewrite_live_range_operands"),
        (0x1072F6CC, 0x10726309, "insert_live_range_spill_store@build"),
        (0x10720F53, 0x10726309, "insert_live_range_spill_store@split"),
        (0x10725B74, 0x10725EED, "demote_live_range@prune"),
        (0x1073207B, 0x10725EED, "demote_live_range@unprofitable"),
    )
)

SYMBOL = re.compile(r"#(\d+)c(\d+)(?:\^(\d+)\+(-?\d+))?z(-?\d+)(?:'([^\s\]]+))?")
TUPLE = re.compile(r"^T (\w+) op=(\w+) k=(\w+) ty=(\w+) ln=(\d+) tag=(\d+)(.*)$")
OPERAND = re.compile(r"\[(\w+):(\d+):(\w+) f(\w+)\.(\w+) ([^\]]*?)\]")


def trace(scratch: Path, out: Path, *, late: bool = True, detail: bool = False):
    extra = PROMOTION_HOOKS + (DETAIL_HOOKS if detail else ()) + (iv_trace.LATE_HOOKS if late else ())
    profile = iv_trace.profile_with_hooks(extra, passes=True)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: profile
    c2.observer_source = iv_trace.observer_source
    c2.decode_trace = iv_trace.decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


def symbols(event):
    """(id, class) -> (parent id, offset, size, name) for every symbol printed in a dump.

    Ids are unique per symbol class, not globally (hard registers reuse small ids)."""
    table = {}
    for m in SYMBOL.finditer(event["body"]):
        sid, cls, parent, off, size, name = m.groups()
        key = (int(sid), int(cls))
        if name or key not in table:
            table[key] = (parent and int(parent), off and int(off), int(size), name)
    return table


def select(table, names):
    """Symbol ids named in `names`, plus every part whose parent is one of them."""
    roots = set()
    for name in names:
        if name.startswith("#"):
            roots |= {key for key in table if key[0] == int(name[1:]) and key[1] in (3, 4, 5)}
        else:
            roots |= {key for key, info in table.items() if info[3] == name}
    ids = {key[0] for key in roots}
    return roots | {key for key, info in table.items() if key[1] in (3, 4, 5) and info[0] in ids}


def refs(side, ids):
    """(kind, symbol id) of each operand on one side that names a selected symbol."""
    found = []
    for m in OPERAND.finditer(side):
        kind, body = int(m.group(2)), m.group(6)
        s = SYMBOL.search(body)
        if s and (int(s.group(1)), int(s.group(2))) in ids:
            found.append((kind, int(s.group(1)), m.group(3)))
    return found


def event_label(e):
    return f"{e['boundary']:6s} {e['name']}"


def classify(events, ids):
    """Per dump: the tuples touching the selected symbols and their reference counts."""
    out = []
    for e in events:
        if not e["body"].strip():
            continue
        rows, counts = [], {"mem-store": 0, "reg-def": 0, "mem-read": 0, "reg-read": 0, "addr": 0}
        for line in e["body"].splitlines():
            m = TUPLE.match(line)
            if not m:
                continue
            addr, op, _, _, ln, _, rest = m.groups()
            dst, _, src = rest.partition("<= ")
            d, s = refs(dst, ids), refs(src, ids)
            if not d and not s:
                continue
            for kind, _, _ in d:
                counts["mem-store" if kind == 2 else "reg-def" if kind == 1 else "addr"] += 1
            for kind, _, _ in s:
                counts["mem-read" if kind == 2 else "reg-read" if kind == 1 else "addr"] += 1
            desc = " ".join(f"{'W' if x in d else 'R'}k{x[0]}#{x[1]}:{x[2]}" for x in d + s)
            rows.append(f"    {addr} op={op} ln={ln} {desc}")
        out.append((e, counts, rows))
    return out


def report(events, names, verbose=False):
    """Summarise each dump; print the tuples whenever the reference counts change.

    A memory store whose count rises after `pass_mark_register_candidates` returned was created
    after promotion (lowering, x87 folding, live-range store-back, demotion or spilling)."""
    table = {}
    for e in events:
        table.update(symbols(e))
    ids = select(table, names)
    lines = [f"symbols: {', '.join(f'#{i}c{c} {table[i, c]}' for i, c in sorted(ids))}"]
    previous, promoted, baseline, quiet = None, False, None, None
    for e, counts, rows in classify(events, ids):
        summary = " ".join(f"{k}={v}" for k, v in counts.items())
        flag = ""
        if promoted and baseline is not None and counts["mem-store"] > baseline:
            flag = f"  <-- {counts['mem-store'] - baseline} memory store(s) more than after promotion"
        line = f"  [{e['event']:2d}] {event_label(e):48s} {summary}{flag}"
        if verbose or counts != previous:
            if quiet:
                lines.append(f"       ... unchanged through [{quiet}]")
            lines.append(line)
            lines += rows
            quiet = None
        else:
            quiet = f"{e['event']}] {event_label(e).strip()}"
        previous = counts
        if e["name"] == "pass_mark_register_candidates" and e["boundary"] == "return":
            promoted, baseline = True, counts["mem-store"]
    if quiet:
        lines.append(f"       ... unchanged through [{quiet}]")
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path, nargs="?")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--symbol", action="append", default=[], help="front-end name or #id; repeatable")
    parser.add_argument("--no-late", action="store_true", help="skip the post-allocation dumps")
    parser.add_argument("--detail", action="store_true", help="also dump inside live-range building and colouring")
    parser.add_argument("--report-only", type=Path)
    parser.add_argument("--verbose", action="store_true", help="print the tuples at every dump")
    args = parser.parse_args()
    if args.report_only:
        out = args.report_only
    else:
        if not args.scratch or not args.out:
            parser.error("scratch and --out are required")
        result = trace(args.scratch, args.out, late=not args.no_late, detail=args.detail)
        print(json.dumps({"out": str(args.out), "events": result["events"], "metrics": result["metrics"]}))
        out = args.out
    if args.symbol:
        events = json.loads((out / "snapshots.json").read_text())
        text = "\n".join(report(events, args.symbol, args.verbose)) + "\n"
        (out / "store-report.txt").write_text(text)
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
