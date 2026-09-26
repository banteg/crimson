"""Which candidate live ranges does a block reference at each register-allocation stage (diagnostic only).

`score_live_ranges` (0x10724b25) charges every range with P, the number of distinct candidate live
ranges referenced in a block (regalloc.md §3.5, guard-placement.md §2). A range counts if any real
tuple of the block has a class-matching kind-1 operand whose home is that live range, even when the
tuple is later deleted: LOADCONSTs of constants that end up as immediates, reloads freed by pruning,
copies whose two ranges get one register. Tuples deleted before scoring do not count. This tool
dumps the IL at every stage between `build_live_ranges` and the local allocator and, for the chosen
blocks, prints the referenced ranges and the tuples each stage removed:

    blr          0x10726d75 entry  (candidates still carry the placeholder home, listed by symbol)
    colour       0x1072fb58 entry  = coalesce_copy_live_ranges 0x10730308 entry
    coalesced    0x107306c1 entry  = after copy coalescing
    substituted  0x10730a40 entry  = after forward_substitute_single_def_ranges
    x87          0x1072f8fc entry  = after the x87 copy fold 0x1072fef2
    score0       0x10724b25 entry  = after mark_register_pressure_splits 0x10730ab7 (initial scoring)
    rescore      0x10724b25 entry  from 0x1072fd62 (only with --rescore; one dump per split)
    local        0x107336f4 entry  = after global colouring and rewrite_live_range_operands

`P` printed at `score0` is the value score_live_ranges uses for the block in the initial scoring
(integer class; `--class 1` for x87). Ranges pruned after it (0x10725b42) no longer count in the
rescorings that decide split pieces.

    uv run python scripts/c2/block_refs_trace.py <scratch> --out <new-dir> --block 1
    # a snail-mail scratch, from the snail-mail checkout:
    uv run python ../crimson/scripts/c2/block_refs_trace.py --snail <scratch> --out <new-dir> --block 1
    uv run python scripts/c2/block_refs_trace.py --reuse <trace-dir> --block 1 --block 7

See tools/match/c2/compiler/invisible-ranges.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import il_stage_trace as stage

BASE = 0x10700000
# Stock hook index -> stage name (entry dumps). Hooks 8..10 run inside global colouring.
STOCK_STAGES = {0: "glob", 6: "blr", 8: "colour", 9: "coalesced", 10: "substituted", 11: "local"}
EXTRA_HOOKS = (
    (0x1072FBEC, 0x1072F8FC, "x87"),
    (0x1072FC30, 0x10724B25, "score0"),
)
RESCORE_HOOK = (0x1072FD62, 0x10724B25, "rescore")
MARKERS = {"1ae", "1af", "1b0", "1b4"}
# g_type_class 0x107a09bc: type nibbles 1, 2, 3, 5, 7 are integer (class 0), 4 is x87 (class 1).
TYPE_CLASS = {"1": 0, "2": 0, "3": 0, "5": 0, "7": 0, "4": 1}
CANDIDATE = re.compile(
    r"\[k1:(?P<type>[0-9a-f]+) #(?P<sym>\d+)c(?P<cls>\d+)(?P<part>\^\d+\+\d+)?z\d+/[0-9a-f.]+"
    r"(?:'(?P<name>\w+))?(?:@a\d+)? @#(?P<home>\d+)c2z",
)
LOADCONST = re.compile(r"\[k1:\w+ #0c13\S* @#(\d+)c2z\S*\] <= \[k(?:7:\w+ =(-?\d+)|3:\w+ (#\d+)\S*)\]")


def profile(c2, rescore: bool):
    stock = c2.load_profile()
    hooks = [
        dict(h, mode=3 if i in STOCK_STAGES else 0, name=STOCK_STAGES.get(i, f"pass@{h['target'] + BASE:#x}"))
        for i, h in enumerate(stock["hooks"][:12])
    ]
    extra = [*EXTRA_HOOKS, RESCORE_HOOK] if rescore else list(EXTRA_HOOKS)
    hooks += [{"site": s - BASE, "target": t - BASE, "return": False, "mode": 3, "name": n} for s, t, n in extra]
    return {**stock, "name": stock["name"] + "-block-refs", "hooks": hooks}


def observer_source(original):
    def make(iv):
        base = original(iv)

        def source(prof):
            text = base(prof)
            # Hooks 8..10 and the extra hooks run inside global colouring, where ecx is not the function.
            patched = text.replace(
                "if (phase < 12) saved_function = r[6];",
                "if (phase < 8 || phase == 11) saved_function = r[6];",
            )
            if patched == text:
                raise ValueError("Unexpected observer template")
            return patched

        return source

    return make


def dumps(trace_dir: Path):
    """[(stage, [raw tuple lines])] for the first compiled function."""
    prof = json.loads((trace_dir / "profile.json").read_text())
    result = []
    for event in stage.decode((trace_dir / "observed/phases.bin").read_bytes(), prof):
        il = [line for line in event["body"].splitlines() if line.startswith("T ")]
        if not il or event["boundary"] != "entry":
            continue
        if event["name"] == "glob" and result:
            break
        result.append((event["name"], il))
    return result


def split_blocks(il: list[str]) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    current = None
    for line in il:
        m = re.search(r"BLOCK n=(-?\d+)", line)
        if m:
            current = m.group(1)
            blocks.setdefault(current, [])
            continue
        if current is not None:
            blocks[current].append(line)
    return blocks


def constant_values(il: list[str]) -> dict[str, str]:
    """{live range id: value} of the constant ranges loaded anywhere in one IL dump."""
    values = {}
    for line in il:
        m = LOADCONST.search(stage.pretty(line))
        if m:
            values[m.group(1)] = m.group(2) or f"&{m.group(3)}"
    return values


def references(lines: list[str], cls: int, values: dict[str, str]) -> dict[str, str]:
    """{home id: label} of the candidate operands of class `cls` in the real tuples of one block."""
    refs: dict[str, str] = {}
    for line in lines:
        text = stage.pretty(line)
        if text.split()[1] in MARKERS:
            continue
        for m in CANDIDATE.finditer(text):
            if TYPE_CLASS.get(m.group("type")[0]) != cls:
                continue
            home = m.group("home")
            if m.group("cls") == "13":
                label = f"const {values.get(home, '?')}"
            else:
                label = f"#{m.group('sym')}{m.group('part') or ''} c{m.group('cls')} {m.group('name') or ''}".rstrip()
            refs.setdefault(home, label)
    return refs


def report(trace_dir: Path, blocks: list[str], cls: int, show_il: bool):
    previous: dict[str, dict[str, str]] = {}
    for name, il in dumps(trace_dir):
        if name == "glob":
            continue
        per_block = split_blocks(il)
        values = constant_values(il)
        for block in blocks:
            lines = per_block.get(block, [])
            refs = references(lines, cls, values)
            addresses = {line.split()[1]: line for line in lines}
            gone = [line for addr, line in previous.get(block, {}).items() if addr not in addresses]
            previous[block] = addresses
            if name == "blr":
                symbols = sorted(
                    {m.group("sym") for line in lines for m in CANDIDATE.finditer(stage.pretty(line))},
                    key=int,
                )
                print(f"--- {name} block {block}: {len(lines)} tuples, candidate symbols {' '.join(symbols)}")
                continue
            listing = ", ".join(f"lr{home} {label}" for home, label in sorted(refs.items(), key=lambda x: int(x[0])))
            print(f"--- {name} block {block}: {len(lines)} tuples, P={len(refs)}: {listing}")
            for line in gone:
                print("    removed", stage.pretty(line)[:200])
            if show_il:
                for line in lines:
                    print("     ", stage.pretty(line)[:200])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reuse", type=Path, help="report an existing trace directory")
    parser.add_argument("--snail", action="store_true", help="trace a snail-mail scratch through its adapter")
    parser.add_argument("--match-root", type=Path, help="snail-mail: compile against another tools/match root")
    parser.add_argument("--block", action="append", default=[], help="block number (repeatable; default 1)")
    parser.add_argument("--class", dest="cls", type=int, default=0, help="register class: 0 integer, 1 x87")
    parser.add_argument("--rescore", action="store_true", help="also dump at every rescoring after a split")
    parser.add_argument("--il", action="store_true", help="print the block's tuples at every stage")
    args = parser.parse_args()
    trace_dir = args.reuse
    if trace_dir is None:
        if args.scratch is None or args.out is None:
            parser.error("scratch and --out are required")
        c2, iv = stage.load_modules(args.snail, args.match_root)
        stage.profile = lambda c2_module, preset: profile(c2_module, args.rescore)
        stage.observer_source = observer_source(stage.observer_source)
        result = stage.trace(c2, iv, args.scratch, args.out, "block-refs")
        print(json.dumps({"metrics": result["metrics"]}))
        trace_dir = args.out
    report(trace_dir, args.block or ["1"], args.cls, args.il)


if __name__ == "__main__":
    main()
