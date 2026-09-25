"""Trace VC6 C2 global-colouring priorities per block, and the colouring order (diagnostic only).

`score_live_ranges` (0x10724b25) walks the blocks in list order. For every block it adds
P*w*S_b to each live range referenced in the block and subtracts P*w from each range that is only
live through it (P = distinct candidate ranges referenced in the block, w = 1 << loop depth,
S_b = the range's raw savings in the block). This tool hooks:

    score0    0x1072fc30 -> 0x10724b25   initial scoring (dump at return)
    rescore   0x1072fd62 -> 0x10724b25   rescoring after a split (dump at return)
    choose    0x1072fe5f -> 0x10732f7c   chooser entry and return (range, allowed set, register)
    split     0x1072fd3d -> 0x107204d6   split at the pending markers
    unprof    0x1072fdc7 -> 0x10732001   range with benefit <= 0
    block     0x10724b72 -> 0x1072547e   start of every block inside score_live_ranges

At each block start it records the running priority and benefit of every live range, so the
difference between two consecutive records is exactly that block's contribution. At each scoring
return it records the per-block live-in/live-out/referenced range sets and every live range.

    uv run python scripts/c2/priority_trace.py <scratch> --out <new-dir> [--constant 0] [--symbol 549]
    # a snail-mail scratch, from the snail-mail checkout:
    uv run python ../crimson/scripts/c2/priority_trace.py --snail <scratch> --out <new-dir> --constant 0
    uv run python scripts/c2/priority_trace.py --reuse <trace-dir> --constant 0 --symbol 549

The report prints the colouring order (every chooser call with its priority, block span, allowed set
and register) and, for the ranges selected by --constant/--symbol/--range, their per-block priority
contributions in every scoring run.

`--bump-constant V --bonus N` is an intervention, not a trace: it adds N once to the priority of every
live range of constant V that starts in the first real block, at every scoring return. The whole-COFF
check then fails by design; the tool reports the matcher metrics of the observed object instead.

See tools/match/c2/compiler/guard-placement.md.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import il_stage_trace as stage

REGISTERS = {1: "eax", 2: "ecx", 3: "edx", 4: "ebx", 5: "esp", 6: "ebp", 7: "esi", 8: "edi"}
REGISTER_DESCRIPTORS = 0xAC784  # eax descriptor RVA; the others follow at 0x54-byte steps
NAMES = {12: "score0", 13: "rescore", 14: "choose", 15: "split", 16: "unprof", 17: "block"}

stage.PRESETS["priority"] = (
    (0x1072FC30, 0x10724B25, "score0", True, 5),
    (0x1072FD62, 0x10724B25, "rescore", True, 5),
    (0x1072FE5F, 0x10732F7C, "choose", True, 6),
    (0x1072FD3D, 0x107204D6, "split", False, 0),
    (0x1072FDC7, 0x10732001, "unprof", True, 6),
    (0x10724B72, 0x1072547E, "block", False, 7),
)

EXTRA = r"""
static unsigned long saved_lr, bumped[256], nbumped;
static void bits(unsigned long set)
{
    unsigned long chunk, b;
    if (!set) return;
    for (chunk = W(set, 0); chunk; chunk = W(chunk, 4))
        for (b = 0; b < 32; ++b) if (W(chunk, 8) & (1u << b)) { dec(W(chunk, 0) + b); s(","); }
}
static void lrline(unsigned long lr)
{
    unsigned long y, node;
    if (!lr) return;
    y = W(lr, 0);
    s("LR id="); dec(W(lr, 0x1c)); s(" p="); hx(lr);
    s(" sym="); if (y) { dec(W(y, 0x1c)); s(" cls="); dec(*(unsigned char *)(y + 4)); } else s("-");
    if (y && *(unsigned char *)(y + 4) == 13 && (node = W(y, 0x28)) != 0 && *(unsigned char *)(node + 8) == 7)
        { s(" val="); dec((long)W(node, 0x18)); }
    s(" prio="); dec((long)W(lr, 0xc)); s(" ben="); dec((long)W(lr, 0x3c)); s(" refs="); dec((long)W(lr, 0x24));
    s(" tie="); dec((long)W(lr, 0x40)); s(" reg="); hx(W(lr, 0x10) ? W(lr, 0x10) - compiler_base : 0);
    s(" fb="); hx(W(lr, 0x28)); s(" lb="); hx(W(lr, 0x30)); s(" allowed="); bits(W(lr, 0x20)); s("\n");
}
static void bump(void)
{
    unsigned long b, lr, y, node, k, key, first = W(W(W(saved_function, 8), 0), 0);
    for (b = 0; b < 0x400; ++b)
        for (lr = W(compiler_base + 0x9d88c, b * 4); lr; lr = W(lr, 0x2c)) {
            y = W(lr, 0);
            if (!y || *(unsigned char *)(y + 4) != 13 || !(node = W(y, 0x28)) || *(unsigned char *)(node + 8) != 7)
                continue;
            if ((long)W(node, 0x18) != BUMP_VALUE || W(lr, 0x28) != first) continue;
            key = lr ^ (W(lr, 0x1c) << 20);
            for (k = 0; k < nbumped && bumped[k] != key; ++k) ;
            if (k < nbumped || nbumped == 256) continue;
            bumped[nbumped++] = key;
            *(long *)(lr + 0xc) += BUMP_BONUS;
            s("BUMP id="); dec(W(lr, 0x1c)); s(" prio="); dec((long)W(lr, 0xc)); s("\n");
        }
}
static void dump_ranges(unsigned long block)
{
    unsigned long fn = saved_function, blk, b, lr;
    if (block) {
        s("BS n="); dec(*(short *)(block + 0x6c)); s(" d="); dec(*(unsigned char *)(block + 0x6e)); s(" :");
        for (b = 0; b < 0x400; ++b)
            for (lr = W(compiler_base + 0x9d88c, b * 4); lr; lr = W(lr, 0x2c))
                { s(" "); dec(W(lr, 0x1c)); s("="); dec((long)W(lr, 0xc)); s("/"); dec((long)W(lr, 0x3c)); }
        s("\n");
        return;
    }
    if (BUMP_BONUS) bump();
    for (blk = W(W(fn, 8), 0); blk; blk = W(blk, 0)) {
        s("BLK n="); dec(*(short *)(blk + 0x6c)); s(" p="); hx(blk); s(" d="); dec(*(unsigned char *)(blk + 0x6e));
        s(" in="); bits(W(blk, 0x40)); s(" out="); bits(W(blk, 0x44)); s(" ref="); bits(W(blk, 0x48)); s("\n");
    }
    for (b = 0; b < 0x400; ++b)
        for (lr = W(compiler_base + 0x9d88c, b * 4); lr; lr = W(lr, 0x2c)) lrline(lr);
}
"""


def observer_source(bump_value: int, bonus: int):
    base = stage.observer_source

    def patched(iv):
        make = base(iv)

        def source(prof):
            text = make(prof)
            # Hooks 8..10 run inside global colouring with ecx != function; keep the function pointer.
            text = text.replace("if (phase < 12) saved_function = r[6];", "if (phase < 8) saved_function = r[6];")
            extra = EXTRA.replace("BUMP_VALUE", str(bump_value)).replace("BUMP_BONUS", str(bonus))
            text = text.replace("static void __cdecl observe(", extra + "static void __cdecl observe(", 1)
            text = text.replace(
                '    s("END\\n");\n    flush();\n}',
                "    if (modes[index] == 5 && phase >= 100) dump_ranges(0);\n"
                "    if (modes[index] == 7) dump_ranges(r[2]);\n"
                "    if (modes[index] == 6) { if (phase < 100) saved_lr = r[6]; lrline(saved_lr); }\n"
                '    s("END\\n");\n    flush();\n}',
                1,
            )
            if "dump_ranges(r[2])" not in text or "phase < 8" not in text:
                raise ValueError("Unexpected observer template")
            return text

        return source

    return patched


def events(path: Path):
    text = path.read_bytes().decode("latin-1")
    result = []
    for block in text.split("EVENT ")[1:]:
        head, _, rest = block.partition("\n")
        phase = int(head.split()[0])
        result.append((phase, rest.removesuffix("END\n").splitlines()))
    return result


def parse_range(line: str) -> dict:
    fields = dict(re.findall(r"(\w+)=(\S*)", line))
    fields["allowed"] = [REGISTERS[int(x)] for x in fields.get("allowed", "").split(",") if x]
    reg = int(fields.get("reg", "0"), 16)
    fields["register"] = REGISTERS.get((reg - REGISTER_DESCRIPTORS) // 0x54 + 1) if reg else None
    return fields


def label(lr: dict) -> str:
    if "val" in lr:
        return f"const {lr['val']}"
    return f"sym #{lr['sym']} c{lr.get('cls', '?')}"


def report(trace_dir: Path, constants: set[str], symbols: set[str], ranges: set[str]):
    blocks: dict[str, str] = {}
    runs = []
    current = None
    order = 0
    allowed = ""
    print("colouring order:")
    for phase, lines in events(trace_dir / "observed/phases.bin"):
        index = phase % 100
        name = NAMES.get(index)
        if name is None:
            continue
        for line in lines:
            if line.startswith("BLK"):
                fields = dict(re.findall(r"(\w+)=(\S*)", line))
                blocks[fields["p"]] = fields["n"]
            elif line.startswith("BUMP"):
                print("   ", line)
        if name in ("score0", "rescore") and phase < 100:
            current = {"name": name, "starts": []}
            runs.append(current)
        elif name == "block" and current is not None:
            match = re.match(r"BS n=(-?\d+) d=(\d+) :(.*)", lines[0])
            values = {i: (int(p), int(b)) for i, p, b in re.findall(r"(\d+)=(-?\d+)/(-?\d+)", match.group(3))}
            current["starts"].append((match.group(1), match.group(2), values))
        elif name in ("score0", "rescore"):
            current["final"] = {lr["id"]: lr for lr in (parse_range(x) for x in lines if x.startswith("LR"))}
            current = None
            print(f"  -- {name}")
        elif name == "choose" and phase >= 100:
            lr = parse_range(lines[0])
            order += 1
            span = f"{blocks.get(lr['fb'], '?')}..{blocks.get(lr['lb'], '?')}"
            print(
                f"  #{order:<3} lr{lr['id']:>4} {label(lr):16} prio {lr['prio']:>6} tie {lr['tie']:>4}"
                f" blocks {span:9} allowed {allowed:24} -> {lr['register']}",
            )
        elif name == "choose":
            allowed = ",".join(parse_range(lines[0])["allowed"])
        elif name in ("split", "unprof") and phase < 100:
            extra = f" lr{parse_range(lines[0])['id']} {label(parse_range(lines[0]))}" if lines else ""
            print(f"  -- {name}{extra}")
    for number, run in enumerate(runs):
        final = run.get("final", {})
        chosen = [
            lr for lr in final.values() if lr.get("val") in constants or lr.get("sym") in symbols or lr["id"] in ranges
        ]
        if not chosen:
            continue
        print(f"\nrun {number} ({run['name']}): per-block contributions")
        starts = [*run["starts"], (None, None, {k: (int(v["prio"]), int(v["ben"])) for k, v in final.items()})]
        for lr in chosen:
            span = f"{blocks.get(lr['fb'], '?')}..{blocks.get(lr['lb'], '?')}"
            print(f"  lr{lr['id']} {label(lr)} blocks {span}: prio {lr['prio']} benefit {lr['ben']}")
            for (n, depth, now), (_, _, after) in itertools.pairwise(starts):
                if lr["id"] in now and lr["id"] in after:
                    dp, db = after[lr["id"]][0] - now[lr["id"]][0], after[lr["id"]][1] - now[lr["id"]][1]
                    if dp or db:
                        print(f"      block {n:>4} depth {depth}: prio {dp:+d}  benefit {db:+d}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reuse", type=Path, help="report an existing trace directory")
    parser.add_argument("--snail", action="store_true", help="trace a snail-mail scratch through its adapter")
    parser.add_argument("--match-root", type=Path, help="snail-mail: compile against another tools/match root")
    parser.add_argument("--constant", action="append", default=[], help="report ranges of this constant value")
    parser.add_argument("--symbol", action="append", default=[], help="report ranges of this symbol id")
    parser.add_argument("--range", action="append", default=[], help="report this live-range id")
    parser.add_argument("--bump-constant", type=int, default=0)
    parser.add_argument("--bonus", type=int, default=0, help="intervention: priority added (see module doc)")
    args = parser.parse_args()
    trace_dir = args.reuse
    if trace_dir is None:
        if args.scratch is None or args.out is None:
            parser.error("scratch and --out are required")
        c2, iv = stage.load_modules(args.snail, args.match_root)
        stage.observer_source = observer_source(args.bump_constant, args.bonus)
        try:
            result = stage.trace(c2, iv, args.scratch, args.out, "priority")
            print(json.dumps({"metrics": result["metrics"]}))
        except ValueError as error:
            if not args.bonus:
                raise
            config = c2.match.load_scratch_config((args.out / "source").resolve())
            metrics = c2.replay.function_metrics(config, args.out / "observed/replay.obj")
            print(json.dumps({"intervention": str(error), "observed_metrics": metrics}))
        trace_dir = args.out
    report(trace_dir, set(args.constant), set(args.symbol), set(args.range))


if __name__ == "__main__":
    main()
