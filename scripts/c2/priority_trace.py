"""Trace VC6 C2 global-colouring priorities per block, and the colouring order (diagnostic only).

`score_live_ranges` walks the blocks in list order. For every block it adds P*w*S_b to each live
range referenced in the block and subtracts P*w from each range that is only live through it
(P = distinct candidate ranges referenced in the block, w = 1 << loop depth, S_b = the range's raw
savings in the block). This tool hooks, per C2 build (see LAYOUTS and
tools/match/c2/compiler/regalloc.md):

    colour    global_color_registers entry (ecx = function)
    score0    initial scoring (dump at return)
    rescore   rescoring after a split (dump at return)
    choose    chooser entry and return (range, allowed set, register)
    split     split at the pending markers
    unprof    range with benefit <= 0
    block     start of every block inside score_live_ranges

At each block start it records the running priority and benefit of every live range, so the
difference between two consecutive records is exactly that block's contribution. At each scoring
return it records the per-block live-in/live-out/referenced range sets and every live range.

    uv run python scripts/c2/priority_trace.py <scratch> --out <new-dir> [--constant 0] [--symbol 549]
    uv run python scripts/c2/priority_trace.py <scratch> --out <new-dir> --build 1.9.8 --symbol 549
    uv run python scripts/c2/priority_trace.py --reuse <trace-dir> --constant 0 --symbol 549

`--build` compiles the scratch as that game build (decomp/builds.json: its compiler and CL_BUILD)
and observes that compiler's C2: 1.9.93 is C2 12.00.8966 (msvc6.5), 1.9.8 is 12.00.9044
(msvc6.5pp, which colours four register classes instead of two).

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
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import iv_trace as iv

from crimson_re import match_c2 as c2

REGISTERS = {1: "eax", 2: "ecx", 3: "edx", 4: "ebx", 5: "esp", 6: "ebp", 7: "esi", 8: "edi"}
NAMES = ("colour", "score0", "rescore", "choose", "split", "unprof", "block")
# Observer actions per hook: 0 event head only, 5 dump ranges at return, 6 one range (ecx at entry, again at
# return), 7 running priorities at a block start.
MODES = {"colour": 0, "score0": 5, "rescore": 5, "choose": 6, "split": 0, "unprof": 6, "block": 7}
RETURNS = {"score0", "rescore", "choose", "unprof"}


@dataclass(frozen=True)
class Layout:
    """Where one C2 build keeps what the observer reads (image base 0x10700000)."""

    c2_sha256: str
    # (call site VA, callee VA) per NAMES entry
    hooks: tuple[tuple[int, int], ...]
    # Word of the observer's register frame (pushad 0..7, flags 8, return 9, caller stack 10..) holding
    # the block at the block-start call.
    block_word: int
    # Field offsets and globals, as C macros of the observer.
    fields: dict[str, int]


LAYOUTS = {
    "msvc6.5": Layout(
        c2_sha256="d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a",
        hooks=(
            (0x107583B2, 0x1072FB58),
            (0x1072FC30, 0x10724B25),
            (0x1072FD62, 0x10724B25),
            (0x1072FE5F, 0x10732F7C),
            (0x1072FD3D, 0x107204D6),
            (0x1072FDC7, 0x10732001),
            (0x10724B72, 0x1072547E),
        ),
        block_word=2,  # ebp
        fields={
            "LR_TABLE": 0x9D88C,
            "LR_PRIO": 0xC,
            "LR_REG": 0x10,
            "LR_ID": 0x1C,
            "LR_ALLOWED": 0x20,
            "LR_REFS": 0x24,
            "LR_FIRST": 0x28,
            "LR_NEXT": 0x2C,
            "LR_LAST": 0x30,
            "LR_BENEFIT": 0x3C,
            "LR_TIE": 0x40,
            "BLK_IN": 0x40,
            "BLK_OUT": 0x44,
            "BLK_REF": 0x48,
            "BLK_NUMBER": 0x6C,
            "BLK_DEPTH": 0x6E,
        },
    ),
    "msvc6.5pp": Layout(
        c2_sha256="6c8e3988a5ccd69a9f9829b5c7512848d71c018b8d24be3928d7b00b5f79f231",
        hooks=(
            (0x1072E336, 0x1073122D),
            (0x107313C2, 0x10707A0B),
            (0x10731461, 0x10707A0B),
            (0x10731552, 0x10709937),
            (0x1073143E, 0x10744286),
            (0x107314C5, 0x10743332),
            (0x10707A54, 0x107054F8),
        ),
        block_word=10 + 0x1C // 4,  # [esp+0x1c] at the call
        fields={
            "LR_TABLE": 0xAC5B8,
            "LR_PRIO": 0xC,
            "LR_REG": 0x10,
            "LR_ID": 0x1C,
            "LR_ALLOWED": 0x20,
            "LR_REFS": 0x24,
            "LR_FIRST": 0x28,
            "LR_NEXT": 0x2C,
            "LR_LAST": 0x34,
            "LR_BENEFIT": 0x40,
            "LR_TIE": 0x44,
            "BLK_IN": 0x48,
            "BLK_OUT": 0x4C,
            "BLK_REF": 0x50,
            "BLK_NUMBER": 0x70,
            "BLK_DEPTH": 0x72,
        },
    ),
}
BASE = 0x10700000

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
    s("LR id="); dec(W(lr, LR_ID)); s(" p="); hx(lr);
    s(" sym="); if (y) { dec(W(y, 0x1c)); s(" cls="); dec(*(unsigned char *)(y + 4)); } else s("-");
    if (y && *(unsigned char *)(y + 4) == 13 && (node = W(y, 0x28)) != 0 && *(unsigned char *)(node + 8) == 7)
        { s(" val="); dec((long)W(node, 0x18)); }
    s(" prio="); dec((long)W(lr, LR_PRIO)); s(" ben="); dec((long)W(lr, LR_BENEFIT));
    s(" refs="); dec((long)W(lr, LR_REFS)); s(" tie="); dec((long)W(lr, LR_TIE));
    s(" reg="); dec(W(lr, LR_REG) ? W(W(lr, LR_REG), 0x1c) : 0);
    s(" fb="); hx(W(lr, LR_FIRST)); s(" lb="); hx(W(lr, LR_LAST)); s(" allowed="); bits(W(lr, LR_ALLOWED)); s("\n");
}
static void bump(void)
{
    unsigned long b, lr, y, node, k, key, first = W(W(W(saved_function, 8), 0), 0);
    for (b = 0; b < 0x400; ++b)
        for (lr = W(compiler_base + LR_TABLE, b * 4); lr; lr = W(lr, LR_NEXT)) {
            y = W(lr, 0);
            if (!y || *(unsigned char *)(y + 4) != 13 || !(node = W(y, 0x28)) || *(unsigned char *)(node + 8) != 7)
                continue;
            if ((long)W(node, 0x18) != BUMP_VALUE || W(lr, LR_FIRST) != first) continue;
            key = lr ^ (W(lr, LR_ID) << 20);
            for (k = 0; k < nbumped && bumped[k] != key; ++k) ;
            if (k < nbumped || nbumped == 256) continue;
            bumped[nbumped++] = key;
            *(long *)(lr + LR_PRIO) += BUMP_BONUS;
            s("BUMP id="); dec(W(lr, LR_ID)); s(" prio="); dec((long)W(lr, LR_PRIO)); s("\n");
        }
}
static void dump_ranges(unsigned long block)
{
    unsigned long fn = saved_function, blk, b, lr;
    if (block) {
        s("BS n="); dec(*(short *)(block + BLK_NUMBER)); s(" d="); dec(*(unsigned char *)(block + BLK_DEPTH)); s(" :");
        for (b = 0; b < 0x400; ++b)
            for (lr = W(compiler_base + LR_TABLE, b * 4); lr; lr = W(lr, LR_NEXT))
                { s(" "); dec(W(lr, LR_ID)); s("="); dec((long)W(lr, LR_PRIO)); s("/"); dec((long)W(lr, LR_BENEFIT)); }
        s("\n");
        return;
    }
    if (BUMP_BONUS) bump();
    for (blk = W(W(fn, 8), 0); blk; blk = W(blk, 0)) {
        s("BLK n="); dec(*(short *)(blk + BLK_NUMBER)); s(" p="); hx(blk); s(" d="); dec(*(unsigned char *)(blk + BLK_DEPTH));
        s(" in="); bits(W(blk, BLK_IN)); s(" out="); bits(W(blk, BLK_OUT)); s(" ref="); bits(W(blk, BLK_REF)); s("\n");
    }
    for (b = 0; b < 0x400; ++b)
        for (lr = W(compiler_base + LR_TABLE, b * 4); lr; lr = W(lr, LR_NEXT)) lrline(lr);
}
"""


def profile(compiler: str) -> dict:
    layout = LAYOUTS[compiler]
    hooks = [
        {"site": site - BASE, "target": target - BASE, "return": name in RETURNS, "mode": MODES[name], "name": name}
        for name, (site, target) in zip(NAMES, layout.hooks, strict=True)
    ]
    return {
        "schema_version": 1,
        "name": f"{compiler}-c2-{layout.c2_sha256[:8]}-priority",
        "c2_sha256": layout.c2_sha256,
        "invoke_rva": c2.invoke_rva(),
        "hooks": hooks,
    }


def load_profile(compiler: str):
    def load():
        prof = profile(compiler)
        if c2.replay.sha((c2.replay.COMPILER / "Bin/C2.DLL").read_bytes()) != prof["c2_sha256"]:
            raise ValueError(f"{c2.replay.COMPILER.name} C2.DLL is not the build the {compiler} hooks were read from")
        return prof

    return load


def observer_source(compiler: str, bump_value: int, bonus: int):
    layout = LAYOUTS[compiler]

    def source(prof):
        stock = iv.STOCK_OBSERVER_SOURCE(prof)
        wrappers = stock[stock.index("__declspec(naked)") : stock.index("void __stdcall start")]
        header = stock[: stock.index("#include")]
        defines = "".join(f"#define {name} {value:#x}\n" for name, value in layout.fields.items())
        modes = "static unsigned long modes[] = {" + ",".join(str(h["mode"]) for h in prof["hooks"]) + "};\n"
        text = iv.OBSERVER.replace("/* GENERATED_HOOKS */", wrappers)
        replacements = (
            ("    if (phase < 12) saved_function = r[6];\n", "    if (phase == 0) saved_function = r[6];\n"),
            ("    if (phase == 12) saved_loop = r[6];\n", ""),
            ("static char buf[65536];", modes + "static unsigned long compiler_base;\nstatic char buf[65536];"),
            (
                "    base = (unsigned char *)invoke - INVOKE_RVA;\n",
                "    base = (unsigned char *)invoke - INVOKE_RVA;\n    compiler_base = (unsigned long)base;\n",
            ),
            (
                "static void __cdecl observe(",
                EXTRA.replace("BUMP_VALUE", str(bump_value)).replace("BUMP_BONUS", str(bonus))
                + "static void __cdecl observe(",
            ),
            (
                '    s("END\\n");\n    flush();\n}',
                (
                    "    if (modes[index] == 5 && phase >= 100) dump_ranges(0);\n"
                    f"    if (modes[index] == 7) dump_ranges(r[{layout.block_word}]);\n"
                    "    if (modes[index] == 6) { if (phase < 100) saved_lr = r[6]; lrline(saved_lr); }\n"
                    '    s("END\\n");\n    flush();\n}'
                ),
            ),
        )
        for old, new in replacements:
            if text.count(old) != 1:
                raise ValueError(f"Unexpected observer template near {old.strip()[:40]!r}")
            text = text.replace(old, new)
        return header + defines + text

    return source


def trace(scratch: Path, out: Path, build: str | None, bump_value: int, bonus: int) -> dict:
    config, _ = c2.scratch_target(scratch, build)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = load_profile(config.compiler)
    c2.observer_source = observer_source(config.compiler, bump_value, bonus)
    c2.decode_trace = iv.decode
    try:
        return c2.trace(scratch, out, build=build)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


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
    reg = int(fields.get("reg", "0"))
    fields["register"] = REGISTERS.get(reg, f"reg{reg}") if reg else None
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
        name = NAMES[index]
        for line in lines:
            if line.startswith("BLK"):
                fields = dict(re.findall(r"(\w+)=(\S*)", line))
                blocks[fields["p"]] = fields["n"]
            elif line.startswith("BUMP"):
                print("   ", line)
        if name == "colour":
            print("  == function")
        elif name in ("score0", "rescore") and phase < 100:
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
    parser.add_argument("--build", help="compile and observe as this game build (default: canonical)")
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
        try:
            result = trace(args.scratch, args.out, args.build, args.bump_constant, args.bonus)
            print(json.dumps({"metrics": result["metrics"]}))
        except ValueError as error:
            if not args.bonus:
                raise
            config, target = c2.scratch_target(args.out / "source", args.build)
            metrics = c2.replay.function_metrics(config, args.out / "observed/replay.obj", target)
            print(json.dumps({"intervention": str(error), "observed_metrics": metrics}))
        trace_dir = args.out
    report(trace_dir, set(args.constant), set(args.symbol), set(args.range))


if __name__ == "__main__":
    main()
