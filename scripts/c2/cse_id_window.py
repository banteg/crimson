"""Measure the CSE-id window of a snail scratch, and where its C0 comes from (VC6 C2, diagnostic only).

A CSE temporary's rank is its id: `(id << 6) & 0xffff` as a symbol leaf, `((id & 3) << 14) + 7` inside a load
leaf (sib-operand-order.md). The id is C0 + n (cse-slot-count.md). This tool answers two questions for one
scratch:

1. **Which id shifts are byte exact?** It traces the scratch once, then recompiles it with phantom pool-E ids
   for every spec and matches each object. `K:M` burns M ids before fresh slot K (`0:M` moves every CSE and
   induction temporary together, which is what a C0 change does modulo 1024). Specs accept ranges and
   combinations: `28:830..850`, `0:480..720/8`, `0:832,28:4..13`.
2. **What makes C0?** `--chunks` lists every 32-id symbol chunk opened before the first CSE slot, with the
   allocating call chain (reader temporaries, aggregate parts, frontend storage, tree simplification). C0 is
   the id counter at the first CSE slot, so it is 32 x (chunks opened so far), and it grows with the whole
   function's IL, not just the code before the slot.

Run it from the snail-mail checkout, which provides the `snail` package:

    uv run python ../crimson/scripts/c2/cse_id_window.py <scratch> --out <new-dir> [--source overlay.cpp] \
        [--chunks] [SPEC ...]

See tools/match/c2/compiler/cse-id-push.md.
"""

from __future__ import annotations

import argparse
import bisect
import json
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import cse_slot_trace as cst

m, ao = cst.m, cst.ao
CRIMSON = HERE.parents[1]
SYMBOLS_PATH = "analysis/binary_ninja/c2/c2_symbols.json"
SYMBOLS = next(
    (root / SYMBOLS_PATH for root in (CRIMSON, cst.SNAIL.parent / "crimson") if (root / SYMBOLS_PATH).exists()),
    CRIMSON / SYMBOLS_PATH,
)
C2_BASE = 0x10700000
WRAPPERS = {
    "symbol_alloc",
    "symbol_new_temp",
    "symbol_new_temp_plain",
    "operand_new_temp",
    "operand_new_temp_sym",
    "fe_symbol_get_storage",
    "symbol_get_part",
    "tuple_new_unary_temp",
    "tuple_new_binary_temp",
}

# symbol_alloc call entries also record their return-address chain, so a chunk can be tied to its opener.
CHAIN_ANCHOR = (
    "            if (readable(p)) { rec[9] = *(unsigned long *)(p + 0x1c); rec[10] = *(unsigned char *)(p + 4); }\n"
)
CHAIN_CAPTURE = (
    "        } else if (kind == 1) {\n"
    "            for (i = 9, n = 0; i < 9 + 40 && n < 10; ++i)\n"
    "                if (registers[i] >= base + 0x1000 && registers[i] < base + 0x92000) rec[29 + n++] = registers[i] - base;\n"
)


def function_names():
    functions = json.loads(SYMBOLS.read_text())["functions"]
    rows = sorted((int(address, 16) - C2_BASE, row["name"]) for address, row in functions.items())
    starts = [rva for rva, _ in rows]

    def name(rva: int) -> str:
        i = bisect.bisect_right(starts, rva) - 1
        return rows[i][1] if i >= 0 else f"{rva:#x}"

    return name


def expand(items: list[str]) -> list[str]:
    """Expand `K:A..B[/step]` ranges in each spec; commas join burns into one spec (all combinations)."""
    specs = []
    for item in items:
        combos = [""]
        for burn in item.split(","):
            at, count = burn.split(":")
            if ".." in count:
                span, _, step = count.partition("/")
                low, high = (int(x, 0) for x in span.split(".."))
                values = range(low, high + 1, int(step or 1))
            else:
                values = [int(count, 0)]
            combos = [f"{c},{at}:{v}" if c else f"{at}:{v}" for c in combos for v in values]
        specs += combos
    return specs


def chunk_report(table: list[dict], records: list[tuple]) -> None:
    name = function_names()
    top, pending, entered = -1, [], False
    openers = []
    for rec in records:
        phase = rec[0]
        if phase >= 1000:
            entered = entered or phase == 1000
            continue
        kind = table[phase % 100]["kind"]
        if kind == cst.CSE_ALLOC and phase >= 100 and entered:
            print(f"C0 {rec[9]:#x}: {rec[9] // 32} chunks before the first CSE slot")
            break
        if kind != cst.SYMBOL_ALLOC:
            continue
        if phase < 100:
            pending = [r for r in rec[29:39] if r]
            continue
        ident = rec[9]
        if ident > top:
            top = ident
            if ident % 32 == 0:
                frames = [name(r) for r in pending]
                opener = next((f for f in frames if f not in WRAPPERS), "?")
                openers.append(opener)
                print(f"  chunk {ident:#6x}  {opener:28} {' '.join(frames[:6])}")
    tally: dict[str, int] = {}
    for opener in openers:
        tally[opener] = tally.get(opener, 0) + 1
    print("  openers: " + ", ".join(f"{k} {v}" for k, v in sorted(tally.items(), key=lambda kv: -kv[1])))


def phantom_match(out: Path, config, manifest, spec: str) -> str:
    phantom = [tuple(int(x, 0) for x in item.split(":")) for item in spec.split(",")]
    table = cst.hooks()
    profile = ao.c2.load_profile()
    profile = dict(profile, hooks=[{k: h[k] for k in ("site", "target", "return")} for h in table])
    work = out / ("window-" + "-".join(f"{at}_{count}" for at, count in phantom))
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    (work / "replay_settings.h").write_bytes((out / "observed/replay_settings.h").read_bytes())
    (work / "observer.c").write_text(cst.observer(profile, ao.c2.observer_source, [h["kind"] for h in table], phantom))
    replay = ao.c2.replay
    replay.compile_driver(work, "observer.c", "observer.obj")
    replay.link(work, "observer.exe", "observer.obj")
    replay.run([replay.WIBO, "observer.exe"], work)
    match = m.run_match(
        obj_path=work / "replay.obj",
        function_name=config.function,
        end_va=config.end_va,
        symbol_name=config.symbol,
        manifest=manifest,
        image_path=m.REPO_ROOT / manifest.primary_target,
    )
    shutil.rmtree(work)
    text = f"{spec:28} {match.ratio:9.4%}"
    if match.ratio == 1.0:
        rows = ao.sib_differences(match)
        swaps = [f"+{d['offset']:#x}" for d in rows if d["swapped"]]
        other = len(rows) - len(swaps)
        text += "  exact" if not rows else f"  swaps {' '.join(swaps)}" + (f" other {other}" if other else "")
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", help="snail scratch name or directory")
    parser.add_argument("specs", nargs="*", help="phantom specs: K:M, K:A..B[/step], joined by commas")
    parser.add_argument("--source", type=Path, help="overlay source replacing scratch.cpp")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--chunks", action="store_true", help="list the symbol chunks that make up C0")
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    scratch = Path(args.scratch)
    if not scratch.is_dir():
        scratch = m.DEFAULT_MATCH_ROOT / "scratches" / args.scratch
    if args.chunks:
        if cst.RECORDER.count(CHAIN_ANCHOR) != 1:
            raise ValueError("Unexpected cse_slot_trace recorder near the allocation capture")
        cst.RECORDER = cst.RECORDER.replace(CHAIN_ANCHOR, CHAIN_ANCHOR + CHAIN_CAPTURE)
    work = cst.rot.prepare(scratch, args.source, args.out.parent / (args.out.name + "-input"))
    result, _, table, records = cst.run_observer(work, args.out)
    slots = cst.decode(table, records)
    print(f"metrics: {result['metrics']}")
    print(f"C0 (first CSE slot): {slots[0]['id']:#x}, {len(slots)} CSE slots")
    if args.chunks:
        chunk_report(table, records)
    specs = expand(args.specs)
    if not specs:
        return
    config = m.load_scratch_config(work)
    manifest = m.load_function_symbol_manifest(m.DEFAULT_FUNCTION_SYMBOL_MANIFEST_PATH)
    with ao.c2.compiler_environment(), ThreadPoolExecutor(args.jobs) as pool:
        for text in pool.map(lambda spec: phantom_match(args.out, config, manifest, spec), specs):
            print(text, flush=True)


if __name__ == "__main__":
    main()
