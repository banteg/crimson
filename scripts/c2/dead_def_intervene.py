"""Diagnostic intervention: leave a named pointer's definition dead at `build_live_ranges` (no match credit).

At entry to `build_live_ranges` 0x10726d75 (call site 0x1075838c) the observer finds the first tuple
`NAME = temp` (a kind-1 destination whose front-end name is NAME and a class-3 temp source) and points
every later read of NAME, including the base and index of memory operands, at that temp. NAME's
definition is then dead, so `insert_upward_exposed_reloads` hands it to `demote_unused_candidate_def`
0x107318e5 (call site 0x1072eb81), which turns it into a memory store of the temp. The temp keeps a
value use, so `forward_substitute_single_def_ranges` 0x107306c1 excludes it in phase 1.

`--rebase-lea OLD:SYMBOL:NEW` also rewrites every `t = lea [temp + OLD]` into `t = lea [SYMBOL + NEW]`
(for example `-8:_entry:4` moves a field base from the temp to the entry cursor).

Everything else is `const_trace.py`: block-end demotions, constant-candidate savings and the queue.
The whole COFF object changes, so the preserving harness stops with "Observation changed the whole
COFF object"; the observed object is `<out>/observed/replay.obj` and is scored here directly.

    uv run python scripts/c2/dead_def_intervene.py <scratch-dir> --out <new-dir> [--name _template_id]
        [--rebase-lea -8:_entry:4]

The rewrite needs a temp that is already live across blocks; a block-local temp crashes C2.
See tools/match/c2/compiler/qst-dead-store.md.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import const_trace as ct

from crimson import match as m

REWRITE = r"""
static int is_named(unsigned long y, const char *want)
{
    unsigned long fe, name, k;
    if (!y) return 0;
    fe = W(y, 0);
    if (!fe || *(unsigned char *)(fe + 4) != 1) return 0;
    name = W(fe, 0x18);
    if (!name) return 0;
    for (k = 0; want[k]; ++k) if (*(char *)(name + k) != want[k]) return 0;
    return *(char *)(name + k) == 0;
}
static unsigned long rw_from, rw_to, rw_count;
static void rw_operand(unsigned long p, int depth)
{
    unsigned long kind;
    if (!p || depth > 4) return;
    kind = *(unsigned char *)(p + 8);
    if (kind == 1 && W(p, 0x14) == rw_from) { *(unsigned long *)(p + 0x14) = rw_to; ++rw_count; }
    if (kind == 5 || kind == 6) { rw_operand(W(p, 0x28), depth + 1); rw_operand(W(p, 0x2c), depth + 1); }
}
static int real(unsigned long n) { return *(unsigned char *)(n + 8) != 0x19 && (*(unsigned char *)(n + 9) & 1); }
static void rewrite(void)
{
    unsigned long first = W(W(W(saved_function, 8), 0), 0x1c), node, def = 0, p, d, sop;
    rw_from = rw_to = rw_count = 0;
    for (node = first; node; node = W(node, 0)) {
        if (!real(node)) continue;
        if (!def) {
            d = W(node, 0x1c); sop = W(node, 0x18);
            if (d && *(unsigned char *)(d + 8) == 1 && is_named(W(d, 0x14), REWRITE_NAME)
                && sop && *(unsigned char *)(sop + 8) == 1 && *(unsigned char *)(W(sop, 0x14) + 4) == 3) {
                def = node; rw_from = W(d, 0x14); rw_to = W(sop, 0x14);
                s("REWRITE def "); tuple(node);
            }
            continue;
        }
        for (p = W(node, 0x18); p; p = W(p, 0)) rw_operand(p, 0);
        for (p = W(node, 0x1c); p; p = W(p, 0)) if (*(unsigned char *)(p + 8) != 1) rw_operand(p, 0);
    }
    s("REWRITE count="); dec(rw_count); s("\n");
#ifdef REBASE_SYMBOL
    {
        unsigned long target = 0, m, q;
        for (node = first; node; node = W(node, 0)) {
            if (!real(node)) continue;
            for (q = W(node, 0x18); q; q = W(q, 0))
                if (*(unsigned char *)(q + 8) == 1 && is_named(W(q, 0x14), REBASE_SYMBOL)) target = W(q, 0x14);
        }
        for (node = first; node && target && rw_to; node = W(node, 0)) {
            if (!real(node) || (W(node, 4) & 0xffff) != 0x12) continue;
            m = W(node, 0x18);
            if (!m || *(unsigned char *)(m + 8) != 5 || !W(m, 0x28) || W(W(m, 0x28), 0x14) != rw_to) continue;
            if ((long)W(m, 0x24) != REBASE_OLD) continue;
            *(unsigned long *)(W(m, 0x28) + 0x14) = target;
            *(long *)(m + 0x24) = REBASE_NEW;
            for (q = W(m, 0); q; q = W(q, 0))
                if (*(unsigned char *)(q + 8) == 1 && W(q, 0x14) == rw_to) *(unsigned long *)(q + 0x14) = target;
            s("REBASE "); tuple(node);
        }
    }
#endif
    flush();
}
"""


def install(name: str, rebase: str | None) -> None:
    """Patch const_trace's observer: one extra hook (mode 20) that performs the rewrite."""
    ct.HOOKS = (*ct.HOOKS, (0x1075838C, 0x10726D75, "build_live_ranges_rewrite", False, 20))
    defines = f'#define REWRITE_NAME "{name}"\n'
    if rebase:
        old, symbol, new = rebase.split(":")
        defines += (
            f'#define REBASE_SYMBOL "{symbol}"\n#define REBASE_OLD ({int(old)})\n#define REBASE_NEW ({int(new)})\n'
        )
    observer = ct.OBSERVER.replace("/* Live range: id, symbol", REWRITE + "\n/* Live range: id, symbol")
    observer = observer.replace(
        "        if (mode == 15) {",
        "        if (mode == 20) { rewrite(); return; }\n        if (mode == 15) {",
    )
    ct.OBSERVER = observer.replace("static HANDLE trace_file;", defines + "static HANDLE trace_file;")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", default="_template_id", help="front-end name of the pointer local")
    parser.add_argument("--rebase-lea", help="OLD:SYMBOL:NEW, rebuild `lea [temp+OLD]` as `lea [SYMBOL+NEW]`")
    args = parser.parse_args()
    install(args.name, args.rebase_lea)
    try:
        ct.trace(args.scratch, args.out)
        print("warning: the object did not change (no rewrite happened?)")
    except ValueError as error:
        if "Observation changed" not in str(error):
            raise
    phases = args.out / "observed" / "phases.bin"
    lines = phases.read_bytes().decode("latin-1").splitlines()[1:]
    for line in lines:
        if line.startswith(("REWRITE", "REBASE")):
            print(line)
    print("\n".join(line for line in ct.report(lines) if "DEMOTE" in line and "c4z4'" in line))
    obj = args.out / "observed" / "replay.obj"
    if not obj.exists() or not obj.stat().st_size:
        sys.exit("no observed object (C2 crashed?)")
    config = m.load_scratch_config(args.scratch.resolve())
    image, functions, metadata = m._paths_for_image(config.image)
    result = m.run_match(
        obj_path=obj,
        function=config.function,
        image_path=image,
        functions_path=functions,
        metadata_path=metadata,
        symbol_name=config.symbol,
        object_extent=config.archive_extent,
        object_end_symbol=config.archive_end_symbol,
        object_size=config.archive_size,
        end_va=config.end_va,
        reference_aliases=config.reference_aliases,
    )
    print(f"observed object: ratio {result.ratio:.4%}, {len(result.candidate_lines)}/{len(result.target_lines)} insns")
    diff = difflib.unified_diff(result.target_lines, result.candidate_lines, "target", "observed", n=0, lineterm="")
    print("\n".join(line for line in diff if not line.startswith("@@")))


if __name__ == "__main__":
    main()
