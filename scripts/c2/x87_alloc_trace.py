"""Trace VC6 C2's x87 register allocator for one scratch (diagnostic only; no match credit).

`allocate_x87_live_ranges` 0x107645d8 decides which named float/double variables stay on the x87
stack (storage ST0) and which are left in memory, where the frame packer gives them a class-3 or
local home (possibly a dead parameter home). This tool hooks it through Crimson's preserving
observer (`crimson match c2-trace`); the whole COFF object must still be identical.

It prints, per function that has float candidates:

- the IL after depth tagging and call splits (float tuples, calls, branches, labels; `dN` is the
  expression depth after the tuple, `tNNN=lrK*` a candidate reference, `*` its last use);
- every candidate live range at the first prune with its priority, benefit, tie key and
  def/end points (ranges with benefit <= 0 are dropped to memory there);
- each `x87_range_fits_stack` (0x1076590f) verdict in queue order, with the LIFO check that failed;
- the IL after allocation, before `fold_x87_copy_sequences`.

See tools/match/c2/compiler/x87-spills.md.

    uv run python scripts/c2/x87_alloc_trace.py tools/match/scratches/ui_element_render \
        --out /private/tmp/x87-ui [--lines 40-60]
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sched_trace as st

from crimson import match_c2

# Call sites (RVA) in the pinned C2; the observer checks opcode and destination of each.
FUNCTION_ENTRY = st.FUNCTION_ENTRY  # globopt_run, one per function
EMIT_FUNCTION = st.EMIT_FUNCTION
ALLOC_ENTRY = {"site": 0x64617, "target": 0x649DA, "return": False}  # after call splits and depth tags, before scoring
PRUNE_FIRST = {"site": 0x6462E, "target": 0x6504D, "return": False}  # drop benefit <= 0, first pass
FITS = {"site": 0x646C6, "target": 0x6590F, "return": True}  # per queued range: 1 = assign ST0
PRUNE_SPLIT = {"site": 0x646B0, "target": 0x6504D, "return": False}  # after a split, re-scored queue
ALLOC_DONE = {"site": 0x64660, "target": 0x2FEF2, "return": False}  # allocator tail -> fold_x87_copy_sequences
# Conflict checks inside x87_range_fits_stack (entry args kept, logged with the result at return).
CHECKS = [
    {"site": 0x65B68, "target": 0x665D8, "return": True, "rule": "below-dies-inside"},
    {"site": 0x65BA7, "target": 0x665D8, "return": True, "rule": "below-ends-inside"},
    {"site": 0x7860E, "target": 0x665D8, "return": True, "rule": "born-inside-outlives"},
    {"site": 0x65AFF, "target": 0x65CC4, "return": True, "rule": "last-use-expression-defines"},
    {"site": 0x78675, "target": 0x78756, "return": True, "rule": "def-depth-mismatch"},
    {"site": 0x785A0, "target": 0x7999D, "return": True, "rule": "extend-end"},
]
HOOKS = [FUNCTION_ENTRY, EMIT_FUNCTION, ALLOC_ENTRY, PRUNE_FIRST, FITS, PRUNE_SPLIT, ALLOC_DONE] + [
    {k: v for k, v in c.items() if k != "rule"} for c in CHECKS
]
FIRST_CHECK = 7
LIST_MAX = 12

WATCH = r"""
static void xa_list(unsigned long *row, unsigned long at, unsigned long node) {
    unsigned long k, t;
    for(k=0;node && k<LIST_MAX;++k,node=*(unsigned long *)node){
        t=*(unsigned long *)(node+4);
        row[at+1+k*3]=t;
        if(t){row[at+2+k*3]=*(unsigned long *)(t+4); row[at+3+k*3]=*(unsigned short *)(t+0x10);}
    }
    row[at]=k;
}
static void xa_range(unsigned long type, unsigned long lr, unsigned long extra) {
    unsigned long row[ROW_WORDS], j, sym;
    for(j=0;j<ROW_WORDS;++j)row[j]=0;
    row[0]=type; row[1]=sched_ordinal; row[2]=lr;
    row[3]=*(unsigned long *)(lr+0x1c); row[4]=*(unsigned long *)(lr+0xc); row[5]=*(unsigned long *)(lr+0x3c);
    row[6]=*(unsigned long *)(lr+0x40); row[7]=*(unsigned char *)(lr+5); row[8]=*(unsigned long *)(lr+0x10);
    sym=*(unsigned long *)lr;
    if(sym){row[9]=*(unsigned long *)(sym+0x1c); row[10]=*(unsigned char *)(sym+4); row[11]=*(unsigned long *)(sym+0x20);}
    row[12]=extra; row[13]=*(unsigned long *)(lr+0x24);
    xa_list(row,16,*(unsigned long *)(lr+0x34));
    xa_list(row,16+1+LIST_MAX*3,*(unsigned long *)(lr+0x38));
    sched_row(row);
}
static void xa_il(unsigned long type, unsigned long fn) {
    unsigned long t, row[ROW_WORDS], j;
    for(j=0;j<ROW_WORDS;++j)row[j]=0;
    row[0]=type; row[1]=sched_ordinal; sched_row(row);
    for(t=*(unsigned long *)(**(unsigned long **)(fn+8)+0x1c);t;t=*(unsigned long *)t){
        if((*(unsigned short *)(t+0xa)&0xf000)==0x4000 || *(unsigned char *)(t+8)==0x1a || *(unsigned char *)(t+8)==0x11 || *(unsigned char *)(t+8)==0xe){
            for(j=0;j<ROW_WORDS;++j)row[j]=0;
            row[0]=13; row[1]=sched_ordinal; row[2]=*(unsigned char *)(t+0x12); row[3]=*(unsigned char *)(t+0x13);
            sched_row(row); sched_tuple(12,t);
        }
    }
}
static unsigned long xa_fits_lr, xa_arg1[16], xa_arg2[16];
static void xa_check(unsigned long hook, unsigned long result) {
    unsigned long row[ROW_WORDS], j, t, lr;
    for(j=0;j<ROW_WORDS;++j)row[j]=0;
    row[0]=30; row[1]=sched_ordinal; row[2]=hook; row[3]=result;
    /* 0x665d8(tuple, lr); 0x65cc4(lr, tuple); 0x78756(fn, lr); 0x7999d(lr, tuple, ...) */
    if(hook==FIRST_CHECK+3||hook==FIRST_CHECK+5){lr=xa_arg1[hook]; t=xa_arg2[hook];}
    else if(hook==FIRST_CHECK+4){lr=xa_arg2[hook]; t=0;}
    else {t=xa_arg1[hook]; lr=xa_arg2[hook];}
    row[4]=lr; row[5]=lr?*(unsigned long *)(lr+0x1c):0; row[6]=xa_fits_lr?*(unsigned long *)(xa_fits_lr+0x1c):0;
    if(t){row[7]=*(unsigned long *)(t+4); row[8]=*(unsigned short *)(t+0x10); row[9]=*(unsigned char *)(t+8);}
    sched_row(row);
}
static int sched_watch(unsigned long phase, unsigned long *regs) {
    unsigned long lr;
    if(phase==0){++sched_ordinal; return 0;}
    if(phase==1) return 1;
    if(phase==2){xa_il(10,regs[6]); return 1;}
    if(phase==3||phase==5){
        for(lr=regs[5];lr;lr=*(unsigned long *)(lr+0x14)) xa_range(phase==3?20:21,lr,0);
        return 1;
    }
    if(phase==4){xa_fits_lr=regs[5]; return 1;}
    if(phase==104){xa_range(22,xa_fits_lr,regs[7]); return 1;}
    if(phase==6){xa_il(11,regs[6]); return 1;}
    if(phase>=FIRST_CHECK && phase<100){xa_arg1[phase]=regs[6]; xa_arg2[phase]=regs[5]; return 1;}
    if(phase>=100+FIRST_CHECK){xa_check(phase-100,regs[7]); return 1;}
    return 1;
}
"""


def observer(profile, stock_source):
    base = st.observer(profile, stock_source)
    # Reuse sched_trace's row writer and tuple encoder; replace its hook dispatcher.
    start = base.index("static int sched_watch(")
    stop = base.index("\n}\n", start) + 3
    header = f"#define LIST_MAX {LIST_MAX}\n#define FIRST_CHECK {FIRST_CHECK}\n"
    return base[:start] + header + WATCH + base[stop:]


def run(scratch: Path, out: Path, c2=match_c2):
    stock_source = c2.observer_source
    profile = dict(c2.load_profile(), name="msvc6.5-c2-x87-alloc", hooks=HOOKS)
    with (
        patch.object(c2, "load_profile", return_value=profile),
        patch.object(c2, "observer_source", side_effect=lambda p: observer(p, stock_source)),
    ):
        manifest = c2.trace(scratch, out)
    return manifest, (out / "observed/sched.bin").read_bytes()


def points(w, at):
    return [(w[at + 2 + k * 3], w[at + 3 + k * 3], w[at + 1 + k * 3]) for k in range(w[at])]


def range_row(w):
    signed = [x - (1 << 32) if x >= 1 << 31 else x for x in w[:16]]
    return {
        "lr": w[2],
        "id": w[3],
        "priority": signed[4],
        "benefit": signed[5],
        "tie_key": w[6],
        "flags5": w[7],
        "st0": w[8] != 0,
        "sym_id": w[9],
        "sym_class": w[10],
        "size": w[11],
        "fits": w[12],
        "defs": points(w, 16),
        "ends": points(w, 16 + 1 + LIST_MAX * 3),
    }


def decode(data: bytes):
    functions: dict[int, dict] = {}
    size = st.ROW_WORDS * 4
    for i in range(0, len(data), size):
        w = struct.unpack_from(f"<{st.ROW_WORDS}I", data, i)
        fn = functions.setdefault(w[1], {"il": {}, "first": [], "split": [], "fits": [], "checks": []})
        if w[0] in (10, 11):
            fn["il"][w[0]] = []
            current = fn["il"][w[0]]
        elif w[0] == 13:
            depth = (w[2], w[3])
        elif w[0] == 12:
            current.append(st.tuple_row(w) | {"depth": depth})
        elif w[0] == 20:
            fn["first"].append(range_row(w))
        elif w[0] == 21:
            fn["split"].append(range_row(w))
        elif w[0] == 22:
            fn["fits"].append(range_row(w) | {"checks": fn["checks"]})
            fn["checks"] = []
        elif w[0] == 30:
            fn["checks"].append(
                {"rule": CHECKS[w[2] - FIRST_CHECK]["rule"], "result": w[3], "lr": w[5], "tuple": (w[7], w[8], w[9])},
            )
        else:
            raise ValueError(f"Unknown record {w[0]}")
    return {k: v for k, v in functions.items() if v["first"] or v["il"]}


def render_il(tuples, names, ranges, lines=None):
    out = []
    for t in tuples:
        if lines and t["line"] and not lines[0] <= t["line"] <= lines[1]:
            continue
        text = st.render(t, names)
        refs = []
        for o in t["src"] + t["dst"]:
            if o["kind"] == 1 and not o["register"] and o["value"] in ranges:
                refs.append(f"t{o['sym_id']}=lr{ranges[o['value']]}{'*' if o['flags11'] & 0x10 else ''}")
        tag = f"d{t['depth'][0]}"
        out.append(f"  L{t['line']:<4d} {tag:4s} {text}" + (f"   [{', '.join(refs)}]" if refs else ""))
    return out


def describe_range(r, names):
    def pts(items):
        return ", ".join(
            f"L{line}:{names[op] if op < len(names) else st.IL_NAMES.get(op, hex(op))}" for op, line, _ in items
        )

    return (
        f"lr{r['id']:<3d} var {r['sym_id']:#x} size {r['size']} pri {r['priority']:4d} benefit {r['benefit']:4d} "
        f"tie {r['tie_key']:#x} defs [{pts(r['defs'])}] ends [{pts(r['ends'])}]"
    )


def report(fn, names, lines=None):
    ranges = {r["lr"]: r["id"] for r in fn["first"] + fn["split"] + fn["fits"]}
    out = []
    if 10 in fn["il"]:
        out.append("IL after depth tagging and call splits (float tuples, calls, branches, labels):")
        out += render_il(fn["il"][10], names, ranges, lines)
    out.append("candidates at the first prune (queue order; benefit <= 0 -> memory):")
    out += ["  " + describe_range(r, names) for r in fn["first"]]
    if fn["split"]:
        out.append("queue after splitting (re-scored):")
        out += ["  " + describe_range(r, names) for r in fn["split"]]
    out.append("x87_range_fits_stack verdicts (1 = ST0):")
    for r in fn["fits"]:
        out.append(f"  {r['fits']} " + describe_range(r, names))
        for c in r["checks"]:
            if c["result"] or c["rule"] in ("extend-end", "def-depth-mismatch"):
                op, line, kind = c["tuple"]
                at = (
                    "block"
                    if kind == 0x19
                    else f"L{line}:{names[op] if op < len(names) else st.IL_NAMES.get(op, hex(op))}"
                )
                out.append(f"      {c['rule']} -> {c['result']:#x} (lr{c['lr']} at {at})")
    if 11 in fn["il"]:
        out.append("IL after allocation:")
        out += render_il(fn["il"][11], names, ranges, lines)
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--lines", help="only IL tuples on C2 line labels A-B")
    args = parser.parse_args()
    manifest, data = run(args.scratch, args.out)
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    names = st.mnemonics()
    text = "\n\n".join(f"function {k}\n" + report(v, names, lines) for k, v in decode(data).items())
    (args.out / "x87_alloc.txt").write_text(text + "\n")
    print(text)
    metrics = manifest["metrics"]
    print(f"ratio {metrics['ratio']:.4%} exact {metrics['exact']} body_byte_exact {metrics['body_byte_exact']}")


if __name__ == "__main__":
    main()
