"""Show why two VC6 C2 memory operands are ordered by the scheduler (diagnostic only; no match credit).

Runs `sched_trace.py`'s preserving observer (`crimson match c2-trace`: whole COFF, replay and
missing-stream checks unchanged) and additionally records, for every kind-6 memory operand of every
scheduling window, its alias class (operand +0x1c, the id `operands_may_alias` 0x10702771 compares
with `alias_classes_intersect` 0x107026f4) and, per function, the field-class budget:

    g_alias_class_count 0x1079d670   base alias classes (the field collector may add 0x400 - count)
    g_alias_class_max   0x107adfd8   count + field classes - 1
    0x107adfe0                        field-range refinement flag used by operands_may_alias

For each window touching `--lines` it prints the tuples with the alias class of each memory operand
and the memory dependence edges (0x20 store->load, 0x40 load->store, 0x80 store->store) that the
scheduler built between them. See tools/match/c2/compiler/small-aggregate-copies.md.

    uv run python scripts/c2/alias_trace.py <scratch-dir> --out <new-dir> --lines 270-290
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import sched_trace as st

ALIAS_COUNT, ALIAS_MAX, FIELD_FLAG, FIELD_TEST = 0x9D670, 0xADFD8, 0xADFE0, 0xADFF0
SYMBOL_SETS, SECONDARY = 0x9D678, 0x9D6BC  # g_alias_class_symbol_sets, g_alias_secondary_records
MEMORY_EDGES = {0x20: "st>ld", 0x40: "ld>st", 0x80: "st>st"}
SET_WORDS = 120

KIND6 = "            unsigned long b=*(unsigned long *)(op+0x28);\n"
WINDOW = "        row[0]=1; row[2]=t; row[3]=end; sched_row(row);\n"
OPERANDS = "static void sched_operands("

# One type-8 row per kind-6 operand, written before its tuple row: class, field record, parent symbol set.
ALIAS_ROW = f"""
static void alias_row(unsigned long op) {{
    unsigned long row[ROW_WORDS], j, cls, parent, count, *rec, *set, n;
    for(j=0;j<ROW_WORDS;++j)row[j]=0;
    cls=*(unsigned long *)(op+0x1c); parent=cls;
    count=*(unsigned long *)(sched_base+{ALIAS_COUNT});
    row[0]=8; row[1]=sched_ordinal; row[2]=op; row[3]=cls;
    if(cls>=count && *(unsigned long *)(sched_base+{SECONDARY})){{
        rec=(unsigned long *)(*(unsigned long *)(sched_base+{SECONDARY})+(cls-count)*12);
        parent=rec[0]; row[5]=rec[1]; row[6]=rec[2];
    }}
    row[4]=parent;
    set=*(unsigned long **)(*(unsigned long *)(sched_base+{SYMBOL_SETS})+parent*4);
    if(set && parent>1){{
        n=((set[2]&0xffffff)+31)>>5; if(n>{SET_WORDS})n={SET_WORDS};
        row[7]=set[2]&0xffffff;
        for(j=0;j<n;++j)row[8+j]=((unsigned long *)set[0])[j];
    }}
    sched_row(row);
}}
"""


def watch() -> str:
    source = st.WATCH
    if any(source.count(anchor) != 1 for anchor in (KIND6, WINDOW, OPERANDS)):
        raise ValueError("unexpected sched_trace observer template")
    source = source.replace(OPERANDS, ALIAS_ROW + OPERANDS)
    source = source.replace(KIND6, KIND6 + "            alias_row(op);\n")
    return source.replace(
        WINDOW,
        f"        row[4]=*(unsigned long *)(sched_base+{ALIAS_COUNT});"
        f" row[5]=*(unsigned long *)(sched_base+{ALIAS_MAX}); row[6]=*(unsigned long *)(sched_base+{FIELD_FLAG});"
        f" row[8]=*(unsigned long *)(sched_base+{FIELD_TEST});\n" + WINDOW,
    )


def members(words):
    return [i * 32 + b for i, w in enumerate(words) for b in range(32) if w >> b & 1]


def decode(data: bytes):
    """sched_trace.decode, plus the alias budget of each window and the alias record of each kind-6 operand."""
    rows = [st.struct.unpack_from(f"<{st.ROW_WORDS}I", data, i) for i in range(0, len(data), st.ROW_WORDS * 4)]
    plain = b"".join(st.struct.pack(f"<{st.ROW_WORDS}I", *w) for w in rows if w[0] != 8)
    functions = st.decode(plain)
    budgets: dict[int, list] = {}
    pending: dict[int, list] = {}
    records: dict[int, list] = {}
    for w in rows:
        if w[0] == 1:
            budgets.setdefault(w[1], []).append(
                {"alias_count": w[4], "alias_max": w[5], "field_flag": w[6], "field_test": w[8]},
            )
        elif w[0] == 8:
            pending.setdefault(w[1], []).append(
                {
                    "alias_class": w[3],
                    "parent": w[4],
                    "field_bit": w[5],
                    "overlap_mask": w[6],
                    "set_bits": w[7],
                    "members": members(w[8 : 8 + SET_WORDS]),
                },
            )
        elif w[0] in (2, 6):
            records.setdefault(w[1], []).append(pending.pop(w[1], []))
    for ordinal, fn in functions.items():
        queue = iter(records.get(ordinal, []))
        tuples = [t for win in fn["windows"] for t in win["tuples"]]
        # Rows 2 (window tuples) and 6 (float ops) interleave in the stream; st.decode keeps each kind in order.
        order = [w for w in rows if w[1] == ordinal and w[0] in (2, 6)]
        windows_iter, floats_iter = iter(tuples), iter(fn["float_ops"])
        for w in order:
            t = next(windows_iter) if w[0] == 2 else next(floats_iter)
            alias = iter(next(queue))
            for op in t["src"] + t["dst"]:
                if op["kind"] == 6:
                    op.update(next(alias))
        for win, budget in zip(fn["windows"], budgets.get(ordinal, []), strict=True):
            win["budget"] = budget
    return functions


def alias_text(op):
    if op["alias_class"] == op["parent"]:
        return f"a{op['alias_class']}"
    return f"a{op['alias_class']}=field(a{op['parent']} bit {op['field_bit']} overlaps {op['overlap_mask']:#x})"


def memory_text(t):
    return " ".join(
        f"{side}:{alias_text(op)}"
        for side, ops in (("ld", t["src"]), ("st", t["dst"]))
        for op in ops
        if op["kind"] == 6
    )


def report(fn, names, lines):
    out = []
    budget = fn["windows"][0]["budget"] if fn["windows"] else {}
    if budget:
        fields = budget["alias_max"] - budget["alias_count"] + 1
        out.append(
            f"alias classes: base {budget['alias_count']}, max {budget['alias_max']} "
            f"(field classes {fields}, budget {0x400 - budget['alias_count']}), "
            f"field flags {budget['field_flag']}/{budget['field_test']}",
        )
    parents: dict[int, list] = {}
    emitted = {e["tuple"]: i for i, e in enumerate(fn["emits"])}
    for index, win in enumerate(fn["windows"]):
        ts = win["tuples"]
        if lines and not any(lines[0] <= t["line"] <= lines[1] for t in ts if t["line"]):
            continue
        nodes = {n["node"]: n for n in win["nodes"]}
        pos = {t["ptr"]: i for i, t in enumerate(ts)}
        out.append(f"window {index}: {len(ts)} nodes, {'scheduled' if win['nodes'] else 'not scheduled'}")
        by_tuple = {n["tuple"]: n for n in win["nodes"]}
        for i, t in enumerate(ts):
            n = by_tuple.get(t["ptr"])
            meta = f"h {n['height']:3d} pri {n['priority']:7d} -> {emitted.get(t['ptr'], -1)}" if n else ""
            out.append(f"  {i:3d} L{t['line']:<4d} {meta:30s} {st.render(t, names):44s} {memory_text(t)}")
            for op in t["src"] + t["dst"]:
                if op["kind"] == 6:
                    parents[op["parent"]] = op["members"]
        for e in win["edges"]:
            kinds = [name for bit, name in MEMORY_EDGES.items() if e["kind"] & bit]
            a, b = nodes.get(e["from"]), nodes.get(e["to"])
            if kinds and a and b and a["tuple"] in pos and b["tuple"] in pos:
                out.append(f"    edge {pos[a['tuple']]:3d} -> {pos[b['tuple']]:3d} {'+'.join(kinds)} ({e['kind']:#x})")
    out += [f"class a{c}: symbol ids {m}" for c, m in sorted(parents.items())]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--function-ordinal", type=int, help="default: the function with the most windows")
    parser.add_argument("--lines", help="only windows touching C2 line labels A-B")
    args = parser.parse_args()
    st.WATCH = watch()
    manifest, data = st.run(args.scratch, args.out)
    functions = decode(data)
    ordinal = args.function_ordinal
    if ordinal is None:
        ordinal = max(functions, key=lambda k: len(functions[k]["windows"]))
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    text = report(functions[ordinal], st.mnemonics(), lines)
    (args.out / "alias.txt").write_text(text + "\n")
    (args.out / "alias.json").write_text(json.dumps(functions[ordinal]) + "\n")
    metrics = manifest["metrics"]
    print(text)
    print(f"ratio {metrics['ratio']:.4%} exact {metrics['exact']} body_byte_exact {metrics['body_byte_exact']}")


if __name__ == "__main__":
    main()
