"""Census of VC6 C2 alias field records and the alias-class budget (diagnostic only; no match credit).

Runs the preserving observer (`crimson match c2-trace`: whole COFF, replay and missing-stream checks
unchanged) with two extra return hooks:

- `memory_operand_field_range` 0x1075d788 as called by the first walk of
  `alias_collect_field_classes` 0x1071afd0 (call at 0x1071b1df). Every kind-6 operand whose alias
  class is a pointer class (>= the symbol-class count) and whose +0x10 byte lacks 0x80 reaches it,
  in IL order, destination list before source list. The script replays the collector's per-class
  list (new ranges are prepended; a range is created only while the walk has seen fewer than 0x60
  entries) and labels each access new / reuse / capped / no-range.
- `alias_class_for_symbol_set` 0x1075d456 as called by `alias_class_for_memory_base` 0x1075d2d5
  (call at 0x1075d33d). Once `g_alias_class_count` reaches 0x400 it returns class 1 for every new
  root/points-to pair. The script lists the roots that were collapsed and the last roots that still
  got a class, which is the budget margin.

See tools/match/c2/compiler/alias-field-records.md.

    uv run python scripts/c2/field_records.py tools/match/scratches/<name> --out <new-dir> [--class 0x2d3]

A Snail scratch runs from the snail-mail checkout with its adapter (it compiles and measures with Snail):

    cd ../snail-mail && uv run python ../crimson/scripts/c2/field_records.py <scratch-dir> \
        --out <new-dir> --snail .
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

FUNCTION_ENTRY = {"site": 0x581EE, "target": 0x130CB, "return": False}
EMIT_FUNCTION = {"site": 0x585B1, "target": 0x3EBEA, "return": False}
FIELD_RANGE = {"site": 0x1B1DF, "target": 0x5D788, "return": True}  # memory_operand_field_range, first walk
CLASS_FOR_SET = {"site": 0x5D33D, "target": 0x5D456, "return": True}  # alias_class_for_symbol_set
HOOKS = [FUNCTION_ENTRY, EMIT_FUNCTION, FIELD_RANGE, CLASS_FOR_SET]
CUR_FUNC_SYM = 0xAC378
ALIAS_CLASS_COUNT = 0x9D670
LIST_WALK = 0x60  # alias_collect_field_classes: `cmp ecx, 0x60; jge skip` at 0x1071b20e
CLASS_BUDGET = 0x400  # alias_class_for_symbol_set: `cmp count, 0x400; jae -> class 1` at 0x1075d4dd
WORDS = 40

RECORDER = r"""
static HANDLE field_file;
static void field_name(unsigned long *out, unsigned long symbol)
{
    unsigned long fe, j;
    char *name, *dst = (char *)out;
    for (j = 0; j < 6; ++j) out[j] = 0;
    if (!symbol) return;
    fe = *(unsigned long *)symbol;
    if (!fe) return;
    name = *(char **)(fe + 0x18);
    if (!name) return;
    for (j = 0; j < 23 && name[j]; ++j) dst[j] = name[j];
}
/* Row: 0 kind (1 field range, 2 class), 1 C2 line, 2 opcode, 3 side, 4 class, 5 result, 6 start, 7 size,
   8 disp, 9 root symbol id, 10 def opcode, 11 def source kind, 12 def constant, 13 class count,
   14..19 base name, 20..25 def source name, 26..35 function name. */
static int field_watch(unsigned long phase, unsigned long *registers)
{
    unsigned long rec[WORDS], frame = registers[3] + 4, op, tuple, b, sym, def, src, fe, j, k;
    unsigned char *base;
    DWORD written;
    char *text;
    if (phase % 100 < 2) return 0;
    if (phase < 100) return 1;
    k = phase - 100;
    base = (unsigned char *)targets[k] - (k == 2 ? FIELD_RANGE_RVA : CLASS_FOR_SET_RVA);
    for (j = 0; j < WORDS; ++j) rec[j] = 0;
    rec[0] = k - 1;
    rec[5] = registers[7];
    rec[13] = *(unsigned long *)(base + ALIAS_CLASS_COUNT);
    if (k == 2) {
        op = registers[2];
        tuple = *(unsigned long *)(frame + 0x2c);
        rec[1] = *(unsigned short *)(tuple + 0x10);
        rec[2] = *(unsigned long *)(tuple + 4);
        rec[3] = *(unsigned long *)(frame + 0x10);
        rec[4] = *(unsigned long *)(op + 0x1c);
        rec[6] = *(unsigned long *)(frame + 0x20);
        rec[7] = *(unsigned long *)(frame + 0x1c);
        rec[8] = *(unsigned long *)(op + 0x24);
        b = *(unsigned long *)(op + 0x28);
        sym = b ? *(unsigned long *)(b + 0x14) : 0;
        rec[9] = sym ? *(unsigned long *)(sym + 0x1c) : 0;
        field_name(rec + 14, sym);
        def = sym ? *(unsigned long *)(sym + 0x14) : 0;
        rec[10] = def ? *(unsigned long *)(def + 4) : 0;
        src = def ? *(unsigned long *)(def + 0x18) : 0;
        if (src) {
            rec[11] = *(unsigned char *)(src + 8);
            if (rec[11] == 1 || rec[11] == 2) field_name(rec + 20, *(unsigned long *)(src + 0x14));
            if (*(unsigned long *)src) rec[12] = *(unsigned long *)(*(unsigned long *)src + 0x18);
        }
    } else {
        sym = registers[1]; /* alias_class_for_memory_base keeps the root symbol in esi */
        rec[9] = sym ? *(unsigned long *)(sym + 0x1c) : 0;
        field_name(rec + 14, sym);
    }
    fe = *(unsigned long *)(base + CUR_FUNC_SYM);
    text = fe ? *(char **)(fe + 0x18) : 0;
    for (j = 0; text && j < 39 && text[j]; ++j) ((char *)(rec + 26))[j] = text[j];
    if (!WriteFile(field_file, rec, sizeof(rec), &written, 0) || written != sizeof(rec)) ExitProcess(71);
    return 1;
}
"""


def observer(profile, stock_source):
    source = stock_source(profile)
    anchors = (
        "    unsigned long first, node, count = 0, record[742], op, side, j, k, at;\n",
        "    trace_file = CreateFileA(",
        "    CloseHandle(trace_file);",
        "static void __cdecl observe(",
    )
    for anchor in anchors:
        if source.count(anchor) != 1:
            raise ValueError(f"Unexpected observer template near {anchor!r}")
    defines = {
        "WORDS": WORDS,
        "CUR_FUNC_SYM": CUR_FUNC_SYM,
        "ALIAS_CLASS_COUNT": ALIAS_CLASS_COUNT,
        "FIELD_RANGE_RVA": FIELD_RANGE["target"],
        "CLASS_FOR_SET_RVA": CLASS_FOR_SET["target"],
    }
    header = "".join(f"#define {k} {v}\n" for k, v in defines.items())
    source = source.replace("if(op) ExitProcess(98);", "")  # truncate long operand chains
    source = source.replace(anchors[3], header + RECORDER + anchors[3])
    source = source.replace(anchors[0], anchors[0] + "    if (field_watch(phase, registers)) return;\n")
    source = source.replace(
        anchors[1],
        '    field_file = CreateFileA("fields.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        "    if (field_file == INVALID_HANDLE_VALUE) ExitProcess(72);\n" + anchors[1],
    )
    return source.replace(anchors[2], "    CloseHandle(field_file);\n" + anchors[2])


def run(scratch: Path, out: Path, snail: Path | None):
    if snail:
        sys.path.insert(0, str((snail / "tools/match/c2").resolve()))
        import trace as adapter  # Snail's adapter: Crimson's observer, Snail's compiler and metrics

        c2, runner = adapter.c2, lambda: adapter.trace(scratch, out)[0]
    else:
        from crimson import match_c2 as c2

        runner = lambda: c2.trace(scratch, out)
    stock_source = c2.observer_source
    profile = dict(c2.load_profile(), name="msvc6.5-c2-field-records", hooks=HOOKS)
    with (
        patch.object(c2, "load_profile", return_value=profile),
        patch.object(c2, "observer_source", side_effect=lambda p: observer(p, stock_source)),
    ):
        manifest = runner()
    return manifest, (out / "observed/fields.bin").read_bytes()


def cstring(words):
    return struct.pack(f"<{len(words)}I", *words).split(b"\0", 1)[0].decode("latin-1")


def signed(value):
    return value - (1 << 32) if value & 0x80000000 else value


def decode(data):
    rows = []
    for at in range(0, len(data), WORDS * 4):
        w = struct.unpack_from(f"<{WORDS}I", data, at)
        rows.append(
            {
                "kind": "range" if w[0] == 1 else "class",
                "label": w[1],
                "opcode": w[2],
                "side": "dst" if w[3] == 0 else "src",
                "class": w[4],
                "result": w[5],
                "start": signed(w[6]),
                "size": w[7],
                "disp": signed(w[8]),
                "root_id": w[9],
                "def_opcode": w[10],
                "def_source_kind": w[11],
                "def_constant": signed(w[12]),
                "class_count": w[13],
                "base": cstring(w[14:20]),
                "def_source": cstring(w[20:26]),
                "function": cstring(w[26:36]),
            },
        )
    return rows


def replay_walk(rows):
    """alias_collect_field_classes, first walk: per class, prepend new (start, size); cap the walk at 0x60."""
    lists, written = {}, set()
    for row in rows:
        if not row["result"]:
            row["outcome"] = "no-range"
            continue
        records = lists.setdefault(row["class"], [])
        key = (row["start"], row["size"])
        position = records.index(key) if key in records else len(records)
        if position >= LIST_WALK:
            row["outcome"] = "capped"
            continue
        row["outcome"] = "reuse" if position < len(records) else "new"
        if row["outcome"] == "new":
            records.insert(0, key)
        if row["side"] == "dst":
            written.add(row["class"])  # bitset_set only on the destination pass (0x1071b24b)
    return lists, written


def root_text(row):
    if row["def_opcode"] in (0x16D, 0x16E):
        sign = "+" if row["def_opcode"] == 0x16D else "-"
        return f"{row['def_source'] or '?'}{sign}{row['def_constant']:#x}"
    return row["base"] or f"sym{row['root_id']:#x}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--snail", type=Path, help="snail-mail checkout: trace a Snail scratch with its adapter")
    parser.add_argument("--function", help="substring of the function symbol (default: the most field ranges)")
    parser.add_argument(
        "--class",
        dest="klass",
        type=lambda v: int(v, 0),
        help="list this class (default: most records)",
    )
    parser.add_argument("--all", action="store_true", help="also list reused and no-range accesses")
    parser.add_argument("--line-offset", type=int, default=0, help="added to C2 line labels when printing")
    parser.add_argument("--json", action="store_true", help="write fields.json next to the trace")
    args = parser.parse_args()
    manifest, data = run(args.scratch, args.out, args.snail)
    rows = decode(data)
    functions = {r["function"] for r in rows}
    name = next((f for f in functions if args.function and args.function in f), None) or max(
        functions,
        key=lambda f: sum(r["function"] == f and r["kind"] == "range" for r in rows),
    )
    rows = [r for r in rows if r["function"] == name]
    ranges = [r for r in rows if r["kind"] == "range"]
    classes = [r for r in rows if r["kind"] == "class"]
    lists, written = replay_walk(ranges)
    if args.json:
        (args.out / "fields.json").write_text(json.dumps(rows) + "\n")
    metrics = manifest["metrics"]
    print(f"function {name}: ratio {metrics['ratio']:.4%}")
    tally = {}
    for r in ranges:
        tally.setdefault(r["class"], {}).setdefault(r["outcome"], 0)
        tally[r["class"]][r["outcome"]] += 1
    print("field records per class (new = records created; capped = new ranges refused by the 0x60 walk):")
    for klass, counts in sorted(tally.items(), key=lambda x: -x[1].get("new", 0))[:6]:
        kept = "kept" if klass in written else "dropped: no destination access"
        print(f"  class {klass:#x}: {counts} ({kept})")
    klass = args.klass if args.klass is not None else max(lists, key=lambda k: len(lists[k]))
    ordinal = 0
    print(f"class {klass:#x} in IL order (#n = n-th record; ids are assigned newest first, bit = min(age, 31)):")
    for r in ranges:
        if r["class"] != klass or (r["outcome"] not in ("new", "capped") and not args.all):
            continue
        ordinal += r["outcome"] == "new"
        tag = f"#{ordinal}" if r["outcome"] == "new" else r["outcome"]
        print(
            f"  {tag:8} L{r['label'] + args.line_offset:<5} {r['side']} op{r['opcode']:#05x} "
            f"[{root_text(r)}{r['disp']:+#x}] range ({r['start']:#x}, {r['size']})",
        )
    final = max((r["class_count"] for r in rows), default=0)
    collapsed = [r for r in classes if r["result"] == 1]
    print(
        f"alias classes: count {final:#x}, budget {CLASS_BUDGET:#x}; {len(collapsed)} root lookups collapsed to class 1",
    )
    roots = {}
    for r in classes:
        roots.setdefault((r["root_id"], r["base"]), []).append(r["result"])
    for (root, base), results in roots.items():
        if max(results) >= CLASS_BUDGET - 0x10 or 1 in results:
            ids = ", ".join(sorted({f"{x:#x}" for x in results}))
            print(f"  root {base or '?'} (sym {root:#x}): classes {ids} ({len(results)} lookups)")


if __name__ == "__main__":
    main()
