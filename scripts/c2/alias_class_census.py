"""Census of where a function's symbol-level alias classes come from (diagnostic only; no match credit).

`compute_alias_classes` 0x10718eaf starts `g_alias_class_count` 0x1079d670 at
`count_tuples_and_scan_calls(first tuple) + 3` (0x10718ef9). That count is 1 plus the number of marker
tuples with type 0x16, opcode 0x1b4 and a payload at +0x14: one per lexical scope (a block or an inlined
body) that still holds a symbol. `assign_symbol_alias_classes` 0x1071921c then numbers every root symbol
(locals, surviving inline parameters and locals, compiler temporaries, referenced globals). Pointer roots
are numbered after that, and a root that would get id >= 0x400 gets class 1
(see unfolded-field-pointers.md).

Hooks (preserving observer from `crimson match c2-trace`):
- 0x10718eed -> count_tuples_and_scan_calls (entry, ecx = first tuple): tuples, real tuples, markers;
- 0x10718f1f -> assign_symbol_alias_classes (return): every symbol that received a class.

    uv run python scripts/c2/alias_class_census.py <scratch-dir> --out <new-dir> [--function NAME] [--list]

Prints, per compiled function: scope markers, the first symbol class, symbol classes by category
(named locals, unnamed inline/compiler temporaries, globals) and the first pointer-root class
(= symbols + markers + 3). The budget margin is 0x400 minus that value.
"""

from __future__ import annotations

import argparse
import collections
import struct
from pathlib import Path
from unittest.mock import patch

FUNCTION_ENTRY = {"site": 0x581EE, "target": 0x130CB, "return": False}
EMIT_FUNCTION = {"site": 0x585B1, "target": 0x3EBEA, "return": False}
COUNT = {"site": 0x18EED, "target": 0x190B8, "return": False}  # count_tuples_and_scan_calls(ecx = first)
SYMBOLS = {"site": 0x18F1F, "target": 0x1921C, "return": True}  # assign_symbol_alias_classes
HOOKS = [FUNCTION_ENTRY, EMIT_FUNCTION, COUNT, SYMBOLS]
CUR_FUNC_SYM = 0xAC378
SYMBOL_CHUNKS = 0x9BC50
ALIAS_CLASS_COUNT = 0x9D670
BUDGET = 0x400
WORDS = 16

RECORDER = r"""
static HANDLE census_file;
static const unsigned long census_rva[] = {HOOK_RVAS};
static void census_row(unsigned long *rec, unsigned long symbol)
{
    unsigned long fe = symbol ? *(unsigned long *)symbol : 0, j;
    char *name = fe ? *(char **)(fe + 0x18) : 0, *dst = (char *)(rec + 8);
    for (j = 0; name && j < 31 && name[j] > 32 && name[j] < 127; ++j) dst[j] = name[j];
}
/* Row: 0 kind (1 count, 2 symbol, 3 end), 1..3 counts or (symbol kind, flags5, id), 4 root, 5 class,
   6 class count, 8..15 name (function name for kind 1 and 3). */
static int census_watch(unsigned long phase, unsigned long *registers)
{
    unsigned long rec[WORDS], base, node, chunk, p, fe, j;
    DWORD written;
    if (phase < 2) return 0;
    if (phase < 100 && phase != 2) return 1;
    base = (unsigned long)targets[phase % 100] - census_rva[phase % 100];
    for (j = 0; j < WORDS; ++j) rec[j] = 0;
    if (phase == 2) {
        rec[0] = 1;
        for (node = registers[6]; node; node = *(unsigned long *)node) {
            rec[1]++;
            if (*(unsigned char *)(node + 9) & 1) rec[2]++;
            if (*(unsigned char *)(node + 8) == 0x16 && *(unsigned long *)(node + 4) == 0x1b4
                && *(unsigned long *)(node + 0x14)) rec[3]++;
        }
        fe = *(unsigned long *)(base + CUR_FUNC_SYM);
        if (fe && *(char **)(fe + 0x18)) {
            char *n = *(char **)(fe + 0x18), *d = (char *)(rec + 8);
            for (j = 0; j < 31 && n[j]; ++j) d[j] = n[j];
        }
        if (!WriteFile(census_file, rec, sizeof(rec), &written, 0)) ExitProcess(71);
        return 1;
    }
    for (chunk = *(unsigned long *)(base + SYMBOL_CHUNKS); chunk; chunk = *(unsigned long *)chunk) {
        for (p = chunk + 0xc; p < *(unsigned long *)(chunk + 4); p += 0x54) {
            fe = *(unsigned long *)p;
            if (!fe || !*(unsigned short *)(fe + 0x3e)) continue;
            for (j = 0; j < WORDS; ++j) rec[j] = 0;
            rec[0] = 2;
            rec[1] = *(unsigned char *)(p + 4);
            rec[2] = *(unsigned char *)(p + 5);
            rec[3] = *(unsigned long *)(p + 0x1c);
            rec[4] = *(unsigned long *)(p + 8) == p;
            rec[5] = *(unsigned short *)(fe + 0x3e);
            census_row(rec, p);
            if (!WriteFile(census_file, rec, sizeof(rec), &written, 0)) ExitProcess(71);
        }
    }
    for (j = 0; j < WORDS; ++j) rec[j] = 0;
    rec[0] = 3;
    rec[6] = *(unsigned long *)(base + ALIAS_CLASS_COUNT);
    if (!WriteFile(census_file, rec, sizeof(rec), &written, 0)) ExitProcess(71);
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
        "SYMBOL_CHUNKS": SYMBOL_CHUNKS,
        "ALIAS_CLASS_COUNT": ALIAS_CLASS_COUNT,
        "HOOK_RVAS": ",".join(str(h["target"]) for h in HOOKS),
    }
    header = "".join(f"#define {k} {v}\n" for k, v in defines.items())
    source = source.replace(anchors[3], header + RECORDER + anchors[3])
    source = source.replace(anchors[0], anchors[0] + "    if (census_watch(phase, registers)) return;\n")
    source = source.replace(
        anchors[1],
        '    census_file = CreateFileA("census.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        "    if (census_file == INVALID_HANDLE_VALUE) ExitProcess(72);\n" + anchors[1],
    )
    return source.replace(anchors[2], "    CloseHandle(census_file);\n" + anchors[2])


def run(scratch: Path, out: Path):
    from crimson import match_c2 as c2

    stock_source = c2.observer_source
    profile = dict(c2.load_profile(), name="msvc6.5-c2-alias-class-census", hooks=HOOKS)
    with (
        patch.object(c2, "load_profile", return_value=profile),
        patch.object(c2, "observer_source", side_effect=lambda p: observer(p, stock_source)),
    ):
        manifest = c2.trace(scratch, out)
    return manifest, (out / "observed/census.bin").read_bytes()


def text(words):
    return struct.pack(f"<{len(words)}I", *words).split(b"\0", 1)[0].decode("latin-1")


def decode(data):
    """Group rows per compiled function: {name, tuples, real, markers, symbols: [...], count}."""
    functions, current = [], None
    for at in range(0, len(data), WORDS * 4):
        w = struct.unpack_from(f"<{WORDS}I", data, at)
        if w[0] == 1:
            current = {"name": text(w[8:16]), "tuples": w[1], "real": w[2], "markers": w[3], "symbols": []}
            functions.append(current)
        elif w[0] == 2 and current is not None:
            current["symbols"].append(
                {"kind": w[1], "flags5": w[2], "id": w[3], "root": w[4], "class": w[5], "name": text(w[8:16])},
            )
        elif w[0] == 3 and current is not None:
            current["count"] = w[6]
    return functions


def category(symbol):
    if symbol["kind"] == 7:
        return "global"
    return "named local" if symbol["name"] else "unnamed temporary"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--function", help="substring of the compiled function (default: all)")
    parser.add_argument("--list", action="store_true", help="list every classed symbol")
    args = parser.parse_args()
    manifest, data = run(args.scratch, args.out)
    print(f"ratio {manifest['metrics']['ratio']:.4%}")
    for f in decode(data):
        if args.function and args.function not in f["name"]:
            continue
        cats = collections.Counter(category(s) for s in f["symbols"])
        first = min((s["class"] for s in f["symbols"]), default=None)
        pointer = f.get("count", 0)
        print(
            f"{f['name']}: {f['real']} real tuples, {f['markers']} scope markers, first symbol class {first}, "
            f"{len(f['symbols'])} symbol classes ({', '.join(f'{k} {v}' for k, v in sorted(cats.items()))}), "
            f"first pointer class {pointer}, margin to 0x400: {BUDGET - pointer}",
        )
        if args.list:
            for s in sorted(f["symbols"], key=lambda s: s["class"]):
                print(f"  class {s['class']:<5} kind {s['kind']} flags5 {s['flags5']:#x} id {s['id']:<6} {s['name']}")


if __name__ == "__main__":
    main()
