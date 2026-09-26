"""Trace VC6 C2's per-function inline budget (P2/inline.c) on a scratch (diagnostic only; no match credit).

`inline_function_calls` 0x107180fd sets `g_inline_total_size` 0x1079f234 to the caller's own size estimate
(`fe_function+0x6d`) and calls `inline_expand_calls` 0x107181a8 with budget `clamp(2*size, 1000, 35000)`.
For each collected call site (0x10718676 loop) a callee of size `s = fsym+0x6d` is inlined when
`s <= remaining` or `s <= 0x28` (and the running total is at most 35000); a callee with `s > 0x28` then
spends `s` of the remaining budget (0x1071835a), and every expansion adds `s` to the running total
(0x1071879a). A refused `__inline` callee produces warning C4710 (0x10718281); the call stays a call.

Hooks (preserving observer from `crimson match c2-trace`):
- 0x10718134 -> inline_expand_calls (entry): caller size and budget;
- 0x107187ae -> read_function_il (entry, ecx = callee): an accepted expansion;
- 0x10718281 -> warning (entry, edi = callee): a refused `__inline` callee.

Each row prints the call-site line, callee, callee size, the remaining budget after the decision and
the running total, in the inliner's visiting order.

    uv run python scripts/c2/inline_budget_trace.py <scratch-dir> --out <new-dir> [--function NAME] [--all]
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from unittest.mock import patch

FUNCTION_ENTRY = {"site": 0x581EE, "target": 0x130CB, "return": False}
EMIT_FUNCTION = {"site": 0x585B1, "target": 0x3EBEA, "return": False}
TOP = {"site": 0x18134, "target": 0x181A8, "return": False}  # inline_expand_calls, top level
ACCEPT = {"site": 0x187AE, "target": 0x1BA73, "return": False}  # read_function_il(callee)
REFUSE = {"site": 0x18281, "target": 0x42BBE, "return": False}  # warning(4, C4710/C4714, name)
HOOKS = [FUNCTION_ENTRY, EMIT_FUNCTION, TOP, ACCEPT, REFUSE]
CUR_FUNC_SYM = 0xAC378
INLINE_TOTAL = 0x9F234
WORDS = 24

RECORDER = r"""
static HANDLE inline_file;
static const unsigned long hook_rva[] = {HOOK_RVAS};
static void copy_name(unsigned long *out, const char *text, unsigned long words)
{
    unsigned long j;
    char *dst = (char *)out;
    for (j = 0; j < words; ++j) out[j] = 0;
    for (j = 0; text && j + 1 < words * 4 && text[j]; ++j) dst[j] = text[j];
}
/* Row: 0 kind (1 top, 2 accept, 3 refuse), 1 line, 2 callee size, 3 remaining, 4 running total,
   5 budget or depth word, 6..13 callee name, 14..23 function name. */
static int inline_watch(unsigned long phase, unsigned long *registers)
{
    unsigned long rec[WORDS], entry = registers[3] + 4, loop, fsym, fe, tuple, j;
    unsigned char *base;
    DWORD written;
    if (phase < 2) return 0;
    if (phase >= 100) return 1;
    base = (unsigned char *)targets[phase] - hook_rva[phase];
    for (j = 0; j < WORDS; ++j) rec[j] = 0;
    rec[0] = phase - 1;
    rec[4] = *(unsigned long *)(base + INLINE_TOTAL);
    if (phase == 2) {
        rec[5] = *(unsigned long *)(entry + 4);
    } else {
        loop = entry + 4 + (phase == 4 ? 0xc : 0);
        fsym = phase == 3 ? registers[6] : registers[0];
        tuple = *(unsigned long *)(*(unsigned long *)(loop + 0x14) + 4);
        rec[1] = *(unsigned short *)(tuple + 0x10);
        rec[2] = (unsigned long)(long)*(short *)(fsym + 0x6d);
        rec[3] = *(unsigned long *)(loop + 0x48);
        rec[5] = *(unsigned long *)(loop + 0x34);
        copy_name(rec + 6, *(char **)(fsym + 0x18), 8);
    }
    fe = *(unsigned long *)(base + CUR_FUNC_SYM);
    copy_name(rec + 14, fe ? *(char **)(fe + 0x18) : 0, 10);
    if (!WriteFile(inline_file, rec, sizeof(rec), &written, 0) || written != sizeof(rec)) ExitProcess(71);
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
        "INLINE_TOTAL": INLINE_TOTAL,
        "HOOK_RVAS": ",".join(str(h["target"]) for h in HOOKS),
    }
    header = "".join(f"#define {k} {v}\n" for k, v in defines.items())
    source = source.replace(anchors[3], header + RECORDER + anchors[3])
    source = source.replace(anchors[0], anchors[0] + "    if (inline_watch(phase, registers)) return;\n")
    source = source.replace(
        anchors[1],
        '    inline_file = CreateFileA("inline.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        "    if (inline_file == INVALID_HANDLE_VALUE) ExitProcess(72);\n" + anchors[1],
    )
    return source.replace(anchors[2], "    CloseHandle(inline_file);\n" + anchors[2])


def run(scratch: Path, out: Path):
    from crimson import match_c2 as c2

    stock_source = c2.observer_source
    profile = dict(c2.load_profile(), name="msvc6.5-c2-inline-budget", hooks=HOOKS)
    with (
        patch.object(c2, "load_profile", return_value=profile),
        patch.object(c2, "observer_source", side_effect=lambda p: observer(p, stock_source)),
    ):
        manifest = c2.trace(scratch, out)
    return manifest, (out / "observed/inline.bin").read_bytes()


def text(words):
    return struct.pack(f"<{len(words)}I", *words).split(b"\0", 1)[0].decode("latin-1")


def signed(value):
    return value - (1 << 32) if value & 0x80000000 else value


def decode(data):
    rows = []
    for at in range(0, len(data), WORDS * 4):
        w = struct.unpack_from(f"<{WORDS}I", data, at)
        rows.append(
            {
                "kind": {1: "top", 2: "inline", 3: "refuse"}[w[0]],
                "line": w[1],
                "size": signed(w[2]),
                "remaining": signed(w[3]),
                "total": signed(w[4]),
                "word": signed(w[5]),
                "callee": text(w[6:14]),
                "function": text(w[14:24]),
            },
        )
    return rows


def summary(rows):
    """Per function: own size, budget, expansions, budget spent, refusals."""
    out = {}
    for r in rows:
        f = out.setdefault(r["function"], {"size": None, "budget": None, "inline": 0, "refuse": [], "rows": []})
        f["rows"].append(r)
        if r["kind"] == "top":
            f["size"], f["budget"] = r["total"], r["word"]
        elif r["kind"] == "inline":
            f["inline"] += 1
        else:
            f["refuse"].append(r["callee"])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--function", help="substring of the compiled function to list (default: all)")
    parser.add_argument("--all", action="store_true", help="list every expansion, not only the budget spenders")
    args = parser.parse_args()
    manifest, data = run(args.scratch, args.out)
    print(f"ratio {manifest['metrics']['ratio']:.4%}")
    for name, f in summary(decode(data)).items():
        if args.function and args.function not in name:
            continue
        last = f["rows"][-1]
        print(
            f"{name}: own size {f['size']}, budget {f['budget']}, {f['inline']} expansions, "
            f"final total {last['total']}, remaining {last['remaining'] if last['kind'] != 'top' else f['budget']}, "
            f"refused {len(f['refuse'])}: {', '.join(f['refuse'])}",
        )
        for r in f["rows"]:
            if r["kind"] == "top" or (not args.all and r["kind"] == "inline" and r["size"] <= 0x28):
                continue
            print(
                f"  {r['kind']:6} line {r['line']:<5} {r['callee']:<32} size {r['size']:<5} "
                f"remaining {r['remaining']:<6} total {r['total']}",
            )


if __name__ == "__main__":
    main()
