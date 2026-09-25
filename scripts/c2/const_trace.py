"""Trace VC6 C2 constant register candidates (class 13) for one scratch, without changing its output.

`build_live_ranges` (0x10726d75) first runs `promote_immediates_to_candidates` (0x1072795a), which
asks `tuple_allows_constant_candidate` (0x10727e73) about every tuple with an integer immediate
source and replaces each allowed immediate with an operand of the per-value constant symbol
(`make_constant_candidate_operand`, 0x10727f41). `score_live_ranges` (0x10724b25) then credits
each use with `memory_operand_saving` (0x10725751) or `load_saving` (0x107254dc) and charges each
LOADCONST. This tool hooks those call sites (entry and return) plus the initial priority queue and
prints, per constant value: every promoted or refused tuple, every scored use with its saving and
block weight, and the benefit the range was queued with.

    uv run python scripts/c2/const_trace.py <scratch-dir> --out <new-dir> [--il]

It runs through the preserving `c2-trace` harness (whole-COFF, replay and missing-stream checks
unchanged). In a Snail checkout (`uv run python <this file>` from snail-mail) it uses Snail's
`tools/match/c2/trace.py` adapter, so Snail scratches, compilers and metrics are used. `--il` also
dumps the IL at the stock pass boundaries, entering `build_live_ranges` and the global colourer. Only the pinned msvc6.5 C2 is
supported (the profile hash is checked by the harness).
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

BASE = 0x10700000


def c2_module():
    """Crimson's preserving harness, or Snail's adapter of it when run inside snail-mail."""
    try:
        from snail import match as snail_match
    except ImportError:
        return importlib.import_module("crimson.match_c2")
    sys.path.insert(0, str(Path(snail_match.__file__).resolve().parents[2] / "tools/match/c2"))
    return importlib.import_module("trace").c2


# (call site VA, callee VA, name, return hook, mode). Modes: 3 dumps the IL at entry (with --il),
# 10 allow check, 11 promotion, 12 memory-operand saving, 13 load saving, 14 LOADCONST cost, 15 queue,
# 16 block-end demotion of a candidate whose last def or reload is unused and not live-out.
HOOKS = (
    (0x10727B93, 0x10727E73, "tuple_allows_constant_candidate", True, 10),
    (0x10727BA5, 0x10727F41, "make_constant_candidate_operand", True, 11),
    (0x107252D4, 0x10725751, "memory_operand_saving", True, 12),
    (0x10724DC6, 0x107254DC, "load_saving", True, 13),
    (0x10724F18, 0x107254DC, "loadconst_cost", True, 14),
    (0x10733607, 0x10731D21, "queue_initial", False, 15),
    (0x1072EB81, 0x107318E5, "demote_pending_at_block_end", False, 16),
)
IL_HOOKS = (
    (0x1075838C, 0x10726D75, "build_live_ranges", False, 3),
    (0x107583B2, 0x1072FB58, "global_color_registers", False, 3),
)

OBSERVER = r"""
#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file;
static unsigned long targets[HOOK_COUNT], returns[HOOK_COUNT], active[HOOK_COUNT], saved_function;
static unsigned long sv_tuple, sv_op, sv_sym, sv_lr, sv_weight, sv_benefit;
static char buf[65536];
static unsigned long used;

static void flush(void)
{
    DWORD written;
    if (used && (!WriteFile(trace_file, buf, used, &written, 0) || written != used)) ExitProcess(99);
    used = 0;
}
static void ch(char c) { if (used == sizeof(buf)) flush(); buf[used++] = c; }
static void s(const char *t) { while (*t) ch(*t++); }
static void hx(unsigned long v)
{
    char t[9]; int i;
    for (i = 7; i >= 0; --i) { t[i] = "0123456789abcdef"[v & 15]; v >>= 4; }
    t[8] = 0; i = 0;
    while (i < 7 && t[i] == '0') ++i;
    s(t + i);
}
static void dec(long v)
{
    char t[12]; int i = 11; unsigned long u;
    t[i] = 0;
    if (v < 0) { ch('-'); u = (unsigned long)(-v); } else u = (unsigned long)v;
    do { t[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    s(t + i);
}
static unsigned long W(unsigned long p, unsigned long o) { return *(unsigned long *)(p + o); }

/* Symbol: #id c<class> [^parent+offset] z<size> ['name], =value for a class-13 constant. */
static void sym(unsigned long y)
{
    unsigned long fe, name, k;
    if (!y) { s("nil"); return; }
    s("#"); dec(W(y, 0x1c));
    s("c"); dec(*(unsigned char *)(y + 4));
    if (*(unsigned char *)(y + 4) == 13 && W(y, 0x28) && *(unsigned char *)(W(y, 0x28) + 8) == 7) {
        s("="); dec((long)W(W(y, 0x28), 0x18));
        return;
    }
    if (W(y, 0x08) && W(y, 0x08) != y) { s("^"); dec(W(W(y, 0x08), 0x1c)); s("+"); dec(W(y, 0x24)); }
    s("z"); dec(W(y, 0x20));
    fe = W(y, 0);
    if (fe && *(unsigned char *)(fe + 4) == 1) {
        name = *(unsigned long *)(fe + 0x18);
        if (name) { s("'"); for (k = 0; k < 40 && *(char *)(name + k) > 32 && *(char *)(name + k) < 127; ++k) ch(*(char *)(name + k)); }
    }
}

static void operand(unsigned long p)
{
    unsigned long kind = *(unsigned char *)(p + 8);
    s("["); dec(kind); s(":"); hx(*(unsigned short *)(p + 10)); s(" ");
    if (kind >= 1 && kind <= 3) {
        sym(W(p, 0x14));
        if (kind == 1 && W(p, 0x18) && W(p, 0x18) != W(p, 0x14)) { s(" @"); sym(W(p, 0x18)); }
    } else if (kind == 7) {
        s("="); dec((long)W(p, 0x18));
    } else if (kind == 5 || kind == 6) {
        s("op"); hx(W(p, 4) & 0xffff);
        if (W(p, 0x20)) { s(" sym="); sym(W(p, 0x20)); }
        s(" disp="); dec((long)W(p, 0x24));
        if (W(p, 0x28)) { s(" base="); operand(W(p, 0x28)); }
        if (W(p, 0x2c)) { s(" idx="); operand(W(p, 0x2c)); }
    } else {
        s("w14="); hx(W(p, 0x14));
    }
    s("]");
}

static void chain(unsigned long p)
{
    unsigned long k = 0;
    while (p && k < 16) { operand(p); s(" "); p = W(p, 0); ++k; }
}

static void tuple(unsigned long node)
{
    s("T "); hx(node); s(" op="); hx(W(node, 4) & 0xffff); s(" ln="); dec(*(unsigned short *)(node + 0x10));
    if (*(unsigned char *)(node + 9) & 1) { s(" | "); chain(W(node, 0x1c)); s("<= "); chain(W(node, 0x18)); }
    s("\n");
}

static void dump_il(void)
{
    unsigned long node = W(W(W(saved_function, 8), 0), 0x1c);
    while (node) {
        if (*(unsigned char *)(node + 8) == 0x19) s("BLOCK\n");
        else if (*(unsigned char *)(node + 9) & 1) tuple(node);
        node = W(node, 0);
    }
}

/* Live range: id, symbol, benefit (+0x3c), priority (+0x0c). */
static void range(unsigned long lr)
{
    s("lr="); dec(W(lr, 0x1c)); s(" sym="); sym(W(lr, 0)); s(" benefit="); dec((long)W(lr, 0x3c));
    s(" prio="); dec((long)W(lr, 0x0c));
}

static void __cdecl observe(unsigned long phase, unsigned long *r)
{
    unsigned long index = phase >= 100 ? phase - 100 : phase, mode = modes[index];
    if (phase < 12) saved_function = r[6];
    if (mode == 0) return;
    if (mode == 3) {
        if (phase < 100) { s("IL "); s(names[index]); s("\n"); dump_il(); s("END\n"); flush(); }
        return;
    }
    if (phase < 100) {
        /* r[0..7] = edi esi ebp esp ebx edx ecx eax, r[8] = eflags, r[9] = return, r[10..] = caller stack. */
        if (mode == 10) sv_tuple = r[6];
        if (mode == 11) { sv_tuple = r[6]; sv_op = r[5]; }
        if (mode == 12) { sv_tuple = r[6]; sv_sym = r[5]; sv_lr = r[1]; sv_op = r[2]; sv_weight = r[19]; }
        if (mode == 13) { sv_sym = r[6]; sv_lr = r[1]; sv_op = r[2]; sv_tuple = r[15]; sv_weight = r[19]; }
        if (mode == 14) { sv_sym = r[6]; sv_lr = r[1]; sv_tuple = r[0]; sv_weight = r[19]; }
        if (mode == 12 || mode == 13 || mode == 14) sv_benefit = W(sv_lr, 0x3c);
        if (mode == 15) { s("QUEUE "); range(r[6]); s("\n"); flush(); }
        if (mode == 16) {
            /* edx = symbol; its candidate info (+0x30) records the pending def/reload tuple at +0x10. */
            unsigned long info = W(r[5], 0x30), last = info ? W(info, 0x10) : 0;
            s("DEMOTE "); sym(r[5]);
            if (last) { s(" "); tuple(last); } else s("\n");
            flush();
        }
        return;
    }
    if (mode == 10) {
        if (!r[7]) { s("REFUSE "); tuple(sv_tuple); }
    } else if (mode == 11) {
        s("PROMOTE "); sym(W(r[7], 0x14)); s(" index="); dec(W(W(W(r[7], 0x14), 0x30), 0)); s(" ");
        tuple(sv_tuple);
    } else if (*(unsigned char *)(sv_sym + 4) == 13) {
        s(mode == 12 ? "SAVE mem " : mode == 13 ? "SAVE load " : "COST loadconst ");
        sym(sv_sym); s(" result="); dec((long)r[7]); s(" weight="); dec((long)sv_weight);
        s(" before="); dec((long)sv_benefit); s(" "); range(sv_lr); s(" ");
        tuple(sv_tuple);
    }
    flush();
}
/* GENERATED_HOOKS */
void __stdcall start(void)
{
    HMODULE module;
    invoke_t invoke;
    protect_t protect;
    unsigned char *base, *site;
    unsigned long i;
    DWORD old;
    int result;
    if (!LoadLibraryA(pdb_path)) ExitProcess(90);
    module = LoadLibraryA(backend_path);
    if (!module) ExitProcess(91);
    invoke = (invoke_t)GetProcAddress(module, "_InvokeCompilerPass@12");
    if (!invoke) ExitProcess(92);
    base = (unsigned char *)invoke - INVOKE_RVA;
    protect = (protect_t)GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualProtect");
    if (!protect) ExitProcess(93);
    trace_file = CreateFileA("phases.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (trace_file == INVALID_HANDLE_VALUE) ExitProcess(94);
    s("C2CONSTTRACE\n"); flush();
    for (i = 0; i < HOOK_COUNT; ++i) {
        site = base + sites[i];
        targets[i] = (unsigned long)base + offsets[i];
        if (site[0] != 0xe8 || (unsigned long)(site + 5) + *(long *)(site + 1) != targets[i])
            ExitProcess(95);
        if (!protect(site, 5, PAGE_EXECUTE_READWRITE, &old)) ExitProcess(96);
        *(long *)(site + 1) = (long)hooks[i] - (long)site - 5;
    }
    result = invoke(sizeof(arguments) / sizeof(arguments[0]), arguments, 0);
    flush();
    CloseHandle(trace_file);
    ExitProcess(result);
}
"""


def profile_with_hooks(c2, il):
    profile = c2.load_profile()
    mode = 3 if il else 0  # --il dumps every stock pass boundary too
    hooks = [dict(h, mode=mode, name=f"pass@{h['target'] + BASE:#x}") for h in profile["hooks"][:12]]
    stock = {h["site"]: h for h in hooks}
    for site, target, name, ret, mode in HOOKS + (IL_HOOKS if il else ()):
        if site - BASE in stock:  # a stock pass boundary: dump there instead of patching the site twice
            stock[site - BASE].update(mode=mode, name=name)
        else:
            hooks.append({"site": site - BASE, "target": target - BASE, "return": ret, "mode": mode, "name": name})
    return {**profile, "name": profile["name"] + "-const-trace", "hooks": hooks}


def observer_source(stock, profile):
    """Reuse the harness's preserving call-site wrappers; replace only the observer body."""
    source = stock(profile)
    wrappers = source[source.index("__declspec(naked)") : source.index("void __stdcall start")]
    header = source[: source.index("#include")]
    tables = "static unsigned long modes[] = {" + ",".join(str(h["mode"]) for h in profile["hooks"]) + "};\n"
    tables += "static const char *names[] = {" + ",".join(f'"{h["name"]}"' for h in profile["hooks"]) + "};\n"
    body = OBSERVER.replace("/* GENERATED_HOOKS */", wrappers)
    return header + body.replace("static char buf[65536];", tables + "static char buf[65536];")


def decode(data, _profile):
    text = data.decode("latin-1")
    if not text.startswith("C2CONSTTRACE\n"):
        raise ValueError("Not a constant-candidate trace")
    lines = text.splitlines()[1:]
    if not lines:
        raise ValueError("Empty constant-candidate trace")
    return [{"line": line} for line in lines]


def trace(scratch: Path, out: Path, *, il: bool = False):
    c2 = c2_module()
    profile = profile_with_hooks(c2, il)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: profile
    c2.observer_source = lambda p: observer_source(stock[1], p)
    c2.decode_trace = decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


CONSTANT = re.compile(r"#\d+c13=(-?\d+)")
EVENT = re.compile(r"^(REFUSE|PROMOTE|SAVE mem|SAVE load|COST loadconst|QUEUE|DEMOTE) ")
LINE = re.compile(r" ln=(\d+)")
SCORE = re.compile(r"result=(-?\d+) weight=(\d+)")


def report(lines):
    """Per constant value: promotions, refusals, the first scoring pass and the queued benefit.

    Later rescoring of split pieces is only counted. Block-end demotions are listed for all symbols,
    since a local demoted there turns its immediate stores into memory stores that save 1.
    """
    first_queue = next((i for i, line in enumerate(lines) if line.startswith("QUEUE ")), len(lines))
    rows, later, demoted = defaultdict(list), defaultdict(int), []
    for i, line in enumerate(lines):
        m = EVENT.match(line)
        if not m:
            continue
        kind = m.group(1)
        if kind == "DEMOTE":
            demoted.append(line)
            continue
        if kind == "REFUSE":
            value = re.search(r"\[7:\w+ =(-?\d+)\]", line.split("<= ", 1)[-1])
            rows[int(value.group(1)) if value else None].append(line)
            continue
        c = CONSTANT.search(line)
        if not c:
            continue
        value = int(c.group(1))
        if kind in ("SAVE mem", "SAVE load", "COST loadconst") and i > first_queue:
            later[value] += 1
        elif kind != "QUEUE" or i >= first_queue:
            rows[value].append(line)
    out = []
    for value in sorted(rows, key=lambda v: (v is None, v)):
        out.append(f"== constant {value}")
        net = 0
        for row in rows[value]:
            kind = EVENT.match(row).group(1)
            ln = LINE.search(row)
            detail = row.split(" | ", 1)[-1] if " | " in row else ""
            score = SCORE.search(row)
            if score:
                sign = -1 if kind == "COST loadconst" else 1
                net += sign * int(score.group(1)) * int(score.group(2))
                if kind != "COST loadconst" and score.group(1) == "0":
                    continue  # uses that save nothing (register or push operands) are not listed
            extra = f" {'-' if kind == 'COST loadconst' else '+'}{score.group(1)}x{score.group(2)}" if score else ""
            if kind == "QUEUE":
                extra = f" benefit={re.search(r' benefit=(-?\d+)', row).group(1)}"
            out.append(f"  {kind:15} ln={ln.group(1) if ln else '-':>4}{extra}  {detail[:140]}")
        out.append(f"  first scoring net: {net}; later rescoring events: {later[value]}")
    if demoted:
        out.append("== block-end demotions (last def/reload unused and not live-out -> memory form)")
        out += [f"  {line[:170]}" for line in demoted]
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path, nargs="?")
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--il",
        action="store_true",
        help="dump the IL at every stock pass boundary, build_live_ranges and colouring",
    )
    parser.add_argument("--report-only", type=Path, help="summarise an existing trace directory")
    args = parser.parse_args()
    if args.report_only:
        out = args.report_only
    else:
        if not args.scratch or not args.out:
            parser.error("scratch and --out are required")
        result = trace(args.scratch, args.out, il=args.il)
        print(json.dumps({"out": str(args.out), "metrics": result["metrics"]}))
        out = args.out
    lines = [row["line"] for row in json.loads((out / "snapshots.json").read_text())]
    text = report(lines)
    (out / "const-report.txt").write_text("\n".join(text) + "\n")
    sys.stdout.write("\n".join(text) + "\n")


if __name__ == "__main__":
    main()
