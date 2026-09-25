"""Observe VC6 C2 loop strength reduction (IV/SR/LTR) on a scratch, without changing its output.

Runs the scratch through `crimson match c2-trace`'s preserving harness (whole-COFF, replay and
missing-stream controls are unchanged) with a custom observer. The observer hooks the calls made by
`optimize_loop_induction_variables` (C2 0x10745d75) and writes a readable IL dump of the function
after each step, plus a register/argument line for small helpers (derived-IV creation, preheader
inserts). `--report` then summarises every loop: basic IVs, derived IVs in creation order, the
preheader insertion order, rewritten exit tests and the memory operands anchored on each pointer.

    uv run python scripts/c2/iv_trace.py <scratch-dir> --out <new-dir> [--report]
    uv run python scripts/c2/iv_trace.py --report-only <trace-dir>

Only the pinned msvc6.5 C2 (profile hash checked by crimson) is supported.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from crimson import match_c2 as c2

BASE = 0x10700000
STOCK_OBSERVER_SOURCE = c2.observer_source

# (call site VA, callee VA, name, return hook, dump mode)
# mode 1 dumps the whole IL list; mode 2 dumps registers, stack arguments and the operand in eax.
IV_HOOKS = (
    (0x1074519C, 0x10745D75, "optimize_loop_induction_variables", True, 1),
    (0x10745DB5, 0x107468AA, "analyze_loop_exit_test", True, 0),
    (0x10745DD0, 0x10746A2F, "merge_parallel_induction_variables#1", True, 1),
    (0x10745DDC, 0x1074775C, "strength_reduce_loop", True, 1),
    (0x10745DE5, 0x10747C9A, "cleanup_preheader_after_sr", True, 1),
    (0x10745DF5, 0x10747DDA, "remove_dead_iv_code#1", True, 1),
    (0x10745DFE, 0x10747ED0, "convert_loop_stores_to_block_op", True, 1),
    (0x10745E0E, 0x10746A2F, "merge_parallel_induction_variables#2", True, 1),
    (0x10745E1E, 0x107482CD, "replace_loop_exit_tests", True, 1),
    (0x10745E27, 0x10747DDA, "remove_dead_iv_code#2", True, 1),
    (0x10745E35, 0x10748429, "strength_reduce_address_operands", True, 1),
    (0x10745E45, 0x107452DB, "convert_exit_test_to_countdown", True, 1),
    (0x10745E55, 0x1074542C, "replace_iv_with_final_value", True, 1),
    (0x10745E6E, 0x1074572F, "delete_empty_loop", True, 1),
    (0x10745E77, 0x10708EFE, "recse_preheader", True, 1),
    (0x10745E80, 0x10745921, "rewrite_loop_guard_compare", True, 1),
    (0x1074781F, 0x10753DEF, "get_derived_iv@candidate", True, 2),
)

# Post-allocation passes called by the per-function driver 0x10757fc2 (fn in ecx), dumped on entry.
# The local allocator 0x107336f4 itself is stock pass boundary 11 (use --passes).
LATE_HOOKS = tuple(
    (site, target, f"late@{target:#x}", False, 3)
    for site, target in (
        (0x107583E9, 0x107337EC),
        (0x107583FC, 0x10733B7B),
        (0x1075840F, 0x10734032),
        (0x1075842F, 0x1073404F),
        (0x10758450, 0x10704D75),
        (0x10758466, 0x10735042),
        (0x10758479, 0x1073536C),
        (0x107584A9, 0x10735042),
        (0x107584BC, 0x1073663C),
        (0x107584CF, 0x10704DE1),
        (0x107584D6, 0x10704EA7),
        (0x107584DD, 0x10736AB0),
        (0x107584F9, 0x10736B27),
        (0x10758526, 0x107374AA),
        (0x10758541, 0x1073E113),
        (0x10758554, 0x1073E591),
        (0x1075857E, 0x1073E945),
        (0x10758591, 0x1073EB93),
        (0x107585B1, 0x1073EBEA),
        (0x107585C2, 0x1073FBDD),
    )
)

OBSERVER = r"""
#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file;
static unsigned long targets[HOOK_COUNT], returns[HOOK_COUNT], active[HOOK_COUNT], saved_function, saved_loop;
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

static void sym(unsigned long y)
{
    unsigned long fe, name, k;
    if (!y) { s("nil"); return; }
    s("#"); dec(W(y, 0x1c));
    s("c"); dec(*(unsigned char *)(y + 4));
    if (W(y, 0x08) && W(y, 0x08) != y) { s("^"); dec(W(W(y, 0x08), 0x1c)); s("+"); dec(W(y, 0x24)); }
    s("z"); dec(W(y, 0x20));
    fe = W(y, 0);
    if (fe && *(unsigned char *)(fe + 4) == 1) {
        name = *(unsigned long *)(fe + 0x18);
        if (name) { s("'"); for (k = 0; k < 40 && *(char *)(name + k) > 32 && *(char *)(name + k) < 127; ++k) ch(*(char *)(name + k)); }
    }
}

static void operand(unsigned long p, int depth)
{
    unsigned long kind = *(unsigned char *)(p + 8);
    s("["); hx(W(p, 4) & 0xffff); s(":"); dec(kind); s(":"); hx(*(unsigned short *)(p + 10));
    s(" f"); hx(*(unsigned char *)(p + 0x10)); s("."); hx(*(unsigned char *)(p + 0x11));
    s(" ");
    if (kind >= 1 && kind <= 3) {
        sym(W(p, 0x14));
        if (kind == 1 && W(p, 0x18) && W(p, 0x18) != W(p, 0x14)) { s(" @"); sym(W(p, 0x18)); }
    } else if (kind == 7) {
        s("="); dec((long)W(p, 0x18));
    } else if ((kind == 5 || kind == 6) && depth < 4) {
        s("w14="); hx(W(p, 0x14));
        s(" w18="); hx(W(p, 0x18)); s(" w1c="); hx(W(p, 0x1c)); s(" disp="); dec((long)W(p, 0x20));
        s(" w24="); hx(W(p, 0x24)); s(" sc="); dec(*(unsigned char *)(p + 0x10) & 15);
        if (W(p, 0x28)) { s(" base="); operand(W(p, 0x28), depth + 1); }
        if (W(p, 0x2c)) { s(" idx="); operand(W(p, 0x2c), depth + 1); }
    } else {
        s("w14="); hx(W(p, 0x14)); s(" w18="); hx(W(p, 0x18));
    }
    s("]");
}

static void chain(unsigned long p)
{
    unsigned long k = 0;
    while (p && k < 16) { operand(p, 0); s(" "); p = W(p, 0); ++k; }
}

static void dump_il(void)
{
    unsigned long function = saved_function, node, blk, loop;
    node = W(W(W(function, 8), 0), 0x1c);
    while (node) {
        s("T "); hx(node); s(" op="); hx(W(node, 4) & 0xffff); s(" k="); hx(*(unsigned char *)(node + 8));
        s(" ty="); hx(*(unsigned short *)(node + 10)); s(" ln="); dec(*(unsigned short *)(node + 0x10));
        s(" tag="); dec(*(unsigned char *)(node + 0x13));
        if (*(unsigned char *)(node + 8) == 0x19 && W(node, 0x14)) {
            blk = W(node, 0x14);
            s(" BLOCK n="); dec(*(short *)(blk + 0x6c)); s(" depth="); dec(*(short *)(blk + 0x6e));
            s(" flags="); hx(W(blk, 0x18));
            loop = W(blk, 0x68);
            if (loop) {
                s(" loop="); hx(loop);
                s(" hdr="); dec(*(short *)(W(loop, 0x14) + 0x6c));
                s(" latch="); dec(*(short *)(W(loop, 0x18) + 0x6c));
                if (W(loop, 0x10)) { s(" pre="); dec(*(short *)(W(loop, 0x10) + 0x6c)); }
            }
        }
        if (*(unsigned char *)(node + 9) & 1) {
            s(" | "); chain(W(node, 0x1c)); s("<= "); chain(W(node, 0x18));
        }
        s("\n");
        node = W(node, 0);
    }
}

static void __cdecl observe(unsigned long phase, unsigned long *r)
{
    unsigned long index = phase >= 100 ? phase - 100 : phase, i;
    if (phase < 12) saved_function = r[6];
    if (phase == 12) saved_loop = r[6];
    s("EVENT "); dec(phase); s(" fn="); hx(saved_function);
    s(" eax="); hx(r[7]); s(" ecx="); hx(r[6]); s(" edx="); hx(r[5]); s(" ebx="); hx(r[4]);
    s(" esi="); hx(r[1]); s(" edi="); hx(r[0]);
    if (saved_loop) { s(" trip="); hx(W(saved_loop, 0x28)); s(" exitcmp="); hx(W(saved_loop, 0x2c)); }
    s(" args=");
    for (i = 0; i < 6; ++i) { hx(r[(phase >= 100 ? 9 : 10) + i]); s(","); }
    s("\n");
    if ((modes[index] == 1 && (phase >= 100 || phase == 12)) || (modes[index] == 3 && phase < 100)) dump_il();
    if (modes[index] == 2 && phase >= 100 && r[7]) { s("RET "); operand(r[7], 0); s("\n"); }
    s("END\n");
    flush();
}
/* GENERATED_HOOKS */
void __stdcall start(void)
{
    HMODULE module;
    invoke_t invoke;
    protect_t protect;
    unsigned char *base, *site;
    unsigned long i, header[3];
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
    s("C2IVTRACE base="); hx((unsigned long)base); s("\n"); flush();
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


def profile_with_hooks(extra=IV_HOOKS, *, passes=False):
    profile = c2.load_profile()
    hooks = [
        dict(h, mode=3 if passes and i else 0, name=f"pass@{h['target'] + BASE:#x}")
        for i, h in enumerate(profile["hooks"][:12])
    ]
    hooks += [
        {"site": site - BASE, "target": target - BASE, "return": ret, "mode": mode, "name": name}
        for site, target, name, ret, mode in extra
    ]
    return {**profile, "name": profile["name"] + "-iv-trace", "hooks": hooks}


def observer_source(profile):
    """Reuse crimson's preserving call-site wrappers; replace only the dump routine."""
    stock = STOCK_OBSERVER_SOURCE(profile)
    wrappers = stock[stock.index("__declspec(naked)") : stock.index("void __stdcall start")]
    header = stock[: stock.index("#include")]
    modes = "static unsigned long modes[] = {" + ",".join(str(h["mode"]) for h in profile["hooks"]) + "};\n"
    body = OBSERVER.replace("/* GENERATED_HOOKS */", wrappers)
    return header + body.replace("static char buf[65536];", modes + "static char buf[65536];")


def decode(data, profile):
    text = data.decode("latin-1")
    if not text.startswith("C2IVTRACE"):
        raise ValueError("Not an IV trace")
    events = []
    for block in text.split("EVENT ")[1:]:
        head, _, rest = block.partition("\n")
        phase = int(head.split()[0])
        hook = profile["hooks"][phase % 100]
        events.append(
            {
                "event": len(events),
                "phase": phase,
                "name": hook["name"],
                "boundary": "return" if phase >= 100 else "entry",
                "head": head,
                "body": rest.removesuffix("END\n"),
            },
        )
    if not events:
        raise ValueError("Empty IV trace")
    return events


def trace(scratch: Path, out: Path, *, passes=False, late=False):
    profile = profile_with_hooks(IV_HOOKS + (LATE_HOOKS if late else ()), passes=passes)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: profile
    c2.observer_source = observer_source
    c2.decode_trace = decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


# ---------------------------------------------------------------- report

TUPLE = re.compile(r"^T (\w+) op=(\w+) k=(\w+) ty=(\w+) ln=(\d+) tag=(\d+)(.*)$")
OPNAMES = {
    "15b": "=",
    "16d": "+",
    "16e": "-",
    "16f": "*",
    "15f": "cvt",
    "15d": "lea",
    "17d": "cmp",
    "17e": "cmp",
    "186": "jmp",
    "187": "call",
}


def pretty_operand(text):
    """Shorten an operand dump to kind/symbol/offset."""
    return re.sub(r"\[(\w+):(\d+):(\w+) f\w+\.\w+ ", r"[\2:", text)


def pretty_tuple(line):
    m = TUPLE.match(line)
    if not m:
        return line
    _, op, kind, ty, ln, tag, rest = m.groups()
    name = OPNAMES.get(op, op)
    return f"{name:>5} k{kind} ty{ty} ln{ln} tag{tag}{pretty_operand(rest)}"


def loops_from(events):
    """Group IV-driver events per loop invocation (entry .. return of 0x10745d75)."""
    loops, current = [], None
    for e in events:
        if e["name"] == "optimize_loop_induction_variables":
            if e["boundary"] == "entry":
                current = {"loop": e["head"].split("ecx=")[1].split()[0], "events": []}
                loops.append(current)
            else:
                current["events"].append(e)
                current = None
        elif current is not None:
            current["events"].append(e)
    return loops


def il_lines(event):
    return [line for line in event["body"].splitlines() if line.startswith("T ")]


def diff_il(before, after):
    """Tuples added (by address) with their neighbours, and tuples removed."""
    old = {line.split()[1]: line for line in before}
    new = {line.split()[1]: line for line in after}
    added = [(i, line) for i, line in enumerate(after) if line.split()[1] not in old]
    removed = [line for addr, line in old.items() if addr not in new]
    changed = [line for addr, line in new.items() if addr in old and old[addr] != line]
    return added, removed, changed


DST_SYM = re.compile(r"\| \[\w+:\d+:\w+ f\w+\.\w+ #(\d+)c")


def block_tuples(il, number):
    """Tuples of the block whose physical number is `number`."""
    tuples, inside = [], False
    for line in il:
        if " BLOCK n=" in line:
            inside = f" BLOCK n={number} " in line
        elif inside:
            tuples.append(line)
    return tuples


def preheader_number(il, loop):
    header = next((line for line in il if f" loop={loop} " in line), "")
    match = re.search(r" pre=(-?\d+)", header)
    return match and int(match.group(1))


def dst_sym(line):
    match = DST_SYM.search(line)
    return match and int(match.group(1))


def loop_summary(loop, derived):
    """Derived-IV creation order, preheader init order, merge survivors (anchors) and rewritten compares."""
    last = {}
    for e in loop["events"]:
        if il_lines(e):
            last[e["name"]] = il_lines(e)
    lines = [f"  derived IVs in creation order: {' '.join(f'#{d}' for d in derived)}"]
    for stage in ("strength_reduce_loop", "merge_parallel_induction_variables#2", "optimize_loop_induction_variables"):
        il = last.get(stage)
        if not il:
            continue
        number = preheader_number(il, loop["loop"])
        inits = [line for line in block_tuples(il, number) if " op=15b " in line]
        lines.append(f"  preheader (block {number}) assignments after {stage}:")
        lines += [f"     {pretty_tuple(line)}" for line in inits]
        updated = {dst_sym(line) for line in il if " op=15b " in line and " tag=4 " in line}
        survivors = [d for d in derived if d in updated]
        if survivors:
            lines.append(f"  derived IVs still updated in the loop: {' '.join(f'#{d}' for d in survivors)}")
    return lines


def report(events, out):
    lines = []
    candidate = ""
    for loop in loops_from(events):
        lines.append(f"=== loop {loop['loop']}")
        previous = None
        derived = []
        for e in loop["events"]:
            if e["name"].startswith("get_derived_iv"):
                if e["boundary"] == "entry":
                    # esi holds the candidate tuple at call site 0x1074781f
                    anchor = e["head"].split("esi=")[1].split()[0]
                    known = {line.split()[1]: line for line in previous or []}
                    candidate = pretty_tuple(known.get(anchor, f"T {anchor} (created this round)"))
                else:
                    ret = e["body"].strip().splitlines()[0] if e["body"].strip() else ""
                    number = int(re.search(r"#(\d+)c", ret).group(1))
                    if number not in derived:
                        derived.append(number)
                    lines.append(f"  derived IV {pretty_operand(ret).removeprefix('RET ')} for {candidate.strip()}")
                continue
            if e["name"] == "analyze_loop_exit_test" and e["boundary"] == "return":
                # 0x107468aa returns 1 unless the trip count is the constant 0 or 1; a failed
                # exit-shape check only leaves the trip count (loop+0x28) null.
                ok = e["head"].split("eax=")[1].split()[0]
                trip = e["head"].split("trip=")[1].split()[0] if "trip=" in e["head"] else "?"
                recorded = {"0": "no", "?": "unknown"}.get(trip, "yes")
                lines.append(f"  IV pipeline runs: {ok != '0'}; trip count recorded: {recorded}")
                continue
            il = il_lines(e)
            if not il:
                continue
            if previous is not None:
                added, removed, changed = diff_il(previous, il)
                if added or removed or changed:
                    lines.append(f"  -- after {e['name']}")
                    for i, line in added:
                        lines.append(f"     + @{i:<4} {pretty_tuple(line)}")
                    for line in removed:
                        lines.append(f"     - {pretty_tuple(line)}")
                    for line in changed:
                        lines.append(f"     ~ {pretty_tuple(line)}")
            else:
                lines.append(f"  -- IL entering the IV pipeline ({len(il)} tuples)")
            previous = il
        lines += loop_summary(loop, derived)
    (out / "iv-report.txt").write_text("\n".join(lines) + "\n")
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path, nargs="?")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--passes", action="store_true", help="also dump IL at the 11 later stock pass boundaries")
    parser.add_argument("--late", action="store_true", help="also dump IL entering each post-allocation pass")
    parser.add_argument("--report-only", type=Path, help="summarise an existing trace directory")
    args = parser.parse_args()
    if args.report_only:
        out = args.report_only
    else:
        if not args.scratch or not args.out:
            parser.error("scratch and --out are required")
        result = trace(args.scratch, args.out, passes=args.passes, late=args.late)
        print(json.dumps({"out": str(args.out), "events": result["events"], "metrics": result["metrics"]}))
        out = args.out
        if not args.report:
            return
    events = json.loads((out / "snapshots.json").read_text())
    sys.stdout.write("\n".join(report(events, out)) + "\n")


if __name__ == "__main__":
    main()
