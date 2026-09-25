"""Dump readable VC6 C2 IL at chosen internal stages (diagnostic only; no match credit).

Runs a scratch through Crimson's preserving observer (`crimson match c2-trace`: whole-COFF, replay
and missing-stream controls unchanged) with the readable IL dump from `iv_trace.py`. Symbols print as
`#id c<class> ^parent+offset z<size> /<flags5>.<+0x32> @a<alias class> 'name'`, so a field copy of
`vertex.y` reads `#v^P+4`. Event heads also record g_alias_class_count (0x1079d670) and
g_alias_class_max (0x107adfd8).

`--preset globopt` (aggregate copies, forward substitution, CSE) dumps:

    glob        0x107581ee  globopt_run entry (IL after inlining)
    canon       0x1071313c  after globopt_canonicalize_tuples
    coalesce    0x10713143  after coalesce_temp_copies
    dce0        0x10713153  after globopt_dead_code_elim (phase 0)
    fwd         0x1071315a  after forward_propagate_definitions
    vn          0x10713189  after assign_expression_owners (value numbering)
    cse1        0x10713375  entry of delete_status1_fact_tuples = after the phase-1 CSE sweep
    dce1        0x10713394  after DCE following phase 1
    cse3        0x1071366c  entry of delete_status1_fact_tuples = after the phase-3 (full) CSE sweep
    dce3        0x10713683  after the final DCE
    fold        0x107136a1  after globopt_fold_adjacent_copies
    final       0x107136a8  after globopt_finalize_tuples
    purge       0x107581fc  purge_unreferenced_temps entry (after globopt)
    lower       0x10758310  pass_lower_function entry

and `--lines A-B` prints, per stage, the tuples whose C2 line label is in the range, marking
new/changed (+) and removed (-) tuples, so the stage that deletes a copy is visible.

`--preset jumpopt` (tail merging) dumps the IL at jump_optimize #2 entry (0x107584a9), block_mover
entry (0x107584bc) and emit (0x107585b1), and reports every cross_jump_into_fallthrough (0x1073d701),
cross_jump_pair (0x1071dfc6, called from cross_jump_label_refs) and sink_common_tail_pair
(0x1074d84f) attempt with its two jumps (ecx/edx), the tuples before them and the verdict.

    uv run python scripts/c2/il_stage_trace.py <crimson-scratch> --out <new-dir> --lines 12-20
    # a snail-mail scratch, run from the snail-mail checkout (it provides the `snail` package):
    uv run python ../crimson/scripts/c2/il_stage_trace.py --snail <scratch> --out <new-dir> \
        [--match-root <alternate tools/match root>] [--preset jumpopt]
    uv run python scripts/c2/il_stage_trace.py --reuse <trace-dir> --lines 12-20

See tools/match/c2/compiler/aggregate-temporaries.md.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = 0x10700000
CRIMSON = HERE.parents[1]
SNAIL = CRIMSON.parent / "snail-mail"

# (call site VA, callee VA, name, return hook, mode) with iv_trace modes: 1 dumps on return, 3 on entry,
# 0 records only the event head (registers and stack arguments at entry, eax at return).
PRESETS = {
    "globopt": (
        (0x1071313C, 0x10713989, "canon", True, 1),
        (0x10713143, 0x107117D0, "coalesce", True, 1),
        (0x10713153, 0x10706BD0, "dce0", True, 1),
        (0x1071315A, 0x10711AFA, "fwd", True, 1),
        (0x10713189, 0x10711209, "vn", True, 1),
        (0x10713375, 0x1070A547, "cse1", False, 3),
        (0x10713394, 0x10706BD0, "dce1", True, 1),
        (0x1071366C, 0x1070A547, "cse3", False, 3),
        (0x10713683, 0x10706BD0, "dce3", True, 1),
        (0x107136A1, 0x10726654, "fold", True, 1),
        (0x107136A8, 0x107266FF, "final", True, 1),
    ),
    "jumpopt": (
        (0x10758466, 0x10735042, "jo1", False, 3),
        (0x107584A9, 0x10735042, "jo2", False, 3),
        (0x107352F4, 0x1073D701, "cross_jump_into_fallthrough", True, 0),
        (0x10735112, 0x1073D211, "cross_jump_label_refs", True, 1),
        (0x1073D290, 0x1071DFC6, "cross_jump_pair", True, 0),
        (0x10735121, 0x1073D2C5, "sink_common_tails_of_label", True, 0),
        (0x1073D322, 0x1074D84F, "sink_common_tail_pair", True, 1),
        (0x107584BC, 0x1073663C, "mover", False, 3),
        (0x107585B1, 0x1073EBEA, "emit", False, 3),
    ),
}
STOCK_NAMES = {0: "glob", 1: "purge", 4: "lower"}
TUPLE = re.compile(r"^T (\w+) op=(\w+) k=(\w+) ty=(\w+) ln=(\d+) tag=(\d+)(.*)$")
OPERAND = re.compile(r"\[(\w+):(\d+):(\w+) f(\w+)\.(\w+) ([^\]]*(?:\[[^\]]*\][^\]]*)*)\]")
OPNAMES = {
    "15b": "=",
    "15d": "lea",
    "15f": "cvt",
    "162": "round",
    "16a": "blkarg",
    "16b": "blkcopy",
    "169": "=agg",
    "16d": "+",
    "16e": "-",
    "16f": "*",
    "175": "/",
    "184": "call",
    "187": "call",
    "190": "intrin",
}


def load_modules(snail: bool, match_root: Path | None):
    """Return (match_c2, iv_trace) for Crimson, or through snail-mail's adapter."""
    if not snail:
        sys.path.insert(0, str(HERE))
        from crimson import match_c2

        return match_c2, importlib.import_module("iv_trace")
    sys.path.insert(0, str(SNAIL / "tools/match/c2"))
    adapter = importlib.import_module("trace")
    if match_root is not None:
        from snail import match as m

        root = match_root.resolve()
        adapter.facade.compile_scratch = lambda config, force=False: m.compile_scratch(config, root)
    stub = types.ModuleType("crimson")
    stub.match_c2 = adapter.c2
    sys.modules.setdefault("crimson", stub)
    sys.modules.setdefault("crimson.match_c2", adapter.c2)
    sys.path.insert(0, str(HERE))
    return adapter.c2, importlib.import_module("iv_trace")


def profile(c2, preset: str):
    stock = c2.load_profile()
    hooks = [
        dict(h, mode=3 if i in STOCK_NAMES else 0, name=STOCK_NAMES.get(i, f"pass@{h['target'] + BASE:#x}"))
        for i, h in enumerate(stock["hooks"][:12])
    ]
    hooks += [
        {"site": site - BASE, "target": target - BASE, "return": ret, "mode": mode, "name": name}
        for site, target, name, ret, mode in PRESETS[preset]
    ]
    return {**stock, "name": stock["name"] + f"-il-stage-{preset}", "hooks": hooks}


def observer_source(iv):
    body = iv.OBSERVER.replace("    if (phase == 12) saved_loop = r[6];\n", "")
    # Also print symbol flags5 (+5; 0x02 memory-resident aggregate part, 0x04 address taken), +0x32, and
    # for memory-resident symbols the alias class that avail_transfer_tuple 0x1070a0d8 kills on a write
    # (word +0x3e of the record at *(sym+8)).
    body = body.replace(
        '    s("z"); dec(W(y, 0x20));\n',
        '    s("z"); dec(W(y, 0x20));\n'
        '    s("/"); hx(*(unsigned char *)(y + 5)); s("."); hx(*(unsigned char *)(y + 0x32));\n'
        "    if ((*(unsigned char *)(y + 5) & 2) && W(y, 8) && W(W(y, 8), 0))\n"
        '        { s("@a"); dec(*(unsigned short *)(W(W(y, 8), 0) + 0x3e)); }\n',
    )
    # Record the field alias budget (base count 0x1079d670, class count 0x107adfd8) in every event head.
    body = body.replace("static char buf[65536];", "static unsigned long compiler_base;\nstatic char buf[65536];")
    body = body.replace(
        "    base = (unsigned char *)invoke - INVOKE_RVA;\n",
        "    base = (unsigned char *)invoke - INVOKE_RVA;\n    compiler_base = (unsigned long)base;\n",
    )
    body = body.replace(
        '    s(" args=");',
        '    s(" alias_base="); dec(W(compiler_base, 0x9d670)); s(" alias_classes="); dec(W(compiler_base, 0xadfd8));\n'
        '    s(" args=");',
    )

    def source(prof):
        stock = iv.STOCK_OBSERVER_SOURCE(prof)
        wrappers = stock[stock.index("__declspec(naked)") : stock.index("void __stdcall start")]
        header = stock[: stock.index("#include")]
        modes = "static unsigned long modes[] = {" + ",".join(str(h["mode"]) for h in prof["hooks"]) + "};\n"
        text = body.replace("/* GENERATED_HOOKS */", wrappers)
        return header + text.replace("static char buf[65536];", modes + "static char buf[65536];")

    return source


def trace(c2, iv, scratch: Path, out: Path, preset: str):
    prof = profile(c2, preset)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: prof
    c2.observer_source = observer_source(iv)
    c2.decode_trace = iv.decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


def stage_name(event) -> str | None:
    """Only dumped events carry IL: entry dumps (mode 3) and return dumps (mode 1)."""
    if not any(line.startswith("T ") for line in event["body"].splitlines()):
        return None
    return event["name"] + (".ret" if event["boundary"] == "return" else "")


def pretty(line: str) -> str:
    m = TUPLE.match(line)
    if not m:
        return line
    addr, op, _kind, ty, ln, _tag, rest = m.groups()
    rest = OPERAND.sub(lambda o: f"[k{o.group(2)}:{o.group(3)} {o.group(6)}]", rest)
    return f"{addr:>8} {OPNAMES.get(op, op):>7} ty{ty} ln{ln}{rest}"


def functions(events):
    """Split events per compiled function: each starts at the globopt entry dump."""
    groups = []
    for event in events:
        name = stage_name(event)
        if name is None:
            continue
        if name == "glob":
            groups.append([])
        if groups:
            groups[-1].append((name, [line for line in event["body"].splitlines() if line.startswith("T ")]))
    return groups


def report(events, lines: tuple[int, int] | None, ordinal: int | None):
    for number, stages in enumerate(functions(events)):
        if ordinal is not None and number != ordinal:
            continue
        print(f"=== function {number}")
        previous: dict[str, str] = {}
        for name, il in stages:
            selected = {}
            for line in il:
                m = TUPLE.match(line)
                if m and (lines is None or lines[0] <= int(m.group(5)) <= lines[1]):
                    selected[m.group(1)] = line
            gone = [line for addr, line in previous.items() if addr not in selected]
            new = [line for addr, line in selected.items() if previous.get(addr) != line]
            print(f"--- {name}: {len(selected)} tuples, {len(new)} new/changed, {len(gone)} removed")
            for line in gone:
                print("   -", pretty(line))
            for line in selected.values():
                marker = "+" if line in new else " "
                print("  ", marker, pretty(line))
            previous = selected


HEAD = re.compile(r"(\w+)=([0-9a-f,]+)")


def head_fields(event) -> dict[str, str]:
    return dict(HEAD.findall(event["head"]))


def context(il: list[str], addr: str, before: int) -> str:
    """The `before` real tuples ending at `addr` in an IL dump, one per line."""
    index = next((i for i, line in enumerate(il) if line.split()[1] == addr), None)
    if index is None:
        return f"      <{addr} not in the last dump>"
    window = il[max(0, index - before) : index + 1]
    return "\n".join("      " + pretty(line) for line in window)


def report_jumpopt(events, ordinal: int | None, before: int):
    """Late-layout decisions: every cross-jump/sink attempt with its two jumps and result."""
    function = -1
    il: list[str] = []
    pending: dict[str, dict] = {}
    for event in events:
        name, fields = event["name"], head_fields(event)
        if name == "glob" and event["boundary"] == "entry":
            function += 1
        if ordinal is not None and function != ordinal:
            continue
        dump = [line for line in event["body"].splitlines() if line.startswith("T ")]
        if name in ("jo1", "jo2", "mover", "emit") and dump:
            il = dump
            print(f"=== function {function} {name}: {len(dump)} tuples")
            if name != "jo1":
                for line in dump:
                    print("   ", pretty(line))
            continue
        if name in ("cross_jump_pair", "sink_common_tail_pair", "cross_jump_into_fallthrough"):
            if event["boundary"] == "entry":
                pending[name] = fields
                continue
            entry = pending.pop(name, {})
            verdict = "MERGED" if fields.get("eax", "0") != "0" else "no"
            print(f"--- {name}: {verdict} (ecx={entry.get('ecx')} edx={entry.get('edx')})")
            # cross_jump_into_fallthrough takes only the jump (ecx); the pair functions take two jumps.
            registers = ("ecx",) if name == "cross_jump_into_fallthrough" else ("ecx", "edx")
            for register in registers:
                print(f"    {register}:")
                print(context(il, entry.get(register, "0"), before))
        elif name == "cross_jump_label_refs" and event["boundary"] == "return" and dump:
            il = dump


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reuse", type=Path, help="Re-render an existing trace directory")
    parser.add_argument("--snail", action="store_true", help="Trace a snail-mail scratch through its adapter")
    parser.add_argument("--match-root", type=Path, help="snail-mail: compile against another tools/match root")
    parser.add_argument("--lines", help="globopt: C2 line-label range A-B to print")
    parser.add_argument("--function-ordinal", type=int)
    parser.add_argument("--preset", choices=sorted(PRESETS), default="globopt")
    parser.add_argument("--context", type=int, default=12, help="jumpopt: tuples shown before each jump")
    args = parser.parse_args()
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    if args.reuse:
        prof = result_profile(args.reuse)
        events = decode((args.reuse / "observed/phases.bin").read_bytes(), prof)
        args.preset = prof["name"].rsplit("-", 1)[1]
    else:
        if args.scratch is None or args.out is None:
            parser.error("scratch and --out are required")
        c2, iv = load_modules(args.snail, args.match_root)
        result = trace(c2, iv, args.scratch, args.out, args.preset)
        print(json.dumps({k: result[k] for k in ("function", "metrics", "events")}))
        events = decode((args.out / "observed/phases.bin").read_bytes(), result_profile(args.out))
    if args.preset == "jumpopt":
        report_jumpopt(events, args.function_ordinal, args.context)
    else:
        report(events, lines, args.function_ordinal)


def result_profile(out: Path):
    return json.loads((out / "profile.json").read_text())


def decode(data: bytes, prof):
    """Same format as iv_trace.decode, without importing Crimson (usable from snail-mail's env)."""
    text = data.decode("latin-1")
    events = []
    for block in text.split("EVENT ")[1:]:
        head, _, rest = block.partition("\n")
        phase = int(head.split()[0])
        hook = prof["hooks"][phase % 100]
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
    return events


if __name__ == "__main__":
    main()
