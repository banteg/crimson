"""Follow VC6 C2 branch tuples (IL 0x185..0x18c, machine jcc/jmp) from the IL reader to the block mover.

Diagnostic only; no match credit. Runs a scratch through Crimson's preserving observer
(`crimson match c2-trace`): the whole COFF object must stay identical, and extra compact
records are written at these pinned C2 callsites:

    read      0x107580a2  set_current_scope, right after read_function_il (raw reader IL)
    cfg       0x10758147  cfg_rebuild (after SEH/C++ EH lowering, before /Og flow graph)
    ofg       0x1075818f  optimize_flow_graph_initial entry (+ return "ofg.ret")
    glob      0x107581ee  globopt_run
    postglob  0x107581fc  purge_unreferenced_temps after globopt_run
    thread.jmp.ret 0x10709567  tuple_new_jmp_before in thread_jumps_at_block_end (new jmp = EAX)
    repair.jmp.ret 0x1071dd26  tuple_new_jmp_before in cfg_repair_fallthrough (new jmp = EAX)
    lower     0x10758310  pass_lower_function
    jo1       0x10758466  jump_optimize #1
    fin       0x10758479  final_lowering_peepholes
    jo2       0x107584a9  jump_optimize #2
    mover     0x107584bc  block_mover (+ return "mover.ret")
    move      0x107367ce  block_mover loop-1 tuple_move_range(after, first, last)
    sink      0x1074d985  sink_common_tail_pair tuple_move_range(after, first, last)
    emit      0x107585b1  emit_function

For every function it prints, for each forward unconditional jump at block_mover entry, the loop-1
verdict (PASS or the failing condition), where the jump was born (reader, thread_jumps_at_block_end,
cfg_repair_fallthrough, or the pass interval) with its opcode/flags at each boundary, and every
observed loop-1 range move. `--phases` also dumps the branch tuples of the named boundaries.
Events are saved to --out/branch.json; `--reuse` re-renders them without compiling.
glob and emit keep the stock snapshots (phases.bin). See tools/match/c2/compiler/branch-variants.md.

    uv run python scripts/c2/branch_trace.py tools/match/scratches/bonus_pick_random_type \
        --out /private/tmp/br-bonus [--phases read,postglob,mover] [--lines 60-70] [--function-ordinal N]
    uv run python scripts/c2/branch_trace.py --out /private/tmp/br-bonus --reuse
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from unittest.mock import patch

from crimson import match_c2 as c2

G_CUR_FUNCTION = 0xAC380
HOOKS = [
    ("glob", 0x581EE, 0x130CB, False),  # index 0: stock snapshot, function ordinal
    ("emit", 0x585B1, 0x3EBEA, False),  # index 1: stock snapshot
    ("read", 0x580A2, 0x180E6, False),
    ("cfg", 0x58147, 0x0592F, False),
    ("ofg", 0x5818F, 0x053DE, True),
    ("postglob", 0x581FC, 0x0FCDA, False),
    ("thread.jmp", 0x09567, 0x04C60, True),
    ("repair.jmp", 0x1DD26, 0x04C60, True),
    ("lower", 0x58310, 0x29511, False),
    ("jo1", 0x58466, 0x35042, False),
    ("fin", 0x58479, 0x3536C, False),
    ("jo2", 0x584A9, 0x35042, False),
    ("mover", 0x584BC, 0x3663C, True),
    ("move", 0x367CE, 0x33655, False),
    ("sink", 0x4D985, 0x33655, False),
]
PHASES = {i: name for i, (name, *_rest) in enumerate(HOOKS)} | {
    100 + i: name + ".ret" for i, (name, *_rest) in enumerate(HOOKS)
}
READ_INDEX = next(i for i, h in enumerate(HOOKS) if h[0] == "read")
LOCAL_FIRST = next(i for i, h in enumerate(HOOKS) if h[0] == "thread.jmp")
NODE_WORDS = 12
HEADER_WORDS = 9
MAX_NODES = 20000

IL_NAMES = {
    0x8: "ret",
    0xF: "jcc",
    0x10: "jmp",
    0x185: "CJUMP",
    0x186: "JUMP",
    0x187: "CATCH_RETURN",
    0x188: "FINALLY_CALL",
    0x189: "FINALLY_RET",
    0x18A: "BRANCH_18A",
    0x18B: "EH_EDGE",
    0x18C: "NORETURN_EXIT",
    0x18D: "SWITCH",
    0x18E: "SWITCH_18E",
    0x1AE: "LABEL",
}
KIND_NAMES = {0xE: "call", 0xF: "exit", 0x11: "branch", 0x13: "switch", 0x14: "pseudo", 0x1A: "label"}

WATCH = r"""
static HANDLE br_file;
static unsigned char *br_base;
static unsigned long br_ordinal;
static void br_write(void *data, unsigned long size) {
    DWORD written;
    if(!WriteFile(br_file,data,size,&written,0)||written!=size)ExitProcess(74);
}
static int br_watch(unsigned long phase, unsigned long *regs) {
    unsigned long index = phase % 100, fn, cfg, block, first = 0, node, count = 0, head[HEADER_WORDS], rec[NODE_WORDS], j, op, sym, cell;
    unsigned char kind;
    if (index < 2) return 0;
    if (index == READ_INDEX && phase < 100) ++br_ordinal;
    fn = *(unsigned long *)(br_base + G_CUR_FUNCTION);
    if (fn) { cfg = *(unsigned long *)(fn + 8); if (cfg) { block = *(unsigned long *)cfg; if (block) first = *(unsigned long *)(block + 0x1c); } }
    if (index == LOCAL_FIRST || index == LOCAL_FIRST + 1) {
        /* Mid-pass jmp creation: the block list may be in flux, so record only the neighbourhood. */
        if (phase < 100) return 1;
        first = regs[7];
        for (j = 0; j < 8 && *(unsigned long *)(first + 0xc); ++j) first = *(unsigned long *)(first + 0xc);
        for (node = first; node && count < 24; node = *(unsigned long *)node) ++count;
    } else {
        for (node = first; node && count < MAX_NODES; node = *(unsigned long *)node) ++count;
        if (node) ExitProcess(73);
    }
    head[0]=phase; head[1]=br_ordinal; head[2]=count; head[3]=regs[6]; head[4]=regs[5]; head[5]=regs[10]; head[6]=regs[7]; head[7]=fn; head[8]=fn ? *(unsigned long *)(fn + 0x24) : 0;
    br_write(head, sizeof(head));
    for (node = first; count; node = *(unsigned long *)node, --count) {
        for (j=0;j<NODE_WORDS;++j) rec[j]=0;
        kind = *(unsigned char *)(node+8);
        rec[0]=node; rec[1]=*(unsigned long *)node; rec[3]=*(unsigned long *)(node+4); rec[4]=*(unsigned long *)(node+8);
        if (kind >= 0xc) { rec[2]=*(unsigned long *)(node+0xc); rec[5]=*(unsigned short *)(node+0x10); rec[10]=*(unsigned long *)(node+0x14); }
        if (kind == 0x11) {
            rec[6]=*(unsigned long *)(node+0x20);
            op=*(unsigned long *)(node+0x18);
            if (op) {
                rec[8]=*(unsigned char *)(op+8);
                if (rec[8]==4) { sym=*(unsigned long *)(op+0x14); rec[11]=sym; if (sym) rec[7]=*(unsigned long *)(sym+0x32); }
            }
        }
        if (kind == 0x1a) {
            rec[11]=*(unsigned long *)(node+0x18);
            for (cell=*(unsigned long *)(node+0x1c), j=0; cell && j<100000; cell=*(unsigned long *)cell) ++j;
            rec[9]=j;
        }
        br_write(rec, sizeof(rec));
    }
    return 1;
}
"""


def observer(profile, stock_source):
    defines = {
        "NODE_WORDS": NODE_WORDS,
        "HEADER_WORDS": HEADER_WORDS,
        "G_CUR_FUNCTION": G_CUR_FUNCTION,
        "READ_INDEX": READ_INDEX,
        "LOCAL_FIRST": LOCAL_FIRST,
    }
    source = stock_source(profile)
    anchors = (
        "static HANDLE trace_file;",
        "    unsigned long first, node, count = 0, record[742], op, side, j, k, at;\n",
        "    trace_file = CreateFileA(",
        "    CloseHandle(trace_file);",
    )
    for anchor in anchors:
        if source.count(anchor) != 1:
            raise ValueError(f"Unexpected observer template near {anchor!r}")
    header = "".join(f"#define {k} {v}\n" for k, v in defines.items())
    source = source.replace("#define MAX_NODES 16384", f"#define MAX_NODES {MAX_NODES}")
    source = source.replace(anchors[0], anchors[0] + "\n" + header + WATCH)
    source = source.replace(anchors[1], anchors[1] + "    if (br_watch(phase, registers)) return;\n")
    source = source.replace(
        anchors[2],
        "    br_base = base;\n"
        '    br_file = CreateFileA("branch.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        "    if (br_file == INVALID_HANDLE_VALUE) ExitProcess(72);\n" + anchors[2],
    )
    source = source.replace("if(op) ExitProcess(98);", "")
    return source.replace(anchors[3], "    CloseHandle(br_file);\n" + anchors[3])


def run(scratch: Path, out: Path):
    stock_source = c2.observer_source
    hooks = [{"site": site, "target": target, "return": ret} for _name, site, target, ret in HOOKS]
    profile = dict(c2.load_profile(), name="msvc6.5-c2-branch", hooks=hooks)
    with (
        patch.object(c2, "load_profile", return_value=profile),
        patch.object(c2, "observer_source", side_effect=lambda p: observer(p, stock_source)),
        patch.object(c2, "MAX_NODES", MAX_NODES),
    ):
        manifest = c2.trace(scratch, out)
    return manifest, (out / "observed/branch.bin").read_bytes()


def decode(data: bytes) -> list[dict]:
    events = []
    at = 0
    while at < len(data):
        head = struct.unpack_from(f"<{HEADER_WORDS}I", data, at)
        at += HEADER_WORDS * 4
        phase, ordinal, count, ecx, edx, arg0, eax, _fn, _base_line = head
        nodes = []
        for _ in range(count):
            w = struct.unpack_from(f"<{NODE_WORDS}I", data, at)
            at += NODE_WORDS * 4
            nodes.append(
                {
                    "id": w[0],
                    "op": w[3],
                    "kind": w[4] & 0xFF,
                    "flags": (w[4] >> 8) & 0xFF,
                    "type": w[4] >> 16,
                    "prev": w[2],
                    "line": w[5],
                    "cond": w[6],
                    "target": w[7],
                    "src_kind": w[8],
                    "refs": w[9],
                    "aux": w[10],
                    "sym": w[11],
                },
            )
        index = {n["id"]: i for i, n in enumerate(nodes)}
        for n in nodes:
            n["target_index"] = index.get(n["target"]) if n["target"] else None
        event = {"phase": PHASES[phase], "ordinal": ordinal, "nodes": nodes}
        if PHASES[phase] in ("move", "sink"):
            event["move"] = {"after": index.get(ecx), "first": index.get(edx), "last": index.get(arg0)}
        if PHASES[phase].endswith(".jmp.ret"):
            event["new"] = index.get(eax)
        events.append(event)
    return events


def is_uncond_jump(n) -> bool:
    return n["kind"] == 0x11 and n["cond"] == 0 and n["op"] != 0x18B


def mover_gate(nodes: list[dict]) -> list[dict]:
    """Evaluate block_mover loop-1 conditions (0x1073671c..0x1073679a) on a static snapshot."""
    rows = []
    for i, j in enumerate(nodes):
        if not is_uncond_jump(j) or j["src_kind"] != 4:
            continue
        t = j["target_index"]
        reasons = []
        if j["flags"] & 8:
            reasons.append("flag8")
        nxt = nodes[i + 1] if i + 1 < len(nodes) else None
        if t is None:
            reasons.append("no-label-target")
        elif nxt is None or nxt["kind"] != 0x1A:
            reasons.append("next-not-label")
        elif t == i + 1:
            reasons.append("jump-to-next")
        elif t < i:
            reasons.append("backward")
        else:
            prev = nodes[t - 1]
            if not (is_uncond_jump(prev) or prev["kind"] == 0xF):
                reasons.append(f"target-prev-{describe(prev)}")
        rows.append({"index": i, "line": j["line"], "target": t, "passes": not reasons, "reasons": reasons})
    return rows


def describe(n) -> str:
    if n["kind"] == 0x11:
        name = IL_NAMES.get(n["op"], hex(n["op"]))
        return ("cond-" if n["cond"] or n["op"] == 0x18B else "") + name
    return KIND_NAMES.get(n["kind"], f"kind{n['kind']:#x}") + (f"({n['op']:#x})" if n["kind"] != 0x1A else "")


SNAPSHOTS = ["read", "cfg", "ofg", "ofg.ret", "postglob", "lower", "jo1", "fin", "jo2", "mover"]
CREATORS = {"thread.jmp.ret": "thread_jumps_at_block_end", "repair.jmp.ret": "cfg_repair_fallthrough"}


def lineage(events: list[dict], ordinal: int, jump_id: int, line: int) -> dict:
    """Follow one tuple back through the snapshots while its address, kind and C2 line stay the same.

    Arena addresses are recycled, so the chain stops at the first snapshot where the tuple is absent."""
    snaps = {e["phase"]: e for e in events if e["ordinal"] == ordinal and e["phase"] in SNAPSHOTS}
    chain = []
    for phase in reversed(SNAPSHOTS):
        hit = next(
            (n for n in snaps[phase]["nodes"] if n["id"] == jump_id and n["kind"] == 0x11 and n["line"] == line),
            None,
        )
        if hit is None:
            break
        chain.append((phase, hit))
    chain.reverse()
    born = chain[0][0]
    creator = "reader" if born == "read" else None
    if creator is None:
        before = SNAPSHOTS[SNAPSHOTS.index(born) - 1]
        seen = False
        for e in events:
            if e["ordinal"] != ordinal:
                continue
            if e["phase"] == before:
                seen = True
            elif e["phase"] == born:
                break
            elif seen and e["phase"] in CREATORS and e["new"] is not None:
                new = e["nodes"][e["new"]]
                if new["id"] == jump_id and new["line"] == line:
                    creator = CREATORS[e["phase"]]
    return {
        "born": born,
        "creator": creator or f"a pass between {SNAPSHOTS[SNAPSHOTS.index(born) - 1]} and {born}",
        "ops": [(phase, n["op"], n["flags"]) for phase, n in chain],
    }


def report(events: list[dict], ordinal: int) -> str:
    """Mover loop-1 verdict for every forward unconditional jump, with its lineage, plus the observed moves."""
    out = []
    mover = next(e for e in events if e["ordinal"] == ordinal and e["phase"] == "mover")
    for row in mover_gate(mover["nodes"]):
        j = mover["nodes"][row["index"]]
        info = lineage(events, ordinal, j["id"], j["line"])
        ops = " ".join(
            f"{phase}:{IL_NAMES.get(op, hex(op))}/{flags:#04x}"
            for phase, op, flags in info["ops"]
            if phase in ("read", "postglob", "lower", "jo1", "mover") or phase == info["born"]
        )
        verdict = "PASS" if row["passes"] else ",".join(row["reasons"])
        out.append(f"  jmp@{row['index']} line {row['line']} -> L{row['target']}: {verdict}")
        out.append(f"      born {info['born']} ({info['creator']}); {ops}")
    for e in events:
        if e["ordinal"] == ordinal and e["phase"] == "move":
            m, nodes = e["move"], e["nodes"]
            tested = sorted({n["line"] for n in nodes[m["first"] : m["last"] + 1] if n["kind"] == 0x11 and n["cond"]})
            anchor = nodes[m["after"] - 1] if m["after"] else None
            where = f"{describe(anchor)} line {anchor['line']}" if anchor else "function end"
            out.append(f"  MOVE [{m['first']}..{m['last']}] (conditional branches on lines {tested}) -> after {where}")
    return "\n".join(out)


def render(event, lines=None) -> str:
    nodes = event["nodes"]
    out = [f"== {event['phase']} (function {event['ordinal']}, {len(nodes)} nodes)"]
    if "move" in event:
        out.append(f"   range move {event['move']}")
    if "new" in event:
        n = nodes[event["new"]]
        out.append(f"   new jmp@{event['new']} line {n['line']} -> L{n['target_index']}")
        return "\n".join(out)
    for i, n in enumerate(nodes):
        if n["kind"] not in (0x11, 0x1A, 0xF, 0x13) and not (n["kind"] == 0xE and n["op"] != 0x184):
            continue
        if lines and not (lines[0] <= n["line"] <= lines[1]) and n["kind"] != 0x1A:
            continue
        if n["kind"] == 0x1A:
            if lines:
                continue
            out.append(f"  {i:4d}          L{i} refs={n['refs']}")
            continue
        text = describe(n)
        if n["kind"] == 0x11:
            target = f"-> L{n['target_index']}" if n["target_index"] is not None else "-> (non-label)"
            text += f" {target} flags={n['flags']:#04x}{' bit3' if n['flags'] & 8 else ''}"
        out.append(f"  {i:4d} line {n['line']:4d} {text}")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path, nargs="?", help="scratch directory (omit with --reuse)")
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--reuse", action="store_true", help="re-render an existing --out/branch.json")
    parser.add_argument("--function-ordinal", type=int, help="default: every function")
    parser.add_argument("--phases", help="also dump these phases (comma-separated, e.g. read,postglob,mover)")
    parser.add_argument("--lines", help="with --phases: only branches with C2 line labels A-B")
    args = parser.parse_args()
    if args.reuse:
        events = json.loads((args.out / "branch.json").read_text())
        metrics = None
    else:
        manifest, data = run(args.scratch, args.out)
        events = decode(data)
        (args.out / "branch.json").write_text(json.dumps(events) + "\n")
        metrics = manifest["metrics"]
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    phases = set(args.phases.split(",")) if args.phases else set()
    ordinals = sorted({e["ordinal"] for e in events if e["phase"] == "mover"})
    text = []
    for ordinal in ordinals:
        if args.function_ordinal is not None and ordinal != args.function_ordinal:
            continue
        text.append(f"## function {ordinal}")
        text.extend(render(e, lines) for e in events if e["ordinal"] == ordinal and e["phase"] in phases)
        text.append(report(events, ordinal))
    (args.out / "branch.txt").write_text("\n".join(text) + "\n")
    print("\n".join(text))
    if metrics:
        print(f"ratio {metrics['ratio']:.4%} insns {metrics['candidate_instructions']} exact {metrics['exact']}")


if __name__ == "__main__":
    main()
