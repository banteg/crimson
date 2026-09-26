"""List every VC6 C2 CSE slot (pool E, class 15) in creation order, with what created it (diagnostic only).

Value numbering gives each distinct expression a symbol record from pool E through `cse_insert` 0x10707e22 ->
0x10707ebc -> `symbol_alloc(0xf)`. The ids are C0 + n in creation order and are never freed or reused, so n
decides the hash of every CSE temporary (`id << 6` for a symbol leaf, `(id & 3) << 14` in a load leaf's hash;
sib-operand-order.md). This tool traces one snail scratch or overlay through Crimson's preserving observer and
prints, for each pool-E slot:

    n, id, id & 3, the expression opcode (0x14c address, 0x15b assignment, 0x17d compare, ...), its key
    operands, the tuple (C2 line label and opcode) that value numbering was visiting, the creating call chain,
    and whether the id is still referenced by the IL at the address pass (the "IL" column).

For an 0x14c address slot the key is (base symbol, #alias class of the memory operand). `--upto ID` stops the
listing at a slot id; `--lines A-B` keeps only slots created while visiting those line labels; `--sums` also
prints sib_operand_trace's address sums. The matcher result (and the encoded SIB swaps at 100%) closes the report.

`--phantom K:M[,K:M]` is an intervention, not an observation: it re-runs the traced compile with M extra pool-E
ids burned before fresh slot K and matches that object instead. It answers "would the listing be native if
these slots moved by M?" without touching the source (the preserving trace itself is unchanged).

Run it from the snail-mail checkout, which provides the `snail` package:

    uv run python ../crimson/scripts/c2/cse_slot_trace.py <snail-scratch> --out <new-dir> [--source overlay.cpp]

See tools/match/c2/compiler/cse-slot-count.md.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from snail import match as m

SNAIL = Path(m.__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(SNAIL / "tools/match/c2"), str(HERE)]

import addrorder as ao
import rotation as rot
import sib_operand_trace as sot

EXPR_OPERAND_SCRATCH = 0x99620  # g_expr_operand_scratch: the key operands of the expression being hashed

# Hook kinds, decoded in C by `slot_observe`.
PASS, SYMBOL_ALLOC, CSE_ALLOC, TUPLE_ESI, MEMOP_ESI_EDI, TUPLE_ECX = range(6)

CSE_ALLOC_HOOK = {"site": 0x7E51, "target": 0x7EBC, "return": True, "kind": CSE_ALLOC}
# assign_expression_owners 0x10711209: esi is the tuple being numbered at every call.
OWNER_SITES = {
    0x1124B: ("src address", 0x7F1B, MEMOP_ESI_EDI),
    0x1128C: ("dst address", 0x7F1B, MEMOP_ESI_EDI),
    0x11516: ("copy 0x165", 0x817C, TUPLE_ESI),
    0x115D7: ("pure expr", 0x817C, TUPLE_ESI),
    0x11328: ("intrinsic", 0x69C51, TUPLE_ESI),
    0x11431: ("0x18f expr", 0x7F7D, TUPLE_ESI),
    0x11555: ("compare", 0x10CFE, TUPLE_ESI),
    0x11671: ("assignment", 0x8C14, TUPLE_ECX),
}
# The other callers of number_assignment 0x10708c14 (tuple in ecx at each call).
NUMBER_ASSIGNMENT_SITES = (
    0xA6E9,
    0xAA90,
    0xB7F7,
    0xB98C,
    0x10AA4,
    0x10B9A,
    0x431D1,
    0x45F66,
    0x47C86,
    0x48B83,
    0x4C33C,
)

OPCODES = {0x14C: "addr", 0x15B: "assign", 0x17D: "cmp", 0x16D: "add", 0x16E: "sub", 0x16F: "mul", 0x15F: "cvt"}

RECORD_WORDS = 40
RECORDER = r"""
static HANDLE slot_file;
static unsigned long slot_kind[HOOK_COUNT] = {KINDS};
static int readable(unsigned long p) { return p >= 0x10000 && p < 0x80000000; }
static long fresh = -1, phantom_at[] = {PHANTOM_AT}, phantom_count[] = {PHANTOM_COUNT};
static void slot_observe(unsigned long phase, unsigned long *registers)
{
    unsigned long rec[40], i, n, base = targets[0] - FIRST_TARGET, kind = slot_kind[phase % 100], p, q, *key;
    unsigned long allocator = base + ALLOCATOR_RVA;
    DWORD written;
    if (phase == 1000) fresh = 0;
    if (kind == 2 && phase < 100 && fresh >= 0) {
        /* Intervention (--phantom only): burn pool-E ids before the fresh slot number PHANTOM_AT. */
        for (n = 0; n < sizeof(phantom_at) / sizeof(phantom_at[0]); ++n)
            if (fresh == phantom_at[n]) for (i = 0; i < phantom_count[n]; ++i) __asm { mov ecx, 0xf
                                                                                     call allocator }
        ++fresh;
    }
    for (i = 0; i < 40; ++i) rec[i] = 0;
    rec[0] = phase;
    for (i = 0; i < 8; ++i) rec[1 + i] = registers[i];
    if (kind == 1 || kind == 2) {
        if (phase >= 100) {
            p = registers[7];
            if (readable(p)) { rec[9] = *(unsigned long *)(p + 0x1c); rec[10] = *(unsigned char *)(p + 4); }
        } else if (kind == 2) {
            rec[9] = registers[4]; rec[10] = registers[6];
            key = (unsigned long *)(base + EXPR_SCRATCH);
            for (i = 0; i < 3 && key[i]; ++i) {
                p = key[i];
                rec[11 + i * 6] = *(unsigned char *)(p + 8);
                rec[12 + i * 6] = *(unsigned long *)(p + 0x14);
                rec[13 + i * 6] = *(unsigned long *)(p + 0x18);
                q = *(unsigned long *)(p + 0x14);
                if (readable(q)) { rec[14 + i * 6] = *(unsigned long *)(q + 0x1c); rec[15 + i * 6] = *(unsigned char *)(q + 4); }
                q = *(unsigned long *)(p + 0x28);
                if (*(unsigned char *)(p + 8) >= 5 && *(unsigned char *)(p + 8) <= 6 && readable(q) && readable(*(unsigned long *)(q + 0x14)))
                    rec[16 + i * 6] = *(unsigned long *)(*(unsigned long *)(q + 0x14) + 0x1c);
            }
            for (i = 9, n = 0; i < 9 + 96 && n < 10; ++i)
                if (registers[i] >= base + 0x1000 && registers[i] < base + 0x92000) rec[29 + n++] = registers[i] - base;
        }
    } else if (kind >= 3) {
        p = kind == 5 ? registers[6] : registers[1];
        if (readable(p)) { rec[9] = *(unsigned short *)(p + 0x10); rec[10] = *(unsigned long *)(p + 4); rec[11] = *(unsigned char *)(p + 8); rec[12] = p; }
        p = registers[0];
        if (kind == 4 && readable(p)) {
            rec[13] = *(unsigned long *)(p + 0x1c);
            q = *(unsigned long *)(p + 0x28);
            if (readable(q)) {
                rec[14] = *(unsigned char *)(q + 8);
                q = *(unsigned long *)(q + 0x14);
                if (readable(q)) { rec[15] = *(unsigned long *)(q + 0x1c); rec[16] = *(unsigned char *)(q + 4); }
            }
        }
    }
    if (!WriteFile(slot_file, rec, sizeof(rec), &written, 0) || written != sizeof(rec))
        ExitProcess(74);
}
"""


def hooks() -> list[dict]:
    rows = [dict(ao.FUNCTION_ENTRY_HOOK, kind=PASS), dict(ao.ADDRESS_PASS_HOOK, kind=PASS)]
    rows += [{"site": s, "target": ao.ALLOCATOR, "return": True, "kind": SYMBOL_ALLOC} for s in ao.ALLOCATOR_SITES]
    rows.append(CSE_ALLOC_HOOK)
    rows += [{"site": s, "target": t, "return": False, "kind": k} for s, (_, t, k) in OWNER_SITES.items()]
    rows += [{"site": s, "target": 0x8C14, "return": False, "kind": TUPLE_ECX} for s in NUMBER_ASSIGNMENT_SITES]
    return rows


def observer(profile, stock_source, kinds, phantom=((-1, 0),)):
    source = stock_source(profile)
    if source.count(ao.STOCK_CAPTURE) != 1:
        raise ValueError("Unexpected Crimson observer template near the operand capture")
    source = source.replace(ao.STOCK_CAPTURE, ao.STOCK_CAPTURE + ao.SYMBOL_CAPTURE)
    anchors = (
        "    unsigned long first, node, count = 0, record[742], op, side, j, k, at;\n",
        "    trace_file = CreateFileA(",
        "    CloseHandle(trace_file);",
        "static void __cdecl observe(",
    )
    for anchor in anchors:
        if source.count(anchor) != 1:
            raise ValueError(f"Unexpected Crimson observer template near {anchor!r}")
    source = source.replace("if(op) ExitProcess(98);", "")
    recorder = RECORDER.replace("{KINDS}", "{" + ",".join(map(str, kinds)) + "}")
    recorder = recorder.replace("EXPR_SCRATCH", str(EXPR_OPERAND_SCRATCH))
    recorder = recorder.replace("FIRST_TARGET", str(profile["hooks"][0]["target"]))
    recorder = recorder.replace("ALLOCATOR_RVA", str(ao.ALLOCATOR))
    recorder = recorder.replace("PHANTOM_AT", ",".join(str(at) for at, _ in phantom))
    recorder = recorder.replace("PHANTOM_COUNT", ",".join(str(count) for _, count in phantom))
    source = source.replace(anchors[3], recorder + anchors[3])
    source = source.replace(
        anchors[0],
        anchors[0] + "    if (phase % 100 >= 2) { slot_observe(phase, registers); return; }\n"
        "    slot_observe(phase + 1000, registers);\n",
    )
    source = source.replace(
        anchors[1],
        '    slot_file = CreateFileA("slots.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        "    if (slot_file == INVALID_HANDLE_VALUE) ExitProcess(73);\n" + anchors[1],
    )
    return source.replace(anchors[2], "    CloseHandle(slot_file);\n" + anchors[2])


def run_observer(scratch: Path, out: Path):
    stock_profile, stock_source = ao.c2.load_profile, ao.c2.observer_source
    table = hooks()
    profile = stock_profile()
    profile = dict(
        profile,
        name=profile["name"] + "-cse-slots",
        hooks=[{k: h[k] for k in ("site", "target", "return")} for h in table],
    )
    ao.c2.load_profile = lambda: profile
    ao.c2.observer_source = lambda p: observer(p, stock_source, [h["kind"] for h in table])
    try:
        result, events = ao.t.trace(scratch, out)
    finally:
        ao.c2.load_profile, ao.c2.observer_source = stock_profile, stock_source
    words = struct.iter_unpack(f"<{RECORD_WORDS}I", (out / "observed/slots.bin").read_bytes())
    return result, events, table, list(words)


def run_phantom(out: Path, phantom: list[tuple[int, int]]) -> Path:
    """Re-run the traced compile with `count` extra pool-E ids burned before fresh slot `at`, per (at, count).

    This modifies a compiler decision on purpose, so it is not a preserving trace: it reuses the verified
    replay inputs of `out` and returns the resulting object for the matcher.
    """
    table = hooks()
    profile = ao.c2.load_profile()
    profile = dict(profile, hooks=[{k: h[k] for k in ("site", "target", "return")} for h in table])
    work = out / ("phantom-" + "-".join(f"{at}_{count}" for at, count in phantom))
    work.mkdir()
    (work / "replay_settings.h").write_bytes((out / "observed/replay_settings.h").read_bytes())
    (work / "observer.c").write_text(observer(profile, ao.c2.observer_source, [h["kind"] for h in table], phantom))
    replay = ao.c2.replay
    with ao.c2.compiler_environment():
        replay.compile_driver(work, "observer.c", "observer.obj")
        replay.link(work, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], work)
    return work / "replay.obj"


def decode(table: list[dict], records: list[tuple]) -> list[dict]:
    """Pool-E slots in creation order, with the owner-pass context that was current."""
    slots, pending, context, entered = [], None, None, False
    for rec in records:
        phase = rec[0]
        if phase >= 1000:
            entered = entered or phase == 1000
            continue
        index = phase % 100
        kind = table[index]["kind"]
        if kind in (TUPLE_ESI, MEMOP_ESI_EDI, TUPLE_ECX):
            site = table[index]["site"]
            what = OWNER_SITES.get(site, ("number_assignment",))[0]
            context = {"site": site, "what": what, "line": rec[9], "op": rec[10], "tuple": rec[12]}
            if kind == MEMOP_ESI_EDI:
                context |= {"alias": rec[13], "base": rec[15], "base_class": rec[16]}
            continue
        if kind != CSE_ALLOC:
            continue
        if phase < 100:
            keys = []
            for i in range(3):
                okind, _, value, ident, klass, mbase = rec[11 + i * 6 : 17 + i * 6]
                if okind:
                    keys.append({"kind": okind, "value": value, "id": ident, "class": klass, "mem_base": mbase})
            pending = {"op": rec[9], "type": rec[10] & 0xFFFF, "keys": keys, "chain": [r for r in rec[29:] if r]}
            continue
        slots.append(pending | {"id": rec[9], "context": context, "after_entry": entered})
        pending = None
    return [s for s in slots if s["after_entry"]]


def referenced_ids(event: dict) -> set[int]:
    ids = set()
    for node in event["nodes"]:
        for side in ("src", "dst"):
            for operand in node[side]:
                words = operand["temp_words"]
                if operand["kind"] in ao.SYMBOL_KINDS:
                    ids.add(words[7])
                elif operand["kind"] == 6 and words[9] in ao.SYMBOL_KINDS:
                    ids.add(words[12])
    return ids


def key_text(key: dict) -> str:
    kind = key["kind"]
    if kind == 7:
        value = key["value"]
        return f"#{value - (1 << 32) if value & 0x80000000 else value:#x}"
    name = ao.CLASSES.get(key["class"], f"c{key['class']}")
    if kind in (5, 6):
        return f"[{name} {key['id']:#x}]" if key["id"] else f"[.. base {key['mem_base']:#x}]"
    return f"{name} {key['id']:#x}" if key["id"] else f"k{kind}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", help="snail scratch name or directory")
    parser.add_argument("--source", type=Path, help="overlay source replacing scratch.cpp")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--upto", type=lambda s: int(s, 0), help="stop after this slot id")
    parser.add_argument("--lines", help="only slots created while numbering line labels A-B")
    parser.add_argument("--sums", action="store_true", help="also print sib_operand_trace address sums")
    parser.add_argument(
        "--phantom",
        help="K:M[,K:M] - intervention: burn M extra pool-E ids before fresh slot K; match that object instead",
    )
    args = parser.parse_args()
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    scratch = Path(args.scratch)
    if not scratch.is_dir():
        scratch = m.DEFAULT_MATCH_ROOT / "scratches" / args.scratch
    work = rot.prepare(scratch, args.source, args.out.parent / (args.out.name + "-input"))
    result, events, table, records = run_observer(work, args.out)
    slots = decode(table, records)
    (event,) = [e for e in events if e["target_rva"] == ao.ADDRESS_PASS_HOOK["target"]]
    live = referenced_ids(event)
    print(f"metrics: {result['metrics']}")
    c0 = slots[0]["id"] if slots else None
    print(f"C0 (first CSE slot): {c0:#x}" if slots else "C0: none")
    print("  n    id    &3 op      keys                                  IL  context (line label, tuple op, visit)")
    for n, slot in enumerate(slots):
        ctx = slot["context"] or {}
        if lines and not lines[0] <= ctx.get("line", -1) <= lines[1]:
            continue
        op = OPCODES.get(slot["op"], f"{slot['op']:#x}")
        keys = " ".join(key_text(k) for k in slot["keys"])
        chain = " ".join(f"{r:#x}" for r in slot["chain"][:4])
        where = f"ln{ctx.get('line', 0):<4} op {ctx.get('op', 0):#x} {ctx.get('what', '?')}" if ctx else "?"
        mark = "IL" if slot["id"] in live else "--"
        print(
            f"{n:3} {slot['id']:#6x} {slot['id'] & 3:3} {op:7} {keys:38} {mark}  {where}  "
            f"type {slot['type']:#06x}  via {chain}",
        )
        if args.upto is not None and slot["id"] >= args.upto:
            break
    config = m.load_scratch_config(work)
    manifest = m.load_function_symbol_manifest(m.DEFAULT_FUNCTION_SYMBOL_MANIFEST_PATH)
    obj = m.compile_scratch(config)
    if args.phantom:
        phantom = [tuple(int(x, 0) for x in item.split(":")) for item in args.phantom.split(",")]
        obj = run_phantom(args.out, phantom)
        burned = ", ".join(f"{count} before fresh slot {at}" for at, count in phantom)
        print(f"phantom: extra pool-E ids {burned} (compiler decision modified)")
    match = m.run_match(
        obj_path=obj,
        function_name=config.function,
        end_va=config.end_va,
        symbol_name=config.symbol,
        manifest=manifest,
        image_path=m.REPO_ROOT / manifest.primary_target,
    )
    print(f"match: {match.ratio:.4%} exact={match.exact}")
    if match.ratio == 1.0:
        rows = ao.sib_differences(match)
        swaps = [d for d in rows if d["swapped"]]
        print(
            f"encoded differences: {len(rows)}, SIB swaps: {len(swaps)}  "
            + " ".join(f"+{d['offset']:#x}" for d in swaps),
        )
        for d in rows:
            if not d["swapped"]:
                print(f"  other +{d['offset']:#x} target {d['target_asm']}  candidate {d['candidate_asm']}")
    if args.sums:
        creation = {s["id"]: n for n, s in enumerate(slots)}
        for row in sot.address_sums(event, creation):
            access = ",".join(f"{use}{disp:+#x}" if disp else use for disp, use in row["accesses"])
            print(f"ln{row['label']:<4} {access}  " + "  ".join(f"{o['key']:#x} {o['text']}" for o in row["operands"]))


if __name__ == "__main__":
    main()
