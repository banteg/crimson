"""Dump VC6 C2 /G5 scheduling windows for one scratch (diagnostic only; no match credit).

Hooks the pinned C2's list scheduler (`schedule_instructions` 0x107374aa) through
Crimson's preserving observer (`crimson match c2-trace`): the whole COFF object must
still be identical, only extra records are written. For every window it prints the
node count toward the 81-node cap, the ending reason, and, for scheduled windows,
each node's height, priority, creation order and emitted position. See
tools/match/c2/compiler/x87-scheduling.md.

    uv run python scripts/c2/sched_trace.py tools/match/scratches/ui_element_render \
        --out /private/tmp/sched-ui [--function-ordinal N] [--lines 40-60] [--json]
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from unittest.mock import patch

from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

IMAGE_BASE = 0x10700000
# Call sites (RVA) of the pinned C2 scheduler loop; profile SHA pinned by match_c2.
FUNCTION_ENTRY = {"site": 0x581EE, "target": 0x130CB, "return": False}
EMIT_FUNCTION = {"site": 0x585B1, "target": 0x3EBEA, "return": False}
WINDOW_END = {"site": 0x37549, "target": 0x37A43, "return": True}  # sched_find_window_end
PRIORITIES = {"site": 0x37597, "target": 0x3A684, "return": True}  # sched_compute_priorities
EMIT_TUPLE = {"site": 0x3B06E, "target": 0x3B669, "return": False}  # sched_emit_tuple
LOWER = {"site": 0x58310, "target": 0x29511, "return": False}  # pass_lower_function (ecx = function)
HOOKS = [FUNCTION_ENTRY, EMIT_FUNCTION, WINDOW_END, PRIORITIES, EMIT_TUPLE, LOWER]
FLOAT_OPS = (0x16D, 0x16E, 0x16F, 0x175)  # IL add, sub, mul, div recorded at lowering entry
WINDOW_START = 0x9F268  # g_sched_window_start
SCHED_GRAPH = 0x9F240  # g_sched_graph
SCHED_CYCLE = 0x9F238  # g_sched_cycle
REG_SYMBOLS = 0xAC730  # g_reg_symbols, 0x54-byte records indexed by register number
MNEMONICS = 0xA5A90  # listing mnemonic pointers for x86 opcodes 0..0x144
ROW_WORDS = 128
OPERAND_WORDS = 12
SRC_MAX, DST_MAX = 6, 3

# C2's listing register names (0x107a9198), in g_reg_symbols order.
REGISTER_NAMES = [
    "noreg",
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "ax",
    "cx",
    "dx",
    "bx",
    "sp",
    "bp",
    "si",
    "di",
    "al",
    "cl",
    "dl",
    "bl",
    "ah",
    "ch",
    "dh",
    "bh",
    "es",
    "cs",
    "ss",
    "ds",
    "fs",
    "gs",
    "st0",
    "st1",
    "st2",
    "st3",
    "st4",
    "st5",
    "st6",
    "st7",
    "cr0",
    "cr2",
    "cr3",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr4",
    "dr5",
    "dr6",
    "dr7",
    "tr0",
    "tr1",
    "tr2",
    "tr3",
    "tr4",
    "tr5",
    "tr6",
    "tr7",
    "mm0",
    "mm1",
    "mm2",
    "mm3",
    "mm4",
    "mm5",
    "mm6",
    "mm7",
    "cc",
    "cc_soz",
    "cc_so",
    "cc_zc",
    "cc_sf",
    "cc_of",
    "cc_zf",
    "cc_cf",
    "fcc",
]
IL_NAMES = {
    0x15B: "ASSIGN",
    0x162: "FROUND",
    0x19E: "REGUSE",
    0x1AE: "LABEL",
    0x1AF: "BLOCK",
    0x1B1: "FUNC_EXIT",
    0x1B2: "SETMARK",
    0x1B4: "PROLOG_END",
    0x1B5: "EPILOG_BEGIN",
    0x1BC: "DEAD_LABEL",
}
ENDING_KINDS = {0x11: "branch", 0x13: "switch", 0x1A: "label"}

WATCH = r"""
static HANDLE sched_file;
static unsigned long sched_ordinal;
static unsigned char *sched_base;
static void sched_row(unsigned long *row) {
    DWORD written;
    if(!WriteFile(sched_file,row,ROW_WORDS*4,&written,0)||written!=ROW_WORDS*4)ExitProcess(76);
}
static void sched_operands(unsigned long *row, unsigned long at, unsigned long max, unsigned long op) {
    unsigned long k, *w, sym;
    for(k=0;op && k<max;++k,op=*(unsigned long *)op) {
        w=row+at+1+k*OPERAND_WORDS;
        w[0]=*(unsigned long *)(op+4); w[1]=*(unsigned long *)(op+8); w[2]=*(unsigned long *)(op+0xc);
        w[3]=*(unsigned long *)(op+0x10); w[4]=*(unsigned long *)(op+0x14); w[5]=*(unsigned long *)(op+0x18);
        sym=w[4];
        if(sym && (w[1]&255)>=1 && (w[1]&255)<=3){w[6]=*(unsigned long *)(sym+0x1c); w[7]=*(unsigned char *)(sym+4); w[8]=*(unsigned long *)(sym+0x28);}
        if((w[1]&255)==6){
            unsigned long b=*(unsigned long *)(op+0x28);
            w[9]=*(unsigned long *)(op+0x24);
            if(b){
                w[8]=*(unsigned long *)(b+0xc); w[10]=*(unsigned char *)(b+8);
                if(*(unsigned long *)(b+0x14)){w[10]|=*(unsigned char *)(*(unsigned long *)(b+0x14)+4)<<8; w[11]=*(unsigned long *)(*(unsigned long *)(b+0x14)+0x1c);}
            }
        }
    }
    row[at]=k;
}
static void sched_tuple(unsigned long type, unsigned long t) {
    unsigned long row[ROW_WORDS], j;
    for(j=0;j<ROW_WORDS;++j)row[j]=0;
    row[0]=type; row[1]=sched_ordinal; row[2]=t;
    row[3]=*(unsigned long *)(t+4); row[4]=*(unsigned long *)(t+8); row[5]=*(unsigned short *)(t+0x10);
    row[6]=*(unsigned long *)(t+0x14); row[7]=(unsigned long)sched_base;
    if(*(unsigned char *)(t+9)&1){
        sched_operands(row,8,SRC_MAX,*(unsigned long *)(t+0x18));
        sched_operands(row,8+1+SRC_MAX*OPERAND_WORDS,DST_MAX,*(unsigned long *)(t+0x1c));
    }
    sched_row(row);
}
static int sched_watch(unsigned long phase, unsigned long *regs) {
    unsigned long row[ROW_WORDS], j, t, end, count, graph, node, edge;
    unsigned long index = phase % 100;
    if(index==0 && phase==0){++sched_ordinal; return 0;}
    if(index==1) return 0;
    if(phase==5){
        for(t=*(unsigned long *)(**(unsigned long **)(regs[6]+8)+0x1c);t;t=*(unsigned long *)t){
            j=*(unsigned long *)(t+4);
            if(FLOAT_OP(j) && (*(unsigned short *)(t+0xa)&0xf000)==0x4000) sched_tuple(6,t);
        }
        return 1;
    }
    for(j=0;j<ROW_WORDS;++j)row[j]=0;
    row[1]=sched_ordinal;
    if(phase==100+2){
        end=regs[7]; t=*(unsigned long *)(sched_base+WINDOW_START);
        row[0]=1; row[2]=t; row[3]=end; sched_row(row);
        for(count=0;t && count<400;++count){ sched_tuple(2,t); if(t==end)break; t=*(unsigned long *)t; }
        return 1;
    }
    if(phase==100+3){
        graph=*(unsigned long *)(sched_base+SCHED_GRAPH);
        for(node=*(unsigned long *)graph,count=0;node && count<1000;node=*(unsigned long *)node,++count){
            for(j=0;j<ROW_WORDS;++j)row[j]=0;
            row[0]=3; row[1]=sched_ordinal; row[2]=node; row[3]=*(unsigned long *)(node+0x1c);
            for(j=0;j<8;++j)row[4+j]=*(unsigned long *)(node+0x20+j*4);
            sched_row(row);
            for(edge=*(unsigned long *)(node+0xc);edge;edge=*(unsigned long *)edge){
                for(j=0;j<ROW_WORDS;++j)row[j]=0;
                row[0]=4; row[1]=sched_ordinal; row[2]=*(unsigned long *)(edge+8); row[3]=*(unsigned long *)(edge+0xc);
                row[4]=*(unsigned long *)(edge+0x10); row[5]=*(unsigned long *)(edge+0x14);
                sched_row(row);
            }
            if(node==*(unsigned long *)(graph+4))break;
        }
        return 1;
    }
    if(phase==4){
        row[0]=5; row[2]=regs[6]; row[3]=*(unsigned long *)(sched_base+SCHED_CYCLE);
        sched_row(row);
        return 1;
    }
    return 1;
}
"""


def observer(profile, stock_source):
    defines = {
        "ROW_WORDS": ROW_WORDS,
        "OPERAND_WORDS": OPERAND_WORDS,
        "SRC_MAX": SRC_MAX,
        "DST_MAX": DST_MAX,
        "WINDOW_START": WINDOW_START,
        "SCHED_GRAPH": SCHED_GRAPH,
        "SCHED_CYCLE": SCHED_CYCLE,
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
    header += "#define FLOAT_OP(j) (" + "||".join(f"(j)=={op}" for op in FLOAT_OPS) + ")\n"
    source = source.replace(anchors[0], anchors[0] + "\n" + header + WATCH)
    # Only function entry (0) and final emission (1) keep stock snapshots.
    source = source.replace(anchors[1], anchors[1] + "    if (sched_watch(phase, registers)) return;\n")
    source = source.replace(
        anchors[2],
        "    sched_base = base;\n"
        '    sched_file = CreateFileA("sched.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n'
        "    if (sched_file == INVALID_HANDLE_VALUE) ExitProcess(75);\n" + anchors[2],
    )
    # Long operand chains: truncate the stock snapshot instead of aborting.
    source = source.replace("if(op) ExitProcess(98);", "")
    return source.replace(anchors[3], "    CloseHandle(sched_file);\n" + anchors[3])


def run(scratch: Path, out: Path):
    stock_source = c2.observer_source
    profile = dict(c2.load_profile(), name="msvc6.5-c2-sched", hooks=HOOKS)
    with (
        patch.object(c2, "load_profile", return_value=profile),
        patch.object(c2, "observer_source", side_effect=lambda p: observer(p, stock_source)),
    ):
        manifest = c2.trace(scratch, out)
    return manifest, (out / "observed/sched.bin").read_bytes()


def mnemonics():
    data = (replay.COMPILER / "Bin/C2.DLL").read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    table = []
    for i in range(sections):
        at = pe + 24 + optional + i * 40
        vsize, va, rsize, raw = struct.unpack_from("<4I", data, at + 8)
        table.append((va, max(vsize, rsize), raw))

    def read(rva, size):
        for va, length, raw in table:
            if va <= rva < va + length:
                return data[raw + rva - va : raw + rva - va + size]
        raise ValueError(hex(rva))

    names = []
    for op in range(0x145):
        pointer = struct.unpack("<I", read(MNEMONICS + op * 4, 4))[0]
        names.append(read(pointer - IMAGE_BASE, 16).split(b"\0")[0].decode())
    return names


def decode(data: bytes):
    rows = [struct.unpack_from(f"<{ROW_WORDS}I", data, i) for i in range(0, len(data), ROW_WORDS * 4)]
    functions: dict[int, dict] = {}
    for w in rows:
        fn = functions.setdefault(w[1], {"windows": [], "emits": [], "float_ops": []})
        if w[0] == 1:
            fn["windows"].append({"start": w[2], "end": w[3], "tuples": [], "nodes": [], "edges": []})
        elif w[0] == 2:
            fn["windows"][-1]["tuples"].append(tuple_row(w))
        elif w[0] == 3:
            win = fn["windows"][-1]
            win["nodes"].append(
                {
                    "node": w[2],
                    "tuple": w[3],
                    "preds": w[4] & 0xFFFF,
                    "out_degree": w[4] >> 16,
                    "bypassable": w[5] & 0xFFFF,
                    "priority": w[6],
                    "cur_priority": w[7],
                    "earliest": w[8],
                    "height": w[9] & 0xFFFF,
                    "seq": w[9] >> 16,
                    "latency": w[10] & 0xFF,
                    "unit_flags": (w[10] >> 8) & 0xFF,
                    "flags": (w[10] >> 16) & 0xFF,
                },
            )
        elif w[0] == 4:
            fn["windows"][-1]["edges"].append(
                {"from": w[2], "to": w[3], "kind": w[4], "latency": w[5] & 0xFFFF, "rewrite": (w[5] >> 16) & 0xFF},
            )
        elif w[0] == 6:
            fn["float_ops"].append(tuple_row(w))
        elif w[0] == 5:
            fn["emits"].append({"tuple": w[2], "cycle": w[3]})
        else:
            raise ValueError(f"Unknown record {w[0]}")
    return functions


def operands(w, at, base):
    result = []
    for k in range(w[at]):
        o = w[at + 1 + k * OPERAND_WORDS : at + 1 + (k + 1) * OPERAND_WORDS]
        storage = o[5]
        reg = None
        rel = storage - base - REG_SYMBOLS if storage else -1
        if storage and rel >= 0 and rel % 0x54 == 0 and rel // 0x54 < len(REGISTER_NAMES):
            reg = REGISTER_NAMES[rel // 0x54]
        result.append(
            {
                "opcode": o[0],
                "kind": o[1] & 0xFF,
                "type": o[1] >> 16,
                "sort_key": o[2],
                "flags10": o[3] & 0xFF,
                "flags11": (o[3] >> 8) & 0xFF,
                "sym_id": o[6],
                "sym_class": o[7],
                "frame_offset": o[8] - (1 << 32) if o[8] >= 1 << 31 and o[1] & 0xFF != 6 else o[8],
                "register": reg,
                "value": o[5],
                "disp": o[9] - (1 << 32) if o[9] >= 1 << 31 else o[9],
                "base_key": o[8] if o[1] & 0xFF == 6 else None,
                "base_kind": o[10] & 0xFF,
                "base_class": o[10] >> 8,
                "base_id": o[11],
            },
        )
    return result


def tuple_row(w):
    base = w[7]
    return {
        "ptr": w[2],
        "opcode": w[3],
        "kind": w[4] & 0xFF,
        "flags": (w[4] >> 8) & 0xFF,
        "type": w[4] >> 16,
        "line": w[5],
        "aux": w[6],
        "src": operands(w, 8, base),
        "dst": operands(w, 8 + 1 + SRC_MAX * OPERAND_WORDS, base),
    }


def render_operand(op, following):
    kind = op["kind"]
    if kind == 1:
        return op["register"] or f"t{op['sym_id']}"
    if kind == 2:
        return f"s{op['sym_id']}"
    if kind == 3:
        return f"&s{op['sym_id']}"
    if kind == 4:
        return "code"
    if kind == 6:
        parts = [o["register"] or f"t{o['sym_id']}" for o in following]
        if op["disp"] or not parts:
            parts.append(f"{op['disp']:#x}")
        return "[" + "+".join(parts) + "]"
    if kind == 7:
        return f"{op['value']:#x}"
    if kind == 9:
        return "fconst"
    return f"k{kind}"


def render_list(ops):
    out = []
    skip = 0
    for i, op in enumerate(ops):
        if skip:
            skip -= 1
            continue
        if op["kind"] == 6:
            index = [o for o in ops[i + 1 :] if o["flags10"] & 0x20][:2]
            skip = len(index)
            out.append(render_operand(op, index))
        else:
            out.append(render_operand(op, []))
    return out


def render(t, names):
    op = t["opcode"]
    name = names[op] if op < len(names) else IL_NAMES.get(op, f"il{op:#x}")
    if t["kind"] == 0x1A:
        return "LABEL"
    dst, src = render_list(t["dst"]), render_list(t["src"])
    return f"{name} {','.join(dst)}" + (f" <- {','.join(src)}" if src else "")


def ending(window):
    """Why sched_find_window_end stopped: a control tuple (included), the 81-node cap, or a marker."""
    last = window["tuples"][-1]
    if last["kind"] in ENDING_KINDS:
        return ENDING_KINDS[last["kind"]]
    counted = window["tuples"][1:] if window["tuples"][0]["opcode"] == 0x1B5 else window["tuples"]
    return "cap81" if len(counted) == 81 else "marker"


def report(fn, names, lines=None):
    emitted = {e["tuple"]: (i, e["cycle"]) for i, e in enumerate(fn["emits"])}
    out = []
    for index, win in enumerate(fn["windows"]):
        ts = win["tuples"]
        span = [t["line"] for t in ts if t["line"]]
        if lines and not any(lines[0] <= x <= lines[1] for x in span):
            continue
        by_tuple = {n["tuple"]: n for n in win["nodes"]}
        real = sum(1 for t in ts if t["opcode"] < 0x145)
        rounds = sum(1 for t in ts if t["opcode"] == 0x162)
        out.append(
            f"window {index}: {len(ts)} nodes ({real} machine, {rounds} FROUND), "
            f"lines {min(span, default=0)}-{max(span, default=0)}, "
            f"ends at {ending(win)}, {'scheduled' if win['nodes'] else 'not scheduled'}",
        )
        order = sorted(ts, key=lambda t: emitted.get(t["ptr"], (1 << 30, 0))[0]) if win["nodes"] else ts
        position = {t["ptr"]: i for i, t in enumerate(order)}
        for i, t in enumerate(ts):
            n = by_tuple.get(t["ptr"])
            meta = ""
            if n:
                cycle = emitted.get(t["ptr"], (None, None))[1]
                meta = f"seq {n['seq']:3d} h {n['height']:3d} pri {n['priority']:7d} cyc {cycle} -> {position[t['ptr']]:3d}"
            out.append(f"  {i:3d} L{t['line']:<4d} {meta:52s} {render(t, names)}")
    return "\n".join(out)


def is_x87(t, writes_only=False):
    """Machine tuple with an x87 stack register operand (every x87 value lives in ST0's symbol)."""
    ops = t["dst"] if writes_only else t["src"] + t["dst"]
    return t["opcode"] < 0x145 and any((o["register"] or "").startswith("st") for o in ops)


def x87_order_changes(fn, writes_only=False):
    """Scheduled windows whose x87 instruction order differs from the pre-schedule order."""
    emitted = {e["tuple"]: i for i, e in enumerate(fn["emits"])}
    changed = []
    for index, win in enumerate(fn["windows"]):
        if not win["nodes"]:
            continue
        before = [t["ptr"] for t in win["tuples"] if is_x87(t, writes_only)]
        if before != sorted(before, key=emitted.__getitem__):
            changed.append(index)
    return changed


CLASS_PREFIX = {1: "r", 3: "t", 4: "l", 5: "p", 7: "g"}


def describe(op):
    """Operand of a pre-lowering float op: class/id and its packed sort key."""
    kind = op["kind"]
    if kind in (1, 2, 3):
        name = CLASS_PREFIX.get(op["sym_class"], f"c{op['sym_class']}_") + f"{op['sym_id']:#x}"
        name = ("&" if kind == 3 else "") + name
    elif kind == 6:
        base = CLASS_PREFIX.get(op["base_class"], "?") + f"{op['base_id']:#x}" if op["base_kind"] else "?"
        name = f"[{base}+{op['disp']:#x}]"
    elif kind == 9:
        name = "fconst"
    else:
        name = f"k{kind}"
    return f"{name}:{op['sort_key']:#x}"


FLOAT_NAMES = {0x16D: "fadd", 0x16E: "fsub", 0x16F: "fmul", 0x175: "fdiv"}


def report_float(fn, lines=None):
    out = ["float add/sub/mul/div at lowering entry (operands in sorted order; the first is loaded):"]
    for t in fn["float_ops"]:
        if lines and not lines[0] <= t["line"] <= lines[1]:
            continue
        dst = describe(t["dst"][0]) if t["dst"] else "-"
        ops = "  ".join(describe(o) for o in t["src"] if not o["flags10"] & 0x20)
        out.append(f"  L{t['line']:<4d} {FLOAT_NAMES[t['opcode']]} {dst} <- {ops}")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the preserving trace")
    parser.add_argument("--function-ordinal", type=int, help="default: the function with the most windows")
    parser.add_argument("--lines", help="only windows touching C2 line labels A-B")
    parser.add_argument("--json", action="store_true", help="write sched.json next to the trace")
    args = parser.parse_args()
    manifest, data = run(args.scratch, args.out)
    functions = decode(data)
    ordinal = args.function_ordinal
    if ordinal is None:
        ordinal = max(functions, key=lambda k: len(functions[k]["windows"]))
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    text = report(functions[ordinal], mnemonics(), lines) + "\n" + report_float(functions[ordinal], lines)
    fn = functions[ordinal]
    text += (
        f"\nx87 order changed by the scheduler: ST-writing tuples in windows "
        f"{x87_order_changes(fn, writes_only=True) or 'none'}; any x87 tuple in {x87_order_changes(fn) or 'none'}"
    )
    (args.out / "sched.txt").write_text(text + "\n")
    if args.json:
        (args.out / "sched.json").write_text(json.dumps(functions[ordinal]) + "\n")
    metrics = manifest["metrics"]
    print(text)
    print(f"ratio {metrics['ratio']:.4%} exact {metrics['exact']} body_byte_exact {metrics['body_byte_exact']}")


if __name__ == "__main__":
    main()
