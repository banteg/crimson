"""Profile the id-ordered decisions of one function, and which id native needs at each (VC6 C2, diagnostic only).

Operand orders in VC6 `/O2` output are often keyed by C2's own per-function symbol counters, not by frontend ids
(tu-prelude.md). This tool lists every such decision in one compile, names the counter that decides it, and tests
by intervention whether our order or the reversed one is native. See tools/match/c2/compiler/pu-id-delta-profile.md.

Where the ids come from (all pools share the 32-id chunk counter; symbol_alloc 0x107017eb, class in ecx):

- **pool E** (class 15): value-numbering owners and CSE temporaries, `C0 + n` in creation order, never recycled
  (cse-slot-count.md). A field leaf `[owner+0]` sorts by `owner & 3`; a temporary leaf by `(id << 6) & 0xffff`,
  so `id mod 1024`, which moves with C0 in steps of 32.
- **pool B** (classes 4/5): named locals and aggregate parts at first IL reference, inline formal copies from a LIFO
  free list. A local leaf sorts by `id << 5` (creation order; above 0x800 the hash wraps mod 2048), a memory leaf
  through a local base by `(id & 7) << 13`. A new pool-B chunk starts at the shared counter's current value.
- **squares** `t * t` hash `3 * H(t) + 0x2a`; their order is the squared symbols' ids (x87-scheduling.md section 5).

What it does:

1. **Trace** (preserving `crimson match c2-trace`): hooks on the post-globopt commutative sort (0x1070da8d ->
   merge_sort_operand_list), every symbol_alloc call site, the value-numbering walk and
   assign_symbol_alias_classes. Every adjacent pair of a sorted node whose need and size tie is decided by the
   16-bit hash; the tool names the deciding id, re-derives both keys (and fails if the model disagrees), and lists
   the residues (or, for squares, the id windows) at which the pair would reverse.
2. **Probe** (`--probe`, interventions, never match credit): per deciding id, one compile per residue class that
   reverses something:
   - pool E: M ids burned right before that slot and the complement (to 4 or 1024) right after it, so only that
     id's residue moves (`n:M,n+1:4-M`), as in cse_slot_trace --phantom;
   - pool B: its leaves re-keyed as if it had another id (burning class-4 records crashes C2);
   - creation-order and square pairs: that one node's pair swapped by key.
   Each object is matched. The verdict comes first from a data-flow window (stack reads renamed by the value their
   reaching store wrote, so a swap of two `[esp+x]` operands becomes visible) and otherwise from the masked ratios.
3. The report and `--csv` give, per site: counter, id, residue, source line, pairs, reversing residues and nearest
   shifts, probe scores (raw, labels, structural, stack, refs, data-flow delta) and the verdict.

    uv run python scripts/c2/id_delta_profile.py <scratch-dir> --out <new-dir> [--ties] [--probe] [--jobs 8] \
        [--pools E,B,O] [--limit N] [--csv sites.csv]
    uv run python scripts/c2/id_delta_profile.py <scratch-dir> --out <existing-dir> \
        --phantom E:K:M[,O:ID:NEW[:NODE]][,K:NODE:OLDKEY:NEWKEY]

`--out` is reused when it already holds a trace. `--phantom` runs one intervention on it and prints the scores, the
sort nodes that changed and the candidate diff.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import frame_predict as fp
import iv_trace as iv
import residual_map as rm

from crimson import match as m
from crimson import match_c2 as c2

BASE = 0x10700000
ALLOCATOR = 0x17EB  # symbol_alloc (class in ecx)
ALLOCATOR_SITES = (0x2AFA, 0x7EC1, 0x10038, 0x3C34, 0x1DB6B, 0x1BA48)
CUR_FUNC_SYM = 0xAC378
ALIAS_CLASS_COUNT = 0x9D670
# (call site RVA, callee RVA, return hook, mode)
EXTRA_HOOKS = (
    (0x1070DA8D - BASE, 0x1070F584 - BASE, True, 5),  # compute_tree_cost_and_sort -> merge_sort_operand_list
    *((site, ALLOCATOR, True, 7) for site in ALLOCATOR_SITES),
    (0x1124B, 0x7F1B, False, 8),  # assign_expression_owners: src address (esi = tuple)
    (0x1128C, 0x7F1B, False, 8),  # dst address
    (0x11516, 0x817C, False, 8),  # copy 0x165
    (0x115D7, 0x817C, False, 8),  # pure expression
    (0x11328, 0x69C51, False, 8),  # intrinsic
    (0x11431, 0x7F7D, False, 8),  # 0x18f expression
    (0x11555, 0x10CFE, False, 8),  # compare
    (0x11671, 0x8C14, False, 9),  # number_assignment (ecx = tuple)
    (0x580FA, 0x180FD, False, 10),  # function_prepare_temps: the reader is done
    (0x1888B, 0x181A8, False, 11),  # inline_expand_calls recursion
    (0x18F1F, 0x1921C, True, 12),  # assign_symbol_alias_classes
)
STOCK_GLOB, STOCK_PURGE, STOCK_LAST = 0, 1, 11

BODY = r"""
static unsigned long compiler_base, ordinal, after_glob, after_purge, fresh_e, pending[HOOK_COUNT];
static long ph_e_at[] = {PH_E_AT}, ph_e_cnt[] = {PH_E_CNT};
static unsigned long ov_id[] = {OV_ID}, ov_new[] = {OV_NEW}, sort_seq;
static long ov_node[] = {OV_NODE}, kw_node[] = {KW_NODE};
static unsigned long kw_old[] = {KW_OLD}, kw_new[] = {KW_NEW};
static unsigned long H(unsigned long id, unsigned long cls)
{
    unsigned long v;
    if (cls == 3) return (id << 6) & 0xffff;
    v = (id >> 16) ^ (id & 0xffff);
    return (((v & 0x7ff) << 5) ^ ((v << 5) >> 16)) & 0xffff;
}
static unsigned char B(unsigned long p, unsigned long o) { return *(unsigned char *)(p + o); }
static void name_of(unsigned long y)
{
    unsigned long fe = W(y, 0), name, k;
    if (!fe || B(fe, 4) != 1 || !(name = W(fe, 0x18))) return;
    s("'");
    for (k = 0; k < 40 && *(char *)(name + k) > 32 && *(char *)(name + k) < 127; ++k) ch(*(char *)(name + k));
}
static void symid(unsigned long y)
{
    if (!y) { s("0"); return; }
    dec(W(y, 0x1c)); s("c"); dec(B(y, 4));
    if (W(y, 8) && W(y, 8) != y) { s("^"); dec(W(W(y, 8), 0x1c)); s("+"); dec((long)W(y, 0x24)); }
    name_of(y);
}
static void opnd(unsigned long p)
{
    unsigned long kind = B(p, 8), b;
    s(" "); hx(W(p, 0xc)); s(":"); dec(kind); s(":");
    if (kind >= 1 && kind <= 4) symid(W(p, 0x14));
    else if (kind == 5 || kind == 6) {
        s("m"); dec((long)W(p, 0x20));
        if ((b = W(p, 0x28)) != 0) { s("b"); symid(W(b, 0x14)); }
        if ((b = W(p, 0x2c)) != 0) { s("i"); symid(W(b, 0x14)); }
    } else if (kind == 7) { s("="); dec((long)W(p, 0x18)); }
    else { s("t"); hx(W(p, 0x18)); }
}
static void burn(unsigned long cls, long count)
{
    unsigned long allocator = compiler_base + ALLOCATOR_RVA, klass = cls, y;
    long i;
    for (i = 0; i < count; ++i) {
        __asm {
            mov ecx, klass
            call allocator
            mov y, eax
        }
        s("X "); dec(cls); s(" "); dec(W(y, 0x1c)); s("\n");
    }
}
/* Intervention: re-key the leaves of one symbol as if it had another id (post-globopt sort only). */
static void override(unsigned long p)
{
    unsigned long k, n, y, key, fold, old;
    for (k = 0; p && k < 32; ++k, p = W(p, 0)) {
        key = W(p, 0xc);
        for (n = 0; n < sizeof(kw_node) / sizeof(kw_node[0]); ++n)
            if (kw_node[n] == (long)sort_seq && key == kw_old[n]) {
                *(unsigned long *)(p + 0xc) = kw_new[n];
                s("K "); dec(sort_seq); s(" "); hx(key); s(" "); hx(kw_new[n]); s("\n");
            }
        if (key >> 16 != 1) continue;
        if (B(p, 8) == 2) y = W(p, 0x14);
        else if ((B(p, 8) == 5 || B(p, 8) == 6) && W(p, 0x28) && !W(p, 0x2c)) y = W(W(p, 0x28), 0x14);
        else continue;
        if (!y) continue;
        for (n = 0; n < sizeof(ov_id) / sizeof(ov_id[0]); ++n) {
            if (W(y, 0x1c) != ov_id[n] || (ov_node[n] >= 0 && ov_node[n] != (long)sort_seq)) continue;
            old = H(ov_id[n], B(y, 4));
            if (B(p, 8) == 2) key = 0x10000 | H(ov_new[n], B(y, 4));
            else {
                fold = (key - 7 - (old << 8)) & 0xffff;
                key = 0x10000 | ((fold + 7 + (H(ov_new[n], B(y, 4)) << 8)) & 0xffff);
            }
            *(unsigned long *)(p + 0xc) = key;
            s("O "); dec(ov_id[n]); s(" "); hx(key); s("\n");
        }
    }
}
static void __cdecl observe(unsigned long phase, unsigned long *r)
{
    unsigned long index = phase >= 100 ? phase - 100 : phase, mode = modes[index], p, k, n, cls, y;
    if (phase < 12) saved_function = r[6];
    if (phase == STOCK_GLOB) {
        after_glob = 1; after_purge = 0; fresh_e = 0;
        y = W(compiler_base, CUR_FUNC_SYM);
        s("F "); dec(ordinal); s(" "); if (y) symid(y); s("\n");
    } else if (phase == STOCK_PURGE) { after_purge = 1; s("P\n"); }
    else if (phase == STOCK_LAST) { s("E "); dec(ordinal); s("\n"); ++ordinal; after_glob = 0; }
    if (mode == 5 && phase < 100 && after_purge && ordinal == PH_ORDINAL && (ov_id[0] || kw_node[0] >= 0)) override(r[6]);
    if (mode == 5 && phase >= 100 && after_purge) {
        p = r[7];
        s("S "); hx(r[4]); s(" "); hx(W(r[4], 4) & 0xffff); s(" "); dec(*(unsigned short *)(r[4] + 0x10));
        for (k = 0; p && k < 32; ++k, p = W(p, 0)) opnd(p);
        s("\n");
        ++sort_seq;
    } else if (mode == 7 && phase < 100) {
        cls = r[6] & 0xff;
        pending[index] = cls;
        if (ordinal == PH_ORDINAL && cls == 15 && after_glob) {
            for (n = 0; n < sizeof(ph_e_at) / sizeof(ph_e_at[0]); ++n)
                if ((long)fresh_e == ph_e_at[n]) burn(15, ph_e_cnt[n]);
            ++fresh_e;
        }
    } else if (mode == 7) {
        s("A "); dec(index); s(" "); dec(pending[index]); s(" "); dec(r[7] ? W(r[7], 0x1c) : 0); s("\n");
    } else if (mode == 8 || mode == 9) {
        p = mode == 8 ? r[1] : r[6];
        s("V "); dec(*(unsigned short *)(p + 0x10)); s(" "); hx(W(p, 4) & 0xffff); s("\n");
    } else if (mode == 10) s("R\n");
    else if (mode == 11) s("I\n");
    else if (mode == 12 && phase >= 100) { s("C "); dec(W(compiler_base, ALIAS_CLASS_COUNT)); s("\n"); }
    flush();
}
"""


def observer(profile: dict, phantom: dict | None = None, ordinal: int = 0) -> str:
    """The iv_trace observer with this tool's observe().

    phantom: {"E": [(slot, count)], "O": [(id, new id, node or -1)], "K": [(node, old key, new key)]}.
    """
    phantom = phantom or {}
    source = iv.OBSERVER
    head, rest = source.split("static void __cdecl observe(", 1)
    tail = rest[rest.index("/* GENERATED_HOOKS */") :]
    pairs = phantom.get("E") or [(-1, 0)]
    body = BODY.replace("PH_E_AT", ",".join(str(k) for k, _ in pairs))
    body = body.replace("PH_E_CNT", ",".join(str(c) for _, c in pairs))
    triples = [(o + (-1,))[:3] for o in phantom.get("O") or [(0, 0)]]
    body = body.replace("OV_ID", ",".join(str(a) for a, _, _ in triples))
    body = body.replace("OV_NEW", ",".join(str(b) for _, b, _ in triples))
    body = body.replace("OV_NODE", ",".join(str(c) for _, _, c in triples))
    swaps = phantom.get("K") or [(-1, 0, 0)]
    body = body.replace("KW_NODE", ",".join(str(a) for a, _, _ in swaps))
    body = body.replace("KW_OLD", ",".join(str(b) for _, b, _ in swaps))
    body = body.replace("KW_NEW", ",".join(str(c) for _, _, c in swaps))
    body = body.replace("PH_ORDINAL", str(ordinal)).replace("ALLOCATOR_RVA", str(ALLOCATOR))
    body = body.replace("CUR_FUNC_SYM", str(CUR_FUNC_SYM)).replace("ALIAS_CLASS_COUNT", str(ALIAS_CLASS_COUNT))
    body = body.replace("STOCK_GLOB", str(STOCK_GLOB)).replace("STOCK_PURGE", str(STOCK_PURGE))
    body = body.replace("STOCK_LAST", str(STOCK_LAST))
    text = head + body + tail
    text = text.replace(
        "    base = (unsigned char *)invoke - INVOKE_RVA;\n",
        "    base = (unsigned char *)invoke - INVOKE_RVA;\n    compiler_base = (unsigned long)base;\n",
    )
    stock = iv.STOCK_OBSERVER_SOURCE(profile)
    wrappers = stock[stock.index("__declspec(naked)") : stock.index("void __stdcall start")]
    header = stock[: stock.index("#include")]
    modes = "static unsigned long modes[] = {" + ",".join(str(h["mode"]) for h in profile["hooks"]) + "};\n"
    text = text.replace("/* GENERATED_HOOKS */", wrappers)
    return header + text.replace("static char buf[65536];", modes + "static char buf[65536];")


def profile() -> dict:
    stock = c2.load_profile()
    hooks = [dict(h, mode=0, name=f"pass@{h['target'] + BASE:#x}") for h in stock["hooks"][:12]]
    hooks += [
        {"site": site, "target": target, "return": ret, "mode": mode, "name": f"m{mode}@{site:#x}"}
        for site, target, ret, mode in EXTRA_HOOKS
    ]
    return {**stock, "name": stock["name"] + "-id-delta", "hooks": hooks}


def decode(data: bytes, _profile=None) -> list[str]:
    text = data.decode("latin-1")
    if not text.startswith("C2IVTRACE"):
        raise ValueError("Not an id-delta trace")
    return text.splitlines()[1:]


def trace(scratch: Path, out: Path) -> dict:
    prof = profile()
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: prof
    c2.observer_source = lambda p: observer(p)
    c2.decode_trace = decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


# ---------------------------------------------------------------- parsing

OPND = re.compile(r" ([0-9a-f]+):(\d+):(\S+)")
SYM = re.compile(r"(\d+)c(\d+)(?:\^(\d+)\+(-?\d+))?(?:'(\S+))?")


def parse_sym(text: str) -> dict | None:
    mt = SYM.fullmatch(text)
    if not mt:
        return None
    return {
        "id": int(mt.group(1)),
        "cls": int(mt.group(2)),
        "parent": int(mt.group(3)) if mt.group(3) else None,
        "off": int(mt.group(4)) if mt.group(4) else 0,
        "name": mt.group(5) or "",
    }


def parse_operand(key: str, kind: str, body: str) -> dict:
    op = {"key": int(key, 16), "kind": int(kind), "text": body}
    if op["kind"] in (1, 2, 3, 4):
        op["sym"] = parse_sym(body)
    elif op["kind"] in (5, 6):
        mt = re.fullmatch(r"m(-?\d+)(?:b(\S+?))?(?:i(\S+))?", body)
        if mt:
            op["disp"] = int(mt.group(1))
            op["base"] = parse_sym(mt.group(2)) if mt.group(2) else None
            op["index"] = parse_sym(mt.group(3)) if mt.group(3) else None
    elif body.startswith("t"):
        op["tuple"] = body[1:]
    return op


class Trace:
    """One compile's records for the function with the given ordinal."""

    def __init__(self, lines: list[str], ordinal: int | None = None):
        self.functions: list[str] = []
        self.sorts: dict[str, dict] = {}
        self.order: list[str] = []
        self.pool_e: list[dict] = []
        self.pool_b: list[dict] = []
        self.burns: list[tuple[int, int]] = []
        self.alias = None
        current, vn, stage = 0, None, "reader"
        for line in lines:
            tag, _, rest = line.partition(" ")
            if tag == "F":
                self.functions.append(rest.split(maxsplit=1)[1] if " " in rest else "")
                stage = "globopt"
                continue
            if tag == "E":
                current, stage, vn = current + 1, "reader", None
                continue
            owner = ordinal is None or current == ordinal
            if tag == "R":
                stage = "inline"
            elif tag == "V":
                vn = rest
            elif tag == "X" and owner:
                cls, ident = map(int, rest.split())
                self.burns.append((cls, ident))
            elif tag == "A" and owner:
                _hook, cls, ident = map(int, rest.split())
                if cls == 15 and stage != "reader":
                    self.pool_e.append({"n": len(self.pool_e), "id": ident, "vn": vn})
                elif cls in (4, 5):
                    self.pool_b.append({"k": len(self.pool_b), "id": ident, "cls": cls, "stage": stage})
            elif tag == "C" and owner:
                self.alias = int(rest)
            elif tag == "S" and owner:
                node, op, ln, *_ = rest.split(" ", 3)
                ops = [parse_operand(*mt.groups()) for mt in OPND.finditer(" " + rest.split(" ", 3)[3])]
                if node not in self.sorts:
                    self.order.append(node)
                self.sorts[node] = {"node": node, "op": op, "ln": int(ln), "ops": ops}
        self.c0 = self.pool_e[0]["id"] if self.pool_e else None
        self.e_index = {e["id"]: e["n"] for e in self.pool_e}
        self.b_index = {}
        for b in self.pool_b:
            self.b_index.setdefault(b["id"], b["k"])


def symbol_hash(ident: int, cls: int) -> int:
    """hash_operand of a symbol (x87-scheduling.md section 5, part_origin_trace.sort_key)."""
    if cls == 3:
        return (ident << 6) & 0xFFFF
    value = (ident >> 16) ^ (ident & 0xFFFF)
    return (((value & 0x7FF) << 5) ^ ((value << 5) >> 16)) & 0xFFFF


def leaf_key(op: dict, ident: int | None = None) -> int | None:
    """Recompute a leaf's packed key, optionally with its deciding symbol at another id; None if not a leaf."""
    kind = op["kind"]
    if kind == 2 and op.get("sym") and op["key"] >> 16 == 1:
        sym = op["sym"]
        return 0x10000 | symbol_hash(sym["id"] if ident is None else ident, sym["cls"])
    if kind in (5, 6) and op.get("base") and not op.get("index") and op["key"] >> 16 == 1:
        base = op["base"]
        fold = (op["key"] - 7 - (symbol_hash(base["id"], base["cls"]) << 8)) & 0xFFFF
        h = symbol_hash(base["id"] if ident is None else ident, base["cls"])
        return 0x10000 | ((fold + 7 + (h << 8)) & 0xFFFF)
    return None


def decider(op: dict, trace: Trace) -> tuple[str, int, int, str] | None:
    """The counter id this operand's key is made of: (pool, id, residue modulus, leaf kind)."""
    kind = op["kind"]
    sym, leaf = None, None
    if kind in (5, 6) and op.get("base") and not op.get("index") and op["key"] >> 16 == 1:
        sym, leaf = op["base"], "mem"
    elif kind == 2 and op.get("sym") and op["key"] >> 16 == 1:
        sym, leaf = op["sym"], "sym"
    if not sym:
        return None
    if sym["cls"] == 3:
        pool = "E" if sym["id"] in trace.e_index else "A"
        modulus = 4 if leaf == "mem" else 1024
    elif sym["cls"] in (4, 5):
        pool = "B"
        modulus = 8 if leaf == "mem" and sym["id"] < 0x800 else (2048 if sym["id"] >= 0x800 else 0)
    else:
        return None  # globals: fixed ids
    return (pool, sym["id"], modulus, leaf)


def flip_residues(row: dict, side: int) -> list[int] | None:
    """Residues of the deciding id of operand `side` (mod its modulus) at which the pair's order is reversed."""
    dec = row["deciders"][side]
    if not dec or not dec[2]:
        return None
    _pool, ident, modulus, _leaf = dec
    mine, other = (row["first"], row["second"]) if side == 0 else (row["second"], row["first"])
    other_dec = row["deciders"][1 - side]
    if other_dec and other_dec[1] == ident:
        return None  # the same symbol on both sides
    other_key = other["key"]
    out = []
    for residue in range(modulus):
        key = leaf_key(mine, ident - ident % modulus + residue)
        if key is None:
            return None
        # side 0 sorts first now: it keeps first while key > other (ties keep source order: unknown, count as kept)
        if (key < other_key) if side == 0 else (key > other_key):
            out.append(residue)
    return out


def code_relevant(row: dict) -> bool:
    """Pairs whose order can change an instruction: not a constant or a global address against anything."""
    for op in (row["first"], row["second"]):
        if op["kind"] == 7:
            return False
        if op["kind"] == 3:
            return False  # an address constant: folds into the displacement
        sym = op.get("sym")
        if op["kind"] in (1, 2, 4) and sym and sym["cls"] == 7 and row["op"] == "16d" and op["kind"] != 2:
            return False
    return True


def fix_lines(trace: Trace) -> dict[str, int]:
    """Nodes built by globopt carry the function's last line label; give them the previous node's line."""
    last = max((event["ln"] for event in trace.sorts.values()), default=0)
    out, previous = {}, 0
    for node in trace.order:
        ln = trace.sorts[node]["ln"]
        if ln == last and previous and previous < last:
            ln = previous
        out[node] = ln
        previous = ln
    return out


def product_key(ops: list[dict]) -> int | None:
    """The key a two-leaf product node carries as an operand: need 1, size 3, hash h0 + (h1 << 1) + 0x2a."""
    if len(ops) != 2 or any(o["key"] >> 16 != 1 for o in ops):
        return None
    return 0x01030000 | ((ops[0]["key"] + (ops[1]["key"] << 1) + 0x16F - 0x145) & 0xFFFF)


def square_symbol(trace: Trace, position: int, key: int) -> dict | None:
    """For a tuple operand, the square `s * s` node sorted just before it (same key): its symbol leaf."""
    for back in range(1, 8):
        if position - back < 0:
            break
        child = trace.sorts[trace.order[position - back]]
        if child["op"] == "16f" and product_key(child["ops"]) == key:
            a, b = child["ops"]
            if a.get("sym") and b.get("sym") and a["sym"]["id"] == b["sym"]["id"] and a["kind"] == 2:
                return a["sym"]
            return None
    return None


def square_residues(sym: dict, other_key: int, first: bool, modulus: int = 2048) -> list[int]:
    """Residues of a squared symbol's id at which its square's key crosses `other_key`."""
    out = []
    for residue in range(modulus):
        ident = sym["id"] - sym["id"] % modulus + residue
        key = 0x01030000 | ((3 * symbol_hash(ident, sym["cls"]) + 0x2A) & 0xFFFF)
        if (key < other_key) if first else (key > other_key):
            out.append(residue)
    return out


def ties(trace: Trace) -> list[dict]:
    """Adjacent sorted operands with the same need and size: their order is decided by the 16-bit hash."""
    rows = []
    lines = fix_lines(trace)
    for position, node in enumerate(trace.order):
        event = trace.sorts[node]
        for a, b in zip(event["ops"], event["ops"][1:], strict=False):
            if a["key"] >> 16 != b["key"] >> 16 or a["key"] >> 16 == 0:
                continue
            row = {
                "node": node,
                "op": event["op"],
                "ln": lines[node],
                "raw_ln": event["ln"],
                "first": a,
                "second": b,
                "deciders": [decider(a, trace), decider(b, trace)],
            }
            for op in (a, b):
                key = leaf_key(op)
                if key is not None and key != op["key"]:
                    raise ValueError(f"key model disagrees: {op} -> {key:#x}")
            row["flips"] = [flip_residues(row, 0), flip_residues(row, 1)]
            row["relevant"] = code_relevant(row)
            if a["kind"] == 12 and b["kind"] == 12:
                row["squares"] = [square_symbol(trace, position, a["key"]), square_symbol(trace, position, b["key"])]
            rows.append(row)
    return rows


def describe(op: dict) -> str:
    if op.get("sym"):
        s = op["sym"]
        return f"#{s['id']}c{s['cls']}{('^' + str(s['parent']) + '+' + str(s['off'])) if s['parent'] else ''}" + (
            f" {s['name']}" if s["name"] else ""
        )
    if op["kind"] in (5, 6) and op.get("base"):
        s = op["base"]
        return f"[#{s['id']}c{s['cls']}{('+' + str(op['disp'])) if op.get('disp') else ''}]" + (
            f" {s['name']}" if s["name"] else ""
        )
    if op["kind"] == 7:
        return op["text"]
    return f"tuple {op.get('tuple', op['text'])}"


# ---------------------------------------------------------------- interventions


def phantom_object(out: Path, name: str, phantom: dict, ordinal: int) -> tuple[Path, list[str]]:
    work = out / "phantom" / name
    if (work / "replay.obj").exists() and (work / "phases.bin").exists():
        return work / "replay.obj", decode((work / "phases.bin").read_bytes())
    work.mkdir(parents=True, exist_ok=True)
    (work / "replay_settings.h").write_bytes((out / "observed/replay_settings.h").read_bytes())
    prof = json.loads((out / "profile.json").read_text())
    (work / "observer.c").write_text(observer(prof, phantom, ordinal))
    replay = c2.replay
    with c2.compiler_environment():
        replay.compile_driver(work, "observer.c", "observer.obj")
        replay.link(work, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], work)
    return work / "replay.obj", decode((work / "phases.bin").read_bytes())


def match_object(scratch: Path, obj: Path) -> m.MatchResult:
    config = m.load_scratch_config(scratch.resolve())
    image, functions, metadata = m._paths_for_image(config.image)
    return m.run_match(
        obj_path=obj,
        function=config.function,
        image_path=image,
        functions_path=functions,
        metadata_path=metadata,
        symbol_name=config.symbol,
        object_extent=config.archive_extent,
        object_end_symbol=config.archive_end_symbol,
        object_size=config.archive_size,
        end_va=config.end_va,
        reference_aliases=config.reference_aliases,
    )


ESP = re.compile(r"\besp\+0x[0-9a-f]+\b|\besp\b(?=\])")


STORES = ("fstp", "fst", "fistp", "fist", "mov")
PASSIVE = ("fld", "fst", "fstp", "fxch", "push", "pop", "lea", "mov", "add esp", "sub esp")


def framed(result: m.MatchResult, frames: dict, side: str) -> list[tuple[str, int | None]]:
    """Structural lines with each esp operand renamed by data flow, plus its frame offset.

    A stack read is named after the value its reaching store wrote: the last computing instruction before that
    store (its mnemonic: `fsub`, `fsqrt`, `call`, ...; `int` for an integer copy). Slot numbers differ between two builds; the values do not, so an
    operand-order swap of two stack slots becomes a visible difference.
    """
    offsets = {a: off for a, off, _ in frames[side]["refs"]}
    lines = result.target_lines if side == "target" else result.candidate_lines
    disasm = result.target_disassembly if side == "target" else result.candidate_disassembly
    masked = [rm.mask(line, "structural") for line in lines]
    producer: dict[int, str] = {}
    last_value = "?"
    out = []
    for text, d in zip(masked, disasm, strict=True):
        off = offsets.get(d.address)
        mnemonic = text.split()[0] if text else ""
        if (
            off is not None
            and mnemonic in STORES
            and text.split(",")[0].count("[") == 1
            and "esp" in text.split(",")[0]
        ):
            producer[off] = last_value if mnemonic != "mov" else "int"
            out.append((ESP.sub("V", text), off))
        elif off is not None:
            out.append((ESP.sub("V=" + producer.get(off, "entry"), text), off))
        else:
            out.append((text, off))
        if not text.startswith(PASSIVE) and not text.startswith("j"):
            last_value = mnemonic
    return out


def renamed_ratio(target: list[tuple[str, int | None]], candidate: list[tuple[str, int | None]]) -> tuple[int, int]:
    """Equal lines between two windows of data-flow renamed lines."""
    a = [x for x, _ in target]
    b = [x for x, _ in candidate]
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    return sum(block.size for block in matcher.get_matching_blocks()), len(a) + len(b)


def local_slots(base: dict, other: dict, window: int = 40) -> tuple[int, int]:
    """Equal lines near every place `other` differs from `base`, each window renamed on its own.

    `base`/`other` are {"target": framed, "candidate": framed}. Returns (base equal lines, other equal lines) summed
    over the changed hunks: a stack-operand order swap shows up here, where the stack-masked ratio cannot see it.
    """
    tb = [x for x, _ in base["target"]]
    cb = [x for x, _ in base["candidate"]]
    co = [x for x, _ in other["candidate"]]
    to_target = {}
    for block in difflib.SequenceMatcher(a=tb, b=cb, autojunk=False).get_matching_blocks():
        for k in range(block.size):
            to_target[block.b + k] = block.a + k
    keys = sorted(to_target)
    total_base = total_other = 0
    for tag, j1, j2, k1, k2 in difflib.SequenceMatcher(a=cb, b=co, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        lo, hi = max(0, j1 - window), min(len(cb), j2 + window)
        near = [to_target[j] for j in keys if lo <= j < hi]
        if not near:
            continue
        i1, i2 = min(near), max(near) + 1
        target = base["target"][i1:i2]
        eb, _ = renamed_ratio(target, base["candidate"][lo:hi])
        eo, _ = renamed_ratio(target, other["candidate"][max(0, k1 - window) : min(len(co), k2 + window)])
        total_base += eb
        total_other += eo
    return total_base, total_other


def scores(result: m.MatchResult) -> dict:
    out = {k: round(v * 100, 3) for k, v in rm.ratios(result).items()}
    audit = result.masked_operand_audit
    out["refs"] = f"{audit.ok_count}/{audit.unresolved_count}/{audit.mismatch_count}"
    out["insns"] = len(result.candidate_lines)
    return out


def shapes(trace: Trace) -> list[tuple]:
    """Per sorted node, in IL order: its opcode and the id-free shape of each operand, in sorted order."""
    out = []
    for node in trace.order:
        event = trace.sorts[node]
        row = []
        for op in event["ops"]:
            sym = op.get("sym") or op.get("base") or {}
            row.append((op["kind"], op["key"] >> 16, op.get("disp"), sym.get("cls"), sym.get("name"), sym.get("off")))
        out.append((event["op"], event["ln"], tuple(row)))
    return out


def flipped(base: Trace, other: Trace) -> list[int]:
    """Indices of sorted nodes whose operand order differs between two compiles of the same IL shape."""
    a, b = shapes(base), shapes(other)
    if len(a) != len(b):
        return [-1]
    return [
        i
        for i, (x, y) in enumerate(zip(a, b, strict=True))
        if x != y and x[0] == y[0] and sorted(map(str, x[2])) == sorted(map(str, y[2]))
    ]


def parse_phantom(text: str) -> dict:
    phantom: dict[str, list[tuple[int, ...]]] = {"E": [], "O": [], "K": []}
    for item in text.split(","):
        pool, *values = item.split(":")
        phantom[pool.upper()].append(tuple(int(v, 0) for v in values))
    return phantom


def isolated(pool: str, index: int, shift: int, modulus: int) -> dict:
    """Burn `shift` ids right before record `index` and the complement right after it: only that record moves
    (mod `modulus`); every later record moves by a whole modulus."""
    burns = [(index, shift)]
    if shift % modulus:
        burns.append((index + 1, modulus - shift % modulus))
    return {pool: burns}


def probe_spec(site: dict, shift: int) -> dict:
    """The intervention for one site: real pool-E burns; for pool B a re-key of that symbol's leaves (burning
    class-4 records crashes C2), at every node for a residue site and at the site's nodes for an order site."""
    if site["pool"] == "E":
        return isolated("E", site["index"], shift, site["modulus"])
    if site["pool"] == "B":
        return {"O": [(site["id"], site["id"] + shift, -1)]}
    return {"K": [site["swap"]]}


def framing(scratch: Path, obj: Path, result: m.MatchResult) -> dict:
    frames = fp.binary_frames(m.load_scratch_config(scratch.resolve()), obj)
    return {side: framed(result, frames, side) for side in ("target", "candidate")}


def run_phantom(
    scratch: Path,
    out: Path,
    base: Trace,
    name: str,
    phantom: dict,
    ordinal: int,
    base_framed: dict | None = None,
) -> dict:
    obj, lines = phantom_object(out, name, phantom, ordinal)
    result = match_object(scratch, obj)
    other = Trace(lines, ordinal)
    row = {
        "name": name,
        "phantom": phantom,
        **scores(result),
        "flipped": flipped(base, other),
        "burned": len(other.burns),
        "alias": other.alias,
        "trace": other,
        "candidate": result.candidate_lines,
    }
    if base_framed is not None:
        before, after = local_slots(base_framed, framing(scratch, obj, result))
        row["local"] = after - before
    return row


# ---------------------------------------------------------------- report


def site_table(trace: Trace, rows: list[dict], offset: int) -> list[dict]:
    """One entry per deciding counter id whose residue can reverse at least one code-relevant pair."""
    sites: dict[tuple[str, int], dict] = {}
    nodes = {node: i for i, node in enumerate(trace.order)}
    for row in rows:
        if not row["relevant"]:
            continue
        for side in (0, 1):
            dec, flips = row["deciders"][side], row["flips"][side]
            if not dec or not flips or dec[0] not in ("E", "B"):
                continue
            pool, ident, modulus, leaf = dec
            index = trace.e_index.get(ident) if pool == "E" else trace.b_index.get(ident)
            if index is None:
                continue
            site = sites.setdefault(
                (pool, ident),
                {"pool": pool, "id": ident, "index": index, "modulus": modulus, "leaf": leaf, "pairs": []},
            )
            other = row["second" if side == 0 else "first"]
            site["pairs"].append(
                {
                    "line": row["ln"] + offset,
                    "node": nodes[row["node"]],
                    "op": row["op"],
                    "text": f"{describe(row['first'])} ({row['first']['key'] & 0xFFFF:#06x}) before "
                    f"{describe(row['second'])} ({row['second']['key'] & 0xFFFF:#06x})",
                    "other": describe(other),
                    "flips": flips,
                },
            )
    for row in rows:
        # Pairs no residue decides: two pool-B symbol leaves (creation order) or two tuples (hash of their
        # children). One site per sorted node; the probe swaps just that pair.
        dec = row["deciders"]
        b_order = all(d and d[0] == "B" and d[2] == 0 for d in dec) and dec[0][1] != dec[1][1]
        tuples = row["first"]["kind"] == 12 and row["second"]["kind"] == 12
        if not row["relevant"] or not (b_order or tuples) or row["first"]["key"] == row["second"]["key"]:
            continue
        node = nodes[row["node"]]
        squares = row.get("squares") or [None, None]
        windows = [
            square_residues(sq, (row["second"] if side == 0 else row["first"])["key"], side == 0) if sq else None
            for side, sq in enumerate(squares)
        ]
        sites[("O", node, row["first"]["key"])] = {
            "squares": squares,
            "windows": windows,
            "pool": "O",
            "id": dec[0][1] if b_order else 0,
            "other_id": dec[1][1] if b_order else 0,
            "index": node,
            "modulus": 0,
            "leaf": "order" if b_order else "tuple",
            "swap": (node, row["first"]["key"], row["second"]["key"] - 1),
            "pairs": [
                {
                    "line": row["ln"] + offset,
                    "node": node,
                    "op": row["op"],
                    "text": f"{describe(row['first'])} ({row['first']['key'] & 0xFFFF:#06x}) before "
                    f"{describe(row['second'])} ({row['second']['key'] & 0xFFFF:#06x})",
                    "other": describe(row["second"]),
                    "flips": [],
                },
            ],
        }
    for site in sites.values():
        if site["pool"] == "O":
            site["first_line"] = min(p["line"] for p in site["pairs"])
            site["residue"] = site["id"]
            site["groups"] = {site["other_id"] - 1 - site["id"] if site["leaf"] == "order" else 0: [0]}
            continue
        if site["pool"] == "E":
            e = trace.pool_e[site["index"]]
            site["vn_line"] = int(e["vn"].split()[0]) + offset if e["vn"] else None
        else:
            site["stage"] = trace.pool_b[site["index"]]["stage"]
        site["first_line"] = min(p["line"] for p in site["pairs"])
        site["residue"] = site["id"] % site["modulus"]
        # Residues grouped by which pairs they reverse; one probe per group, at the smallest shift.
        groups: dict[tuple, int] = {}
        for shift in range(1, site["modulus"]):
            residue = (site["residue"] + shift) % site["modulus"]
            reversed_pairs = tuple(i for i, pair in enumerate(site["pairs"]) if residue in pair["flips"])
            if reversed_pairs and reversed_pairs not in groups:
                groups[reversed_pairs] = shift
        site["groups"] = {shift: list(pairs) for pairs, shift in groups.items()}
    return sorted(sites.values(), key=lambda s: ("EBO".index(s["pool"]), s["index"], s["id"]))


def line_offset(scratch: Path) -> int:
    """C2 line labels count from the function's first line; find `FUNCTION(` in the source."""
    config = m.load_scratch_config(scratch.resolve())
    text = (config.directory / config.source).read_text(errors="replace").splitlines()
    pattern = re.compile(rf"\b{re.escape(config.function)}\s*\(")
    for number, line in enumerate(text, 1):
        if pattern.search(line) and not line.rstrip().endswith(";"):
            return number
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="trace directory (new, or existing to reuse)")
    parser.add_argument("--ordinal", type=int, help="function ordinal in the translation unit (default: by name)")
    parser.add_argument("--probe", action="store_true", help="run one intervention per site and residue class")
    parser.add_argument("--pools", default="E,B,O", help="E residues (burns), B residues and O orders (key override)")
    parser.add_argument("--limit", type=int, help="probe only the first N sites per pool")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--csv", type=Path, help="write the site table as CSV")
    parser.add_argument(
        "--phantom",
        help="E:SLOT:COUNT, O:ID:NEWID[:NODE], K:NODE:OLDKEY:NEWKEY (comma-separated) - one intervention",
    )
    parser.add_argument("--ties", action="store_true", help="print every tie pair")
    args = parser.parse_args()
    out = args.out.resolve()
    if not (out / "observed/phases.bin").exists():
        result = trace(args.scratch, out)
        print("metrics:", result["metrics"])
    lines = decode((out / "observed/phases.bin").read_bytes())
    function = m.load_scratch_config(args.scratch.resolve()).function
    if args.ordinal is None:
        names = Trace(lines).functions
        args.ordinal = next((i for i, n in enumerate(names) if n.endswith("'_" + function)), 0)
    base = Trace(lines, args.ordinal)
    offset = line_offset(args.scratch)
    rows = ties(base)
    print(
        f"function #{args.ordinal}: C0 {base.c0:#x}, pool-E slots {len(base.pool_e)}, pool-B records"
        f" {len(base.pool_b)}, first pointer class {base.alias}, tie pairs {len(rows)}",
    )
    if args.ties:
        for row in rows:
            dec = " / ".join(f"{d[0]}{d[1]}" if d else "-" for d in row["deciders"])
            print(
                f"  {row['op']:>4} src{row['ln'] + offset:<5} {row['first']['key']:#010x} {describe(row['first']):32}"
                f" | {row['second']['key']:#010x} {describe(row['second']):32} [{dec}]",
            )
    if args.phantom:
        base_result = match_object(args.scratch, out / "observed/replay.obj")
        print("base   ", scores(base_result))
        phantom = parse_phantom(args.phantom)
        name = args.phantom.replace(":", "_").replace(",", "-")
        if len(name) > 40:  # VC6 tools need short paths
            name = "p" + hashlib.sha1(name.encode()).hexdigest()[:12]
        base_framed = framing(args.scratch, out / "observed/replay.obj", base_result)
        row = run_phantom(args.scratch, out, base, name, phantom, args.ordinal, base_framed)
        print("phantom", {k: v for k, v in row.items() if k not in ("candidate", "trace")})
        diff = difflib.unified_diff(base_result.candidate_lines, row["candidate"], "base", "phantom", n=1, lineterm="")
        print("\n".join(list(diff)[:200]))
        return
    sites = site_table(base, rows, offset)
    pools = set(args.pools.upper().split(","))
    sites = [s for s in sites if s["pool"] in pools]
    reference = None
    if args.probe:
        base_result = match_object(args.scratch, out / "observed/replay.obj")
        reference = scores(base_result)
        reference["local"] = 0
        base_framed = framing(args.scratch, out / "observed/replay.obj", base_result)
        print("base", reference)
        jobs = []
        for pool in sorted(pools):
            for site in [s for s in sites if s["pool"] == pool][: args.limit]:
                for shift in site["groups"]:
                    jobs.append((site, shift, probe_spec(site, shift)))

        def work(job):
            site, shift, phantom = job
            name = f"{site['pool']}{site['index']}_{site['id']}_{shift}_{site['modulus']}"
            if site["pool"] == "O":
                name = f"K{site['swap'][0]}_{site['swap'][1]:x}"
            row = run_phantom(args.scratch, out, base, name, phantom, args.ordinal, base_framed)
            other = row.pop("trace")
            row["code_changed"] = row.pop("candidate") != base_result.candidate_lines
            if site["pool"] == "E":
                row["moved_to"] = next((i for i, k in other.e_index.items() if k == site["index"]), None)
            return site, shift, row

        with ThreadPoolExecutor(args.jobs) as executor:
            for site, shift, row in executor.map(work, jobs):
                site.setdefault("probes", {})[shift] = row
    for site in sites:
        verdict(site, reference)
        print(report_site(site))
    if args.csv:
        write_csv(args.csv, sites)


METRICS = ("raw", "labels", "structural", "stack")


def verdict(site: dict, reference: dict | None) -> None:
    """The requirement: the probe that scores best (stack-masked, labels, raw; fewer ref mismatches), if it beats
    ours. A probe that changes code but none of the four masked ratios is a stack-operand order: `invisible`."""
    probes = site.get("probes", {})
    if not reference or not probes:
        site["verdict"] = "untested"
        return

    def rank(row):
        refs = [int(x) for x in row["refs"].split("/")]
        return (row["stack"], row["labels"], row["raw"], -refs[2])

    changed = {shift: row for shift, row in probes.items() if row.get("code_changed")}
    if not changed:
        site["verdict"] = "no code effect"
        return
    # Data-flow windows first: they see stack-operand order, which the masked ratios cannot.
    local = {s: r for s, r in changed.items() if r.get("local")}
    if local:
        shift, row = max(local.items(), key=lambda item: item[1]["local"])
        if row["local"] > 0:
            label = "swap" if site["pool"] == "O" else f"+{shift} (mod {site['modulus']})"
            site["verdict"] = f"native needs {label} (data flow +{row['local']})"
            site["required"] = shift
        else:
            site["verdict"] = f"ours is native (data flow {row['local']})"
            site["required"] = 0
        return
    visible = {s: r for s, r in changed.items() if any(r[k] != reference[k] for k in (*METRICS, "refs"))}
    if not visible:
        site["verdict"] = "code changes, no metric sees it"
        return
    best = max(visible.items(), key=lambda item: rank(item[1]))
    if rank(best[1]) > rank(reference):
        label = "swap" if site["pool"] == "O" else f"+{best[0]} (mod {site['modulus']})"
        site["verdict"] = f"native needs {label}"
        site["required"] = best[0]
    else:
        site["verdict"] = "ours is native"
        site["required"] = 0


def report_site(site: dict) -> str:
    where = f"vn src{site['vn_line']}" if site.get("vn_line") else f"{site.get('stage', '')}"
    if site["pool"] == "O":
        where = f"vs #{site['other_id']}"
    lines = [
        (
            f"{site['pool']} n{site['index']:<5} id {site['id']:#6x} ≡{site['residue']} (mod {site['modulus']}) "
            f"{site['leaf']} first src{site['first_line']} {where}  pairs {len(site['pairs'])}  -> {site['verdict']}"
        ),
    ]
    for pair in site["pairs"][:4]:
        lines.append(f"      {pair['op']}@src{pair['line']} {pair['text']}  reversed at {compact(pair['flips'])}")
        if site["pool"] in ("E", "B"):
            lines.append(f"        nearest reversing shifts: {nearest(site['id'], pair['flips'], site['modulus'])}")
    for sq, window in zip(site.get("squares") or [], site.get("windows") or [], strict=False):
        if sq:
            lines.append(
                f"      square of #{sq['id']}c{sq['cls']} {sq['name']}: reversed when id mod 2048 in {compact(window)};"
                f" nearest shifts {nearest(sq['id'], window, 2048)}",
            )
    if len(site["pairs"]) > 4:
        lines.append(f"      ... {len(site['pairs']) - 4} more pairs")
    for shift, row in sorted(site.get("probes", {}).items()):
        lines.append(
            f"      +{shift}: raw {row['raw']} labels {row['labels']} struct {row['structural']} stack {row['stack']}"
            f" local {row.get('local')} refs {row['refs']} flipped {len(row['flipped'])}"
            f" code {row.get('code_changed')} moved_to {row.get('moved_to')}",
        )
    return "\n".join(lines)


def nearest(ident: int, residues: list[int], modulus: int) -> str:
    """The smallest upward and downward shifts of `ident` that land in `residues` (mod `modulus`)."""
    if not residues or not modulus:
        return "-"
    here = ident % modulus
    up = min((r - here) % modulus for r in residues)
    down = min((here - r) % modulus for r in residues)
    return f"+{up} / -{down}"


def compact(values: list[int]) -> str:
    """Residue list as ranges: 0,1,2,5 -> 0-2,5."""
    out, start = [], None
    for i, v in enumerate(values):
        if start is None:
            start = v
        if i + 1 == len(values) or values[i + 1] != v + 1:
            out.append(f"{start}" if start == v else f"{start}-{v}")
            start = None
    return ",".join(out)


def requirement(site: dict) -> str:
    """The id condition that reverses the site, as the nearest shifts of the deciding id(s)."""
    if site["pool"] in ("E", "B"):
        flips = sorted({r for pair in site["pairs"] for r in pair["flips"]})
        return f"reversed at {compact(flips)} (mod {site['modulus']}); nearest {nearest(site['id'], flips, site['modulus'])}"
    if site["leaf"] == "order":
        return f"reversed when #{site['id']} < #{site['other_id']} (shift {site['other_id'] - 1 - site['id']:+d})"
    parts = [
        f"#{sq['id']}c{sq['cls']} {sq['name']} mod 2048 in {compact(window)}, nearest {nearest(sq['id'], window, 2048)}"
        for sq, window in zip(site.get("squares") or [], site.get("windows") or [], strict=False)
        if sq
    ]
    return "reversed when " + " or ".join(parts) if parts else ""


def write_csv(path: Path, sites: list[dict]) -> None:
    columns = [
        "pool",
        "index",
        "id",
        "modulus",
        "residue",
        "leaf",
        "first_src_line",
        "vn_src_line",
        "pairs",
        "example",
        "requirement_if_reversed",
        "verdict",
        "required_shift",
        "probes",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for site in sites:
            probes = "; ".join(
                f"{k:+d}: {r['raw']}/{r['labels']}/{r['structural']}/{r['stack']} refs {r['refs']}"
                f" dataflow {r.get('local', 0):+d} code {'changed' if r.get('code_changed') else 'same'}"
                for k, r in sorted(site.get("probes", {}).items())
            )
            writer.writerow(
                [
                    site["pool"],
                    site["index"],
                    site["id"],
                    site["modulus"],
                    site["residue"],
                    site["leaf"],
                    site["first_line"],
                    site.get("vn_line", ""),
                    len(site["pairs"]),
                    site["pairs"][0]["text"],
                    requirement(site),
                    site["verdict"],
                    site.get("required", ""),
                    probes,
                ],
            )


if __name__ == "__main__":
    main()
