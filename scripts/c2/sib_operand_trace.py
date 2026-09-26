"""Rank every operand of a VC6 C2 address sum, including loads and expressions (diagnostic only; no match credit).

When an address sum `a + b + disp` folds into a memory operand, its first operand becomes the SIB base and the
second the index. The order is the commutative operand sort of `compute_tree_cost_and_sort` 0x1070d90c: stable,
unsigned descending on the packed key `need<<24 | size<<16 | hash16` (x87-scheduling.md, call-operand-order.md).
snail-mail's `addrorder.py` models only sums of two plain symbols. This tool lists every address sum and
classifies each ranked operand (sib-operand-order.md):

    sym        a symbol leaf (kinds 2-4): need 0, size 1, hash from the slot id
               (class 3: (id << 6) & 0xffff; class 4/5 below 0x800: id << 5)
    load/leaf  a memory operand whose address is a symbol (a CSE temporary, local or parameter):
               need 0, size 1, hash = (hash(address) << 8) + fold(disp) + (opcode - 0x145), 16 bits
               (hash_operand 0x1070db59 case 2, 0x1070dbc5)
    load/expr  a memory operand whose address is still an expression temporary (for example
               `local + 0x5c` that CSE did not make available): it takes the address tree's cost, so
               need >= 1 and it sorts above every leaf (0x1070d9c4..0x1070da11)
    expr       any other expression operand: its own tree cost, need >= 1

The tool re-derives every leaf hash from the captured records and fails if C2's key disagrees. It runs the
scratch through snail-mail's addrorder observer (Crimson's preserving observer: whole COFF, replay and
missing-stream checks unchanged) and prints C0, each sum with its C2 line label, and the matcher's encoded
SIB swaps. Run it from the snail-mail checkout, which provides the `snail` package:

    uv run python ../crimson/scripts/c2/sib_operand_trace.py <snail-scratch> --out <new-dir> [--lines A-B]

See tools/match/c2/compiler/sib-operand-order.md.
"""

from __future__ import annotations

import argparse
import sys
from itertools import pairwise
from pathlib import Path

HERE = Path(__file__).resolve().parent
SNAIL = HERE.parents[2] / "snail-mail"
sys.path.insert(0, str(SNAIL / "tools/match/c2"))

import addrorder as ao
import rotation as rot
from snail import match as m

MEMORY = 6
EXPRESSION = 1
MEMORY_OPCODE_BASE = 0x145


def fold(value: int) -> int:
    signed = value - (1 << 32) if value & 0x80000000 else value
    return ((signed >> 16) ^ (value & 0xFFFF)) & 0xFFFF


def symbol_hash(ident: int, klass: int) -> int:
    """hash_operand 0x1070db59 for a kind-2 symbol (addrorder.symbol_hash with the class alone)."""
    if klass == 3:
        return (ident << 6) & 0xFFFF
    folded = (ident >> 16) ^ (ident & 0xFFFF)
    shifted = folded << 5 & 0xFFFFFFFF
    shifted = shifted - (1 << 32) if shifted & 0x80000000 else shifted
    return ((shifted >> 16) ^ ((folded & 0x7FF) << 5)) & 0xFFFF


def temp_n(ident: int, klass: int, creation: dict[int, int]) -> str:
    n = creation.get(ident) if klass == 3 else None
    return f" n={n}" if n is not None else ""


def classify(operand: dict, creation: dict[int, int]) -> dict:
    kind, raw, words = operand["kind"], operand["raw"], operand["temp_words"]
    key = raw[3]
    row = {"key": key, "need": key >> 24, "size": (key >> 16) & 0xFF, "hash": key & 0xFFFF}
    if kind in ao.SYMBOL_KINDS:
        ident, flags = words[7], words[1]
        klass = flags & 0xFF
        name = "iv-temp" if klass == 3 and flags & ao.INDUCTION_FLAG else ao.CLASSES.get(klass, f"class{klass}")
        if row["key"] and not words[5] and ao.symbol_hash(kind, words) != row["hash"]:
            raise ValueError(f"symbol hash rule mismatch for slot {ident:#x}: key {key:#x}")
        row |= {"what": "sym", "text": f"{name} {ident:#x}{temp_n(ident, klass, creation)}"}
        return row
    if kind == MEMORY:
        disp, child_kind, ident, klass = words[2], words[9], words[12], words[13] & 0xFF
        if child_kind in ao.SYMBOL_KINDS:
            base = symbol_hash(ident, klass)
            expected = (fold(disp) + (raw[1] & 0xFFFF) - MEMORY_OPCODE_BASE + (base << 8)) & 0xFFFF
            if row["key"] and (row["need"] or expected != row["hash"]):
                raise ValueError(f"memory leaf rule mismatch: key {key:#x}, expected hash {expected:#x}")
            name = ao.CLASSES.get(klass, f"class{klass}")
            row |= {
                "what": "load/leaf",
                "text": f"[{name} {ident:#x}{temp_n(ident, klass, creation)}{disp:+#x}]",
            }
            return row
        if row["key"] and not row["need"]:
            raise ValueError(f"memory operand over an expression with need 0: {key:#x}")
        row |= {"what": "load/expr", "text": f"[expr {words[11] & 0xFFFF:04x}{disp:+#x}]"}
        return row
    row |= {"what": "expr" if kind == EXPRESSION else f"kind{kind}", "text": ao.operand_brief(operand)}
    return row


def address_sums(event: dict, creation: dict[int, int]) -> list[dict]:
    """Every ADD whose result addresses memory (directly or through `+ const`), with >= 2 ranked operands."""
    nodes = event["nodes"]
    users: dict[int, list[int]] = {}
    for index, node in enumerate(nodes):
        for operand in node["src"]:
            if operand["kind"] == EXPRESSION:
                users.setdefault(operand["raw"][6], []).append(index)
    rows = []
    for index, node in enumerate(nodes):
        if node["op"] != ao.ADD or len(node["dst"]) != 1 or node["dst"][0]["kind"] != EXPRESSION:
            continue
        # The source list ends with one use per base/index register of its memory operands; those are not ranked.
        uses = sum(bool(o["temp_words"][3]) + bool(o["temp_words"][4]) for o in node["src"] if o["kind"] == MEMORY)
        ranked = [o for o in node["src"][: len(node["src"]) - uses] if o["kind"] != 7]
        if len(ranked) < 2:
            continue
        temp = node["dst"][0]["raw"][6]
        accesses = []
        for user in users.get(temp, []):
            consumer = nodes[user]
            accesses += [(0, use) for use in ao.memory_uses(consumer, temp)]
            constants = [o["raw"][6] for o in consumer["src"] if o["kind"] == 7]
            sign = ao.DISPLACEMENT_SIGN.get(consumer["op"])
            if sign and constants and consumer["dst"][0]["kind"] == EXPRESSION:
                inner = consumer["dst"][0]["raw"][6]
                for follow in users.get(inner, []):
                    accesses += [(sign * constants[0], use) for use in ao.memory_uses(nodes[follow], inner)]
        if not accesses:
            continue
        operands = [classify(o, creation) for o in ranked]
        # A node built after the last expression pass (strength reduction, address folding) keeps stale keys.
        sorted_ = all(a["key"] >= b["key"] for a, b in pairwise(operands)) and all(o["key"] for o in operands)
        rows.append(
            {
                "node": index,
                "label": node["line"],
                "operands": operands,
                "accesses": sorted(set(accesses)),
                "sorted": sorted_,
            },
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", help="snail scratch name or directory")
    parser.add_argument("--source", type=Path, help="overlay source replacing scratch.cpp")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--lines", help="only sums whose C2 line label is in A-B")
    args = parser.parse_args()
    lines = tuple(int(x) for x in args.lines.split("-")) if args.lines else None
    scratch = Path(args.scratch)
    if not scratch.is_dir():
        scratch = m.DEFAULT_MATCH_ROOT / "scratches" / args.scratch
    work = rot.prepare(scratch, args.source, args.out.parent / (args.out.name + "-input"))
    result, events, allocations = ao.run_observer(work, args.out)
    c0, creation = ao.cse_origin(allocations)
    (event,) = [e for e in events if e["target_rva"] == ao.ADDRESS_PASS_HOOK["target"]]
    print(f"metrics: {result['metrics']}")
    print(f"C0 (first CSE temporary): {c0:#x}" if c0 is not None else "C0: none")
    print("first operand = SIB base; key = need<<24 | size<<16 | hash")
    for row in address_sums(event, creation):
        if lines and not lines[0] <= row["label"] <= lines[1]:
            continue
        access = ",".join(f"{use}{disp:+#x}" if disp else use for disp, use in row["accesses"])
        stale = "" if row["sorted"] else "  (keys stale: not re-sorted after this node was built)"
        print(f"ln{row['label']:<4} node {row['node']:<4} {access}{stale}")
        for position, o in zip(("base ", "index"), row["operands"]):
            print(f"    {position} {o['key']:#010x} {o['what']:9} {o['text']}")
        for o in row["operands"][2:]:
            print(f"    more  {o['key']:#010x} {o['what']:9} {o['text']}")
    config = m.load_scratch_config(work)
    manifest = m.load_function_symbol_manifest(m.DEFAULT_FUNCTION_SYMBOL_MANIFEST_PATH)
    match = m.run_match(
        obj_path=m.compile_scratch(config),
        function_name=config.function,
        end_va=config.end_va,
        symbol_name=config.symbol,
        manifest=manifest,
        image_path=m.REPO_ROOT / manifest.primary_target,
    )
    swaps = [d for d in ao.sib_differences(match) if d["swapped"]]
    if match.ratio == 1.0:
        print(f"\nencoded SIB swaps: {len(swaps)}")
    else:
        print(f"\nencoded bytes are compared only at 100% normalized (now {match.ratio:.2%})")
    for d in swaps:
        print(f"  +{d['offset']:#x} target {d['target_asm']}  candidate {d['candidate_asm']}")


if __name__ == "__main__":
    main()
