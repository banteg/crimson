"""Replay merge #2 (C2 0x10746a2f, mode 4) on an `iv_trace.py` trace and print the anchor chain.

For every loop that reaches merge #2 with two or more derived IVs, prints the preheader init order,
the use count of each derived IV at merge entry, the rule-A chain (champion = last init, challengers
in reverse preheader order, challenger wins ties, winner accumulates the loser's uses) and the
survivor the compiler actually kept.

    uv run python scripts/c2/iv_trace.py <scratch-dir> --out <trace-dir>
    uv run python scripts/c2/iv_merge_chain.py <trace-dir> [--loop <loop-address-substring>]

A use is a tuple, outside the IV's own preheader init and its tag-4 latch update, that reads the
derived symbol. The replay does not split IVs into step/opcode/type groups.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import iv_trace

SYMBOL = re.compile(r"#(\d+)c")
INIT_VALUE = re.compile(r"<= \[\w+:\d+:\w+ f\w+\.\w+ #\d+c\w*?(?:\^(\d+))?([+-]\d+)?z")


def merge_inputs(loop):
    """Derived IVs in creation order, IL entering merge #2 and IL leaving it."""
    derived, last_il, before, after = [], None, None, None
    for event in loop["events"]:
        name, boundary = event["name"], event["boundary"]
        if name.startswith("get_derived_iv") and boundary == "return" and event["body"].strip():
            number = int(SYMBOL.search(event["body"]).group(1))
            if number not in derived:
                derived.append(number)
        if name == "merge_parallel_induction_variables#2":
            if boundary == "entry":
                before = last_il
            else:
                after = iv_trace.il_lines(event)
        last_il = iv_trace.il_lines(event) or last_il
    return derived, before, after


def init_label(line):
    match = INIT_VALUE.search(line)
    if not match:
        return "?"
    parent, offset = match.groups()
    if parent:
        return f"^{parent}{offset or '+0'}"
    return f"#{SYMBOL.search(line.split('<=', 1)[1]).group(1)}+0"


def replay(loop):
    derived, il, after = merge_inputs(loop)
    if not il or len(derived) < 2:
        return None
    preheader = iv_trace.preheader_number(il, loop["loop"])
    inits = [
        line
        for line in iv_trace.block_tuples(il, preheader)
        if " op=15b " in line and iv_trace.dst_sym(line) in derived
    ]
    if len(inits) < 2:
        return None
    rows = []
    for init in inits:
        number = iv_trace.dst_sym(init)
        tag = f"#{number}c"
        uses = sum(
            1
            for line in il
            if line is not init and " tag=4 " not in line and "<=" in line and tag in line.split("<=", 1)[1]
        )
        rows.append((number, init_label(init), uses))
    order = rows[::-1]
    champion, count = order[0][0], order[0][2]
    label = {number: text for number, text, _ in rows}
    chain = []
    for number, text, uses in order[1:]:
        if count > uses:
            chain.append(f"{label[champion]}({count}) keeps vs {text}({uses})")
        else:
            chain.append(f"{text}({uses}) beats {label[champion]}({count})")
            champion = number
        count += uses
    kept = []
    if after:
        block = iv_trace.block_tuples(after, iv_trace.preheader_number(after, loop["loop"]))
        kept = [iv_trace.dst_sym(line) for line in block if " op=15b " in line and iv_trace.dst_sym(line) in derived]
    return {"preheader": preheader, "rows": rows, "chain": chain, "predicted": champion, "observed": kept}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trace", type=Path, help="directory written by iv_trace.py --out")
    parser.add_argument("--loop", help="only loops whose address contains this text")
    args = parser.parse_args()
    events = json.loads((args.trace / "snapshots.json").read_text())
    agree = total = 0
    for loop in iv_trace.loops_from(events):
        if args.loop and args.loop not in loop["loop"]:
            continue
        result = replay(loop)
        if not result:
            continue
        total += 1
        agree += result["observed"] == [result["predicted"]]
        print(f"=== loop {loop['loop']} preheader block {result['preheader']}")
        for number, text, uses in result["rows"]:
            print(f"  #{number:<6} init {text:<12} uses {uses}")
        for step in result["chain"]:
            print(f"    {step}")
        print(f"  predicted survivor #{result['predicted']}; kept after merge #2: {result['observed']}")
    print(f"rule A replay agrees on {agree}/{total} loops")


if __name__ == "__main__":
    main()
