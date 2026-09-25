"""Replay merge #2 (C2 0x10746a2f, mode 4) on an `iv_trace.py` trace and print the anchor chain.

For every loop that reaches merge #2 with a derived IV and at least one other IV, prints the IVs in
preheader order with their step, update block and use count, the merge passes (champion = last init,
challengers in reverse preheader order, challenger wins ties, winner accumulates the loser's uses) and
compares the predicted survivors with the IVs the compiler still updates after merge #2.

    uv run python scripts/c2/iv_trace.py <scratch-dir> --out <trace-dir>
    uv run python scripts/c2/iv_merge_chain.py <trace-dir> [--loop <loop-address-substring>]

A use is a tuple, outside the IV's own init and its tag-4 latch update, that reads the IV symbol.

Basic IVs initialised before the preheader (a user cursor such as `++candidate`, or the index) take part
too: mode 4 of `collect_iv_candidates` (0x10746fb7) copies their reaching init to the *start* of the
preheader as a tag-9 pseudo-init (deleted again when merge #2 returns), so they are the last challengers.
Two IVs are compared only with the same step operand and update block and when their init difference
folds to a constant (immediates and addresses of one global do; a variable base does not). A challenger
that cannot be compared goes to the retry list and meets the next champion. Liveness after the loop
(which also blocks a merge) is not modelled.
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


UPDATE = re.compile(
    r" op=(16d|16e) .* tag=4 \| \[[^\]]*#(\d+)c[^\]]*\] <= \[[^\]]*#(\d+)c[^\]]*\] \[[^\]]*?(=-?\d+|#\d+)c?[^\]]*\]",
)
ASSIGN = re.compile(r" op=15b .* tag=4 \| \[[^\]]*#(\d+)c[^\]]*\] <= \[[^\]]*#(\d+)c")


def loop_updates(il, loop):
    """{IV symbol: (step, update block)} for every `t = v +/- k; v = t` tag-4 update pair in the loop's blocks."""
    temps, updates, inside, block = {}, {}, False, None
    for line in il:
        if " BLOCK n=" in line:
            inside = f" loop={loop} " in line
            block = int(line.split(" BLOCK n=")[1].split()[0])
            continue
        if not inside:
            continue
        if match := UPDATE.search(line):
            op, temp, source, step = match.groups()
            temps[int(temp)] = (int(source), f"{'+' if op == '16d' else '-'}{step.lstrip('=')}")
        elif match := ASSIGN.search(line):
            symbol, temp = int(match.group(1)), int(match.group(2))
            if temps.get(temp, (None,))[0] == symbol:
                updates[symbol] = (temps[temp][1], block)
    return updates


INIT_OPERAND = re.compile(r"<= \[\w+:(\d+):\w+ f\w+\.\w+ (?:#(\d+)c\d*(?:\^(\d+))?)?")


OFFSET_DEF = re.compile(
    r" op=16[de] .* \| \[[^\]]*#(\d+)c[^\]]*\] <= \[\w+:[12]:\w+ f\w+\.\w+ #(\d+)c[^\]]*\] \[\w+:7:",
)


def init_class(line, offsets):
    """('imm', None), ('addr', root global) or ('var', base symbol) for an init's source operand.

    `offsets` maps preheader temps `t = x +/- k` to x, so `D = t` counts as based on x."""
    kind, number, parent = INIT_OPERAND.search(line).groups()
    if kind == "7":
        return ("imm", None)
    if kind == "3":
        return ("addr", int(parent or number))
    number = int(number) if number else None
    while number in offsets:
        number = offsets[number]
    return ("var", number)


def constant_difference(a, b):
    """Whether init(a) - init(b) folds to a constant (0x10754157 then 0x10754542)."""
    if "var" in (a[0], b[0]):
        return a == b
    return a[1] is None or b[1] is None or a[1] == b[1]


def use_count(il, number, skip):
    tag = f"#{number}c"
    return sum(
        1
        for line in il
        if line not in skip and " tag=4 " not in line and "<=" in line and tag in line.split("<=", 1)[1]
    )


def replay(loop):
    derived, il, after = merge_inputs(loop)
    if not il:
        return None
    preheader = iv_trace.preheader_number(il, loop["loop"])
    updates = loop_updates(il, loop["loop"])
    inits = [
        line
        for line in iv_trace.block_tuples(il, preheader)
        if " op=15b " in line and iv_trace.dst_sym(line) in updates
    ]
    in_preheader = {iv_trace.dst_sym(line) for line in inits}
    offsets = {
        int(match.group(1)): int(match.group(2))
        for line in iv_trace.block_tuples(il, preheader)
        if (match := OFFSET_DEF.search(line))
    }
    # Basic IVs initialised before the preheader get a pseudo-init at the preheader start (symbol-id order).
    rows = []
    for number in sorted(n for n in updates if n not in in_preheader):
        defs = [
            line for line in il if " op=15b " in line and " tag=4 " not in line and iv_trace.dst_sym(line) == number
        ]
        if not defs:
            continue
        label = init_label(defs[-1])
        if label == "?":
            label = defs[-1].split("<=", 1)[1].split()[-1].rstrip("]")
        rows.append((number, f"{label} (basic)", use_count(il, number, set(defs)), init_class(defs[-1], offsets)))
    rows += [
        (
            iv_trace.dst_sym(init),
            init_label(init),
            use_count(il, iv_trace.dst_sym(init), {init}),
            init_class(init, offsets),
        )
        for init in inits
    ]
    # Simulate 0x10746a2f mode 4: the worklist pops the last preheader init first. A challenger that cannot
    # merge with the champion (other step or update block, or an init difference that is not a constant) goes
    # to the retry list; so does a winning challenger, followed by the rest of the worklist. When the worklist
    # runs dry the champion is final and the retry list becomes the worklist again, in push order.
    count = {row[0]: row[2] for row in rows}
    label = {row[0]: row[1] for row in rows}
    key = {row[0]: (updates[row[0]][0], updates[row[0]][1], row[3]) for row in rows}
    work, chains, predicted = [row[0] for row in reversed(rows)], [], []
    while work:
        champion, retry, chain = work.pop(0), [], []
        while work:
            challenger = work.pop(0)
            a, b = key[champion], key[challenger]
            if a[:2] != b[:2] or not constant_difference(a[2], b[2]):
                retry.append(challenger)
                continue
            if count[champion] > count[challenger]:
                chain.append(f"{label[champion]}({count[champion]}) keeps vs {label[challenger]}({count[challenger]})")
                count[champion] += count[challenger]
                continue
            chain.append(f"{label[challenger]}({count[challenger]}) beats {label[champion]}({count[champion]})")
            count[challenger] += count[champion]
            retry += [challenger, *work]
            work, champion = [], None
        if champion is not None:
            predicted.append(champion)
        if chain:
            chains.append(chain)
        work = retry
    if not any(row[0] in derived for row in rows) or len(rows) < 2:
        return None
    kept = []
    if after:
        updated = {iv_trace.dst_sym(line) for line in after if " op=15b " in line and " tag=4 " in line}
        kept = sorted(row[0] for row in rows if row[0] in updated)
    return {
        "preheader": preheader,
        "rows": rows,
        "updates": updates,
        "chains": chains,
        "predicted": sorted(predicted),
        "observed": kept,
    }


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
        agree += result["observed"] == result["predicted"]
        print(f"=== loop {loop['loop']} preheader block {result['preheader']}")
        for number, text, uses, _ in result["rows"]:
            step, block = result["updates"][number]
            print(f"  #{number:<6} init {text:<18} step {step:<6} update block {block:<4} uses {uses}")
        for number, chain in enumerate(result["chains"], 1):
            print(f"    pass {number}:")
            for line in chain:
                print(f"      {line}")
        survivors = " ".join(f"#{n}" for n in result["predicted"])
        kept = " ".join(f"#{n}" for n in result["observed"])
        print(f"  predicted survivors {survivors}; still updated after merge #2: {kept}")
    print(f"rule A replay agrees on {agree}/{total} loops")


if __name__ == "__main__":
    main()
