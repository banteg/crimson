"""Check every instruction, reference, branch and stack access, including the retry table."""

import collections
import re

STACK = re.compile(r"\[esp(?:\+0x([0-9a-f]+))?\]")
BRANCH = re.compile(r"(j[a-z]+) L([0-9a-f]+)")
TABLE = "compiler:vc6-local-jump-table:"


def table_targets(line):
    keys = {key for ref in line.masked_references for key in ref.keys if key.startswith(TABLE)}
    assert len(keys) == 1
    return [int(value, 0) for value in next(iter(keys))[len(TABLE) :].split(",")]


def frame_depths(lines):
    offsets = {line.offset: index for index, line in enumerate(lines)}
    depths, queue = {0: 0}, collections.deque([0])
    returns = []
    while queue:
        index = queue.popleft()
        line = lines[index]
        text, depth = line.text, depths[index]
        if text.startswith("push "):
            depth -= 4
        elif text.startswith("pop "):
            depth += 4
        elif update := re.fullmatch(r"(sub|add) esp, (0x[0-9a-f]+)", text):
            depth += int(update[2], 0) * (1 if update[1] == "add" else -1)
        # All calls here use caller cleanup, including the recorded console boundary.
        if text == "ret":
            assert depth == 0
            returns.append(line.offset)
            continue
        branch = BRANCH.fullmatch(text)
        if text == "jmp dword [eax*4+ADDR]":
            successors = [offsets[target] for target in table_targets(line)]
        else:
            successors = [offsets[int(branch[2], 16)]] if branch else []
            if not branch or branch[1] != "jmp":
                successors.append(index + 1)
        for successor in successors:
            assert successor < len(lines)
            if successor in depths:
                assert depths[successor] == depth, "Inconsistent stack depth at a control-flow join"
            else:
                depths[successor] = depth
                queue.append(successor)
    assert len(depths) == len(lines), "Uncovered instructions"
    assert sorted(returns) == [0x726, 0x3712]
    return [depths[index] for index in range(len(lines))]


def inspect(native, candidate):
    assert len(native) == len(candidate) == 3159
    nd, cd = frame_depths(native), frame_depths(candidate)
    references = branches = table_edges = accesses = 0
    homes = collections.Counter()
    for index, (left, right) in enumerate(zip(native, candidate, strict=True)):
        assert (left.offset, left.size, left.text) == (right.offset, right.size, right.text), index
        assert len(left.masked_references) == len(right.masked_references)
        for a, b in zip(left.masked_references, right.masked_references, strict=True):
            assert (a.operand_index, a.kind) == (b.operand_index, b.kind)
            assert a.explained and b.explained and set(a.keys).intersection(b.keys)
            references += 1
        if BRANCH.fullmatch(left.text):
            branches += 1
        if left.text == "jmp dword [eax*4+ADDR]":
            assert table_targets(left) == table_targets(right)
            table_edges += len(table_targets(left))
        aa, bb = STACK.findall(left.text), STACK.findall(right.text)
        assert len(aa) == len(bb)
        for a, b in zip(aa, bb, strict=True):
            nh, ch = int(a or "0", 16) + nd[index], int(b or "0", 16) + cd[index]
            assert nh == ch
            homes[nh] += 1
            accesses += 1
    assert references == 363 and table_edges == 4
    return {
        "instructions": len(native), "references": references, "direct_branches": branches,
        "retry_table_edges": table_edges, "returns": [0x431216, 0x434202],
        "stack_accesses": accesses, "entry_relative_homes": dict(sorted(homes.items())),
        "residuals": [], "scope": "Complete positional correspondence; every CFG node is reached and both returns balance. Encoded bytes are independently checked by the native matcher.",
    }
