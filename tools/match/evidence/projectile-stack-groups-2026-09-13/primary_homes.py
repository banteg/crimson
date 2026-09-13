"""Map candidate declarations onto paired native primary-path stack accesses."""

import collections
import re

STACK = re.compile(r"\[esp(?:\+0x([0-9a-f]+))?\]")
BRANCH = re.compile(r"(j[a-z]+) L([0-9a-f]+)")


def frame_depths(lines):
    offsets = {line.offset: index for index, line in enumerate(lines)}
    result, queue = {0: 0}, collections.deque([0])
    frame = int(lines[0].text.split(", ")[1], 0)
    while queue:
        index = queue.popleft()
        line = lines[index]
        text, depth = line.text, result[index]
        if text.startswith("push "):
            depth -= 4
        elif text.startswith("pop "):
            depth += 4
        elif update := re.fullmatch(r"(sub|add) esp, (0x[0-9a-f]+)", text):
            depth += int(update[2], 0) * (1 if update[1] == "add" else -1)
        elif text == "call ADDR" and any("D3DXVec2Normalize" in ref.text for ref in line.masked_references):
            depth += 8  # The sole stdcall boundary; other calls in this function are cdecl.
        if text == "ret":
            assert depth == 0
            continue
        branch = BRANCH.fullmatch(text)
        successors = [offsets[int(branch[2], 16)]] if branch else []
        if not branch or branch[1] != "jmp":
            successors.append(index + 1)
        for successor in successors:
            assert successor < len(lines)
            if successor in result:
                assert result[successor] == depth, "Inconsistent stack depth at a control-flow join"
            else:
                result[successor] = depth
                queue.append(successor)
    assert len(result) == len(lines), "Unreachable or uncovered instructions"
    return [result[index] + frame + 16 for index in range(len(lines))]


def stack_map(result, listing_text, metadata):
    native, candidate = result.target_disassembly, result.candidate_disassembly
    native_depth, candidate_depth = frame_depths(native), frame_depths(candidate)
    frame = int(candidate[0].text.split(", ")[1], 0)
    symbols = {row["name"]: row["offset"] + frame + 16 for row in metadata["stack_layout"]["symbols"]}
    records, offset = {}, None
    for line in listing_text.splitlines():
        if found := re.match(r"  ([0-9a-f]{5})\s", line):
            offset = int(found[1], 16)
            records[offset] = line
        elif offset is not None and line.startswith("\t"):
            records[offset] += " " + line
    count = next(index for index, line in enumerate(native) if line.address == 0x421A0D)
    native_indices = {line.offset: index for index, line in enumerate(native[: count + 1])}
    candidate_indices = {line.offset: index for index, line in enumerate(candidate[: count + 1])}
    rows = collections.defaultdict(list)
    references = accesses = 0
    for index in range(count):
        left, right = native[index], candidate[index]
        if index:
            a = STACK.sub("[STACK]", BRANCH.sub(lambda found: found[1] + " BRANCH", left.text))
            b = STACK.sub("[STACK]", BRANCH.sub(lambda found: found[1] + " BRANCH", right.text))
            assert a == b, (index, left.text, right.text)
        left_branch, right_branch = BRANCH.fullmatch(left.text), BRANCH.fullmatch(right.text)
        if left_branch:
            assert right_branch
            assert native_indices[int(left_branch[2], 16)] == candidate_indices[int(right_branch[2], 16)]
        assert len(left.masked_references) == len(right.masked_references)
        for a, b in zip(left.masked_references, right.masked_references, strict=True):
            assert a.explained and b.explained and set(a.keys).intersection(b.keys)
            references += 1
        left_stack, right_stack = STACK.findall(left.text), STACK.findall(right.text)
        assert len(left_stack) == len(right_stack)
        if not left_stack:
            continue
        accesses += len(left_stack)
        names = [
            name for name in symbols if re.search(re.escape(name) + r"(?=\b|\+|\[|\s)", records.get(right.offset, ""))
        ]
        assert len(names) <= 1
        if names:
            assert len(left_stack) == 1
            name = names[0]
            native_home = int(left_stack[0] or "0", 16) + native_depth[index]
            candidate_home = int(right_stack[0] or "0", 16) + candidate_depth[index]
            rows[name].append(
                {
                    "native_address": left.address,
                    "candidate_offset": right.offset,
                    "native_variable_base": native_home - (candidate_home - symbols[name]),
                    "candidate_variable_base": symbols[name],
                },
            )
    return {
        "paired_instructions": count,
        "paired_references": references,
        "stack_accesses": accesses,
        "declarations": dict(rows),
        "scope": "Instruction order, internal branch destinations and explained references agree across this primary prefix after ignoring the prologue frame size and stack displacements. Candidate declarations label individual observed native accesses. Native reuse does not prove one original source declaration; no encoded-body exactness is claimed.",
    }
