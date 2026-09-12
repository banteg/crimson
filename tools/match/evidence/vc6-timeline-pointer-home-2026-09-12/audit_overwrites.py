"""Reject legacy overwrite hits with intervening overlapping byte/word reads.

This is a conservative direct-frame check of existing same-block candidates,
not alias analysis. Calls and branches are already boundaries in the legacy
screen. Unknown memory widths and address-taking block acceptance.
"""

import argparse
import json
import re
from pathlib import Path

MEMORY = re.compile(r"(?:(byte|word|dword|qword|tword) )?\[(esp|ebp)([+-](?:0x[0-9a-f]+|[0-9]+))?\]")
WIDTHS = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "tword": 10}


def overlapping_reads(lines):
    first = MEMORY.search(lines[0])
    assert first and first[1] == "dword"
    base, start = first[2], int(first[3] or "0", 0)
    sp = 0
    reads = []
    for index, text in enumerate(lines[1:-1], 1):
        opcode = text.split(" ", 1)[0]
        comma = text.find(",")
        for memory in MEMORY.finditer(text):
            if memory[2] != base:
                continue
            offset = int(memory[3] or "0", 0) + (sp if base == "esp" else 0)
            width = WIDTHS.get(memory[1])
            if opcode == "lea" or width is None:
                reads.append({"index": index, "instruction": text, "reason": "address or unknown width"})
                continue
            # Only MOV is classified as a pure write. Other instructions are
            # conservatively treated as reads, including read/modify/write.
            if opcode == "mov" and memory.start() < comma:
                continue
            if offset < start + 4 and start < offset + width:
                reads.append({"index": index, "instruction": text, "offset": offset, "width": width})
        if opcode == "push":
            sp -= 4
        elif opcode == "pop":
            sp += 4
        adjust = re.fullmatch(r"(add|sub) esp, (0x[0-9a-f]+|[0-9]+)", text)
        if adjust:
            sp += int(adjust[2], 0) * (1 if adjust[1] == "add" else -1)
    return reads


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    native = ["mov dword [esp+0x10], edi", "mov dword [esp+0x10], ebx"]
    assert not overlapping_reads(native)
    assert overlapping_reads([native[0], "mov ax, word [esp+0x12]", native[1]])
    assert overlapping_reads([native[0], "push eax", "mov al, byte [esp+0x16]", native[1]])
    assert not overlapping_reads([native[0], "mov ax, word [esp+0x14]", native[1]])
    rows = json.loads((args.root / "results.json").read_text())
    findings = []
    for row in rows:
        lines = (args.root / row["label"] / "candidate.asm").read_text().splitlines()
        for pair in row["same_block_stack_overwrites"]:
            context = lines[pair["first_index"] : pair["second_index"] + 1]
            assert context == pair["context"]
            reads = overlapping_reads(context)
            findings.append(
                {"label": row["label"], **pair, "overlapping_reads": reads, "passes_direct_frame_read_check": not reads},
            )
    rejected = [row for row in findings if row["overlapping_reads"]]
    assert {row["label"] for row in rejected} == {
        "memory/" + name + suffix
        for name in ["split-2-2", "split-3-1", "bytes-unrolled"]
        for suffix in ["", "-relative"]
    }
    witness = next(row for row in findings if row["label"] == "shape/body-copy-relative")
    assert witness["passes_direct_frame_read_check"] and witness["context"] == native
    args.out.write_text(
        json.dumps({"native_positive_control": native, "rejected_hits": len(rejected), "findings": findings}, indent=2)
        + "\n",
    )
    print(len(rejected), "overlapping-read false positives rejected; pointer witness passes")


if __name__ == "__main__":
    main()
