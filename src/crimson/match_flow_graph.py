"""Strict instruction-graph diagnostics, separate from match acceptance."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, NoReturn

from .match import MatchResult, _masked_reference_status

_LOCAL = re.compile(r"(j[a-z]+|loop(?:e|ne)?) L([0-9a-f]+)")
_CONDITIONS = frozenset({
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "je", "jg", "jge", "jl", "jle",
    "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno",
    "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz", "loop", "loope", "loopne",
})
_UNSUPPORTED_TRANSFERS = frozenset({
    "retf", "iret", "iretd", "int", "int1", "int3", "into", "ud2", "hlt", "syscall",
    "sysenter", "sysexit", "sysret", "ljmp", "lcall", "xbegin", "xabort",
})
_CAVEAT = (
    "Diagnostic only: compares decoded instruction graphs with direct local jumps transparent. "
    "Registers, stack operands, constants, ordered conditional edges, and reference evidence under "
    "the existing symbol/literal rules must agree; every instruction must be covered. "
    "Calls are opaque operations with fallthrough. "
    "This is not a runtime or C++ equivalence proof. Scoring, reference audits, encoded-body identity, "
    "and acceptance are unchanged. Unsupported control flow or incomplete coverage is not a match."
)


class _GraphFailure(Exception):
    def __init__(self, status: str, reason: str, **location: Any) -> None:
        super().__init__(reason)
        self.payload = {"status": status, "reason": reason, **location}


def flow_graph_payload(result: MatchResult) -> dict[str, Any]:
    """Attempt an entry-rooted bijection without masking any data operand."""
    sides = (result.target_disassembly, result.candidate_disassembly)
    pairs: dict[int, int] = {}
    reverse: dict[int, int] = {}
    jumps: tuple[set[int], set[int]] = (set(), set())
    references: list[dict[str, Any]] = []
    destinations: tuple[dict[int, int], dict[int, int]] = ({}, {})

    def unsupported(reason: str, side: int, index: int | None = None) -> NoReturn:
        raise _GraphFailure("unsupported", reason, side=("target", "candidate")[side], index=index)

    def prepare(side: int, texts: tuple[str, ...]) -> None:
        lines = sides[side]
        if not lines or tuple(line.text for line in lines) != texts:
            unsupported("Missing or inconsistent disassembly", side)
        offsets = {line.offset: index for index, line in enumerate(lines)}
        if len(offsets) != len(lines) or lines[0].offset != 0:
            unsupported("Instruction offsets must be unique and start at zero", side)
        for index, line in enumerate(lines):
            if line.size <= 0 or (index and lines[index - 1].offset + lines[index - 1].size != line.offset):
                unsupported("Instruction extents are not contiguous", side, index)
            mnemonic, _, operand = line.text.partition(" ")
            branch = _LOCAL.fullmatch(line.text)
            if mnemonic.startswith(("j", "loop")):
                if branch is None or mnemonic not in _CONDITIONS | {"jmp"}:
                    unsupported("Only direct local branches are modeled", side, index)
                destination = offsets.get(int(branch[2], 16))
                if destination is None:
                    unsupported("Branch destination is not an instruction boundary", side, index)
                destinations[side][index] = destination
                if line.masked_references:
                    unsupported("Local branch has unexpected masked references", side, index)
            elif mnemonic == "call" and (operand.startswith(("L", "R")) or not operand):
                unsupported("Local or unresolved relative calls are not modeled", side, index)
            elif mnemonic in _UNSUPPORTED_TRANSFERS or (
                mnemonic.startswith(("rep", "bnd", "notrack"))
                and operand.partition(" ")[0].startswith(("j", "loop", "call", "ret"))
            ):
                unsupported("Unsupported control transfer", side, index)
            if line.text.count("ADDR") != len(line.masked_references):
                unsupported("Masked operands and reference evidence disagree", side, index)

    def resolve(side: int, index: int) -> int:
        seen: set[int] = set()
        while True:
            if index >= len(sides[side]):
                unsupported("Fallthrough leaves the decoded function", side, index)
            if not sides[side][index].text.startswith("jmp "):
                return index
            if index in seen:
                unsupported("Unconditional jump cycle", side, index)
            seen.add(index)
            jumps[side].add(index)
            index = destinations[side][index]

    def children(side: int, index: int) -> tuple[int, ...]:
        mnemonic = sides[side][index].text.partition(" ")[0]
        if mnemonic == "ret":
            return ()
        fallthrough = resolve(side, index + 1)
        if index in destinations[side]:
            return resolve(side, destinations[side][index]), fallthrough
        return (fallthrough,)

    failure: dict[str, Any] | None = None
    try:
        prepare(0, result.target_lines)
        prepare(1, result.candidate_lines)
        pending = [(resolve(0, 0), resolve(1, 0))]
        while pending:
            left, right = pending.pop()
            location = {"target_index": left, "candidate_index": right}
            if left in pairs:
                if pairs[left] != right:
                    raise _GraphFailure("different", "Inconsistent target mapping", **location)
                continue
            if right in reverse:
                raise _GraphFailure("different", "Candidate mapping is not one-to-one", **location)
            a, b = sides[0][left], sides[1][right]
            a_op = a.text.partition(" ")[0] if left in destinations[0] else a.text
            b_op = b.text.partition(" ")[0] if right in destinations[1] else b.text
            if a_op != b_op:
                raise _GraphFailure("different", "Instruction or operand differs", **location)
            if a.masked_references or b.masked_references:
                status = _masked_reference_status(a.masked_references, b.masked_references)
                if status != "ok":
                    raise _GraphFailure("different", f"Mapped reference {status}", **location)
                references.append({
                    **location,
                    "target": [asdict(ref) for ref in a.masked_references],
                    "candidate": [asdict(ref) for ref in b.masked_references],
                })
            pairs[left], reverse[right] = right, left
            a_children, b_children = children(0, left), children(1, right)
            if len(a_children) != len(b_children):
                raise _GraphFailure("different", "Outgoing edge counts differ", **location)
            pending.extend(zip(a_children, b_children, strict=True))
        for side, mapped in enumerate((pairs, reverse)):
            if set(mapped) | jumps[side] != set(range(len(sides[side]))):
                unsupported("Entry traversal does not cover every instruction", side)
    except _GraphFailure as exc:
        failure = exc.payload

    return {
        "schema_version": 1,
        "caveat": _CAVEAT,
        "status": failure["status"] if failure else "matched",
        "all_instructions_covered": failure is None,
        "mapped_non_jump_instructions": len(pairs),
        "reference_instructions": len(references),
        "transparent_jumps": [sorted(indices) for indices in jumps],
        "edge_order": "taken_then_fallthrough",
        "failure": failure,
        "mapping": [
            {
                "target_index": left,
                "candidate_index": right,
                "target_offset": sides[0][left].offset,
                "candidate_offset": sides[1][right].offset,
                "target_instruction": sides[0][left].text,
                "candidate_instruction": sides[1][right].text,
            }
            for left, right in sorted(pairs.items())
        ],
        "references": references,
    }


def render_flow_graph(payload: dict[str, Any]) -> str:
    counts = [len(indices) for indices in payload["transparent_jumps"]]
    lines = [
        (
            f"flow graph: {payload['status']}; mapped={payload['mapped_non_jump_instructions']} "
            f"refs={payload['reference_instructions']} transparent-jumps={counts[0]}/{counts[1]}"
        ),
    ]
    if failure := payload["failure"]:
        lines.append(f"  {failure['reason']} ({failure})")
    lines.append(payload["caveat"])
    return "\n".join(lines)
