"""Conditional affine address hypotheses, never a matching/equivalence gate.

A paired reference-bearing call supplies a hypothetical common EAX result. A
forward must-analysis retains affine expressions only where all known incoming
paths agree. Unsupported writes destroy values; calls preserve only the normal
32-bit x86 callee-saved registers. Indirect jumps end analysis.
"""

from __future__ import annotations

from collections import deque
from typing import Any

MOD = 1 << 32
REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
ALIASES = {
    alias: register
    for register, aliases in (
        ("eax", ("eax", "ax", "al", "ah")),
        ("ebx", ("ebx", "bx", "bl", "bh")),
        ("ecx", ("ecx", "cx", "cl", "ch")),
        ("edx", ("edx", "dx", "dl", "dh")),
        ("esi", ("esi", "si")),
        ("edi", ("edi", "di")),
        ("ebp", ("ebp", "bp")),
        ("esp", ("esp", "sp")),
    )
    for alias in aliases
}
Value = tuple[int, int]
State = dict[str, Value]


def add(a: Value | None, b: Value | None, scale: int = 1) -> Value | None:
    if a is None or b is None:
        return None
    return ((a[0] + scale * b[0]) % MOD, (a[1] + scale * b[1]) % MOD)


def address(insn, memory, state: State, *, displacement: bool) -> Value | None:
    if memory.segment or insn.addr_size != 4:
        return None
    base = state.get(insn.reg_name(memory.base)) if memory.base else (0, 0)
    index = state.get(insn.reg_name(memory.index)) if memory.index else (0, 0)
    return add(add(base, index, memory.scale), (0, memory.disp if displacement else 0))


def transfer(insn, before: State, symbolic_reference: bool = False) -> State:
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

    after = before.copy()
    _, writes = insn.regs_access()
    for reg in writes:
        after.pop(ALIASES.get(insn.reg_name(reg), ""), None)
    if CS_GRP_CALL in insn.groups:
        return {r: v for r, v in after.items() if r in ("ebx", "esi", "edi", "ebp")}
    if symbolic_reference:
        return after
    ops = insn.operands
    if not ops or ops[0].type != X86_OP_REG or ops[0].size != 4:
        return after
    destination = insn.reg_name(ops[0].reg)
    if destination not in REGISTERS:
        return after
    value = None
    if len(ops) == 2:
        source = (
            (0, ops[1].imm % MOD)
            if ops[1].type == X86_OP_IMM
            else (before.get(insn.reg_name(ops[1].reg)) if ops[1].type == X86_OP_REG else None)
        )
        if insn.mnemonic == "mov":
            value = source
        elif insn.mnemonic == "lea" and ops[1].type == X86_OP_MEM:
            value = address(insn, ops[1].mem, before, displacement=True)
        elif insn.mnemonic in ("add", "sub"):
            value = add(before.get(destination), source, -1 if insn.mnemonic == "sub" else 1)
        elif insn.mnemonic in ("shl", "sal") and ops[1].type == X86_OP_IMM:
            value = add((0, 0), before.get(destination), 1 << (ops[1].imm & 31))
    if len(ops) == 3 and insn.mnemonic == "imul" and ops[1].type == X86_OP_REG and ops[2].type == X86_OP_IMM:
        value = add((0, 0), before.get(insn.reg_name(ops[1].reg)), ops[2].imm)
    if value is not None:
        after[destination] = value
    return after


def decode(raw: bytes):
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    return {ins.address: ins for ins in md.disasm(raw, 0)}


def trace_return(
    instructions: dict[int, Any],
    call_offset: int,
    references: frozenset[int] = frozenset(),
    stop_calls: frozenset[int] = frozenset(),
) -> dict[int, State]:
    from capstone import CS_GRP_BRANCH_RELATIVE, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET
    from capstone.x86 import X86_OP_IMM

    origin = instructions[call_offset]
    start = call_offset + origin.size
    if start not in instructions:
        return {}
    states: dict[int, State] = {start: {"eax": (1, 0)}}
    pending = deque([start])
    while pending:
        offset = pending.popleft()
        insn = instructions[offset]
        # A later execution of the seed call is a different return value.
        if offset == call_offset or offset in stop_calls:
            continue
        outgoing = transfer(insn, states[offset], offset in references)
        successors = []
        groups = set(insn.groups)
        if not groups.intersection((CS_GRP_RET, CS_GRP_IRET, CS_GRP_INT)):
            if CS_GRP_JUMP in groups or (CS_GRP_BRANCH_RELATIVE in groups and CS_GRP_CALL not in groups):
                if offset not in references and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    successors.append(insn.operands[0].imm)
                if insn.mnemonic != "jmp":
                    successors.append(offset + insn.size)
            else:
                successors.append(offset + insn.size)
        # Calls may use the usual ABI; no claim is made about their arguments.
        if CS_GRP_CALL in groups:
            outgoing = {r: v for r, v in outgoing.items() if r in ("ebx", "esi", "edi", "ebp")}
        for successor in successors:
            if successor not in instructions:
                continue
            previous = states.get(successor)
            merged = (
                outgoing.copy() if previous is None else {r: v for r, v in previous.items() if outgoing.get(r) == v}
            )
            if previous is None or merged != previous:
                states[successor] = merged
                pending.append(successor)
    return states


def hypotheses(rows, raw: dict[str, bytes]):
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_MEM

    instructions = {s: decode(data) for s, data in raw.items()}
    references = {
        s: frozenset(r[s]["offset"] for r in rows if r[s] and r[s]["masked_references"]) for s in instructions
    }
    output = []
    for row in rows:
        a, b = row["target"], row["candidate"]
        if not a or not b or row["reference_status"] != "ok":
            continue
        if not all(CS_GRP_CALL in instructions[s][r["offset"]].groups for s, r in (("target", a), ("candidate", b))):
            continue
        states = {
            s: trace_return(
                instructions[s],
                r["offset"],
                references[s],
                frozenset(
                    other[s]["offset"]
                    for other in rows
                    if other[s]
                    and CS_GRP_CALL in instructions[s][other[s]["offset"]].groups
                    and other[s]["masked_references"] == r["masked_references"]
                ),
            )
            for s, r in (("target", a), ("candidate", b))
        }
        uses = []
        for pair in rows:
            left, right = pair["target"], pair["candidate"]
            if not left or not right or left["text"] == right["text"] or pair["reference_status"] != "ok":
                continue
            for ref_a, ref_b in zip(left["masked_references"], right["masked_references"], strict=True):
                if ref_a["kind"] != "disp":
                    continue
                values = {}
                for side, line, ref in (("target", left, ref_a), ("candidate", right, ref_b)):
                    insn = instructions[side][line["offset"]]
                    operand = insn.operands[ref["operand_index"]]
                    state = states[side].get(line["offset"], {})
                    if operand.type != X86_OP_MEM:
                        break
                    value = address(insn, operand.mem, state, displacement=False)
                    if value is None or value[0] == 0:
                        break
                    registers = [insn.reg_name(reg) for reg in (operand.mem.base, operand.mem.index) if reg]
                    values[side] = {
                        "offset": line["offset"],
                        "instruction": line["text"],
                        "affine": value,
                        "retained_registers": {r: state[r] for r in registers},
                        "memory_scale": operand.mem.scale,
                    }
                if (len(values) == 2 and values["target"]["affine"] == values["candidate"]["affine"]
                    and values["target"]["memory_scale"] != values["candidate"]["memory_scale"]):
                    uses.append({"reference_keys": sorted(set(ref_a["keys"]) & set(ref_b["keys"])), **values})
        if len(uses) >= 2:
            definitions = {}
            for side in instructions:
                definitions[side] = []
                for offset, state in sorted(states[side].items()):
                    insn = instructions[side][offset]
                    if CS_GRP_CALL in insn.groups:
                        continue
                    for register, value in transfer(insn, state, offset in references[side]).items():
                        if value[0] and state.get(register) != value:
                            definitions[side].append(
                                {
                                    "offset": offset,
                                    "instruction": f"{insn.mnemonic} {insn.op_str}",
                                    "register": register,
                                    "affine": value,
                                },
                            )
            output.append(
                {
                    "kind": "retained-index-scale",
                    "origin": {"target": a, "candidate": b},
                    "definitions": definitions,
                    "assumptions": [
                        "These paired calls return the same index on corresponding paths.",
                        "Intervening calls follow the x86 callee-saved register ABI.",
                        "Only statically decoded direct control-flow paths are considered.",
                        "This return-value lifetime ends at the next call with the same reference operands.",
                    ],
                    "claim": "Listed reference operands have equal affine offsets modulo 2^32 under the assumptions.",
                    "prediction": "Changing where the source retains the scaled index may change this group of operands together.",
                    "uses": uses,
                },
            )
    return output
