"""Symbolic effects of small, straight-line x86 argument-preparation windows.

This is deliberately not a general emulator or a matching acceptance rule. Only
MOV (without memory loads), LEA, and PUSH are supported. There are no branches,
calls, arithmetic flags, floating point, or assumptions about callee behavior.
"""

import re
from dataclasses import dataclass

REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
CALLEE_SAVED = ("ebx", "ebp", "esi", "edi")


@dataclass(frozen=True)
class Value:
    """One unconstrained entry value or named address, plus a 32-bit offset."""

    base: str | None
    offset: int = 0

    def add(self, delta: int) -> "Value":
        return Value(self.base, (self.offset + delta) & 0xFFFFFFFF)


@dataclass(frozen=True)
class WindowEffects:
    registers: dict[str, Value]
    writes: tuple[tuple[Value, Value], ...]

    def call_inputs(self) -> tuple[Value, tuple[tuple[Value, Value], ...], tuple[Value, ...]]:
        """Project effects for a stack-argument call with volatile EAX/ECX/EDX.

        The user must separately prove the next callee/ABI and that no intervening
        instruction consumes those registers. This projection is invalid for a
        register argument, thiscall/fastcall receiver, or a live volatile value.
        Writes remain ordered, so no assumption about address disjointness is
        needed. Unmodified incoming memory is implicit.
        """
        return self.registers["esp"], self.writes, tuple(self.registers[r] for r in CALLEE_SAVED)


def evaluate_window(instructions: list[str]) -> WindowEffects:
    """Evaluate a closed subset of normalized Intel syntax; reject everything else.

    Named addresses use ``@name``. Bare ``ADDR`` masks are rejected: the caller
    must resolve and verify each external reference before supplying a name.
    Stack addresses are relative to the symbolic ESP at window entry.
    """
    registers = {name: Value(f"entry:{name}") for name in REGISTERS}
    writes: list[tuple[Value, Value]] = []

    def value(operand: str) -> Value:
        if operand in registers:
            return registers[operand]
        if re.fullmatch(r"@[A-Za-z_][A-Za-z_0-9]*", operand):
            return Value(operand)
        if re.fullmatch(r"-?(?:0x[0-9a-f]+|[0-9]+)", operand):
            return Value(None, int(operand, 0) & 0xFFFFFFFF)
        raise ValueError(f"unsupported value operand: {operand}")

    def address(operand: str) -> Value:
        parsed = re.fullmatch(r"dword \[(esp(?:[+-]0x[0-9a-f]+)?|@[A-Za-z_][A-Za-z_0-9]*)\]", operand)
        if parsed is None:
            raise ValueError(f"unsupported address operand: {operand}")
        base = parsed[1]
        if base.startswith("@"):
            return value(base)
        displacement = base[3:]
        return registers["esp"].add(int(displacement, 0) if displacement else 0)

    for instruction in instructions:
        if instruction.startswith("push "):
            pushed = value(instruction[5:])
            registers["esp"] = registers["esp"].add(-4)
            writes.append((registers["esp"], pushed))
            continue
        parsed = re.fullmatch(r"(mov|lea) ([^,]+), (.+)", instruction)
        if parsed is None:
            raise ValueError(f"unsupported instruction: {instruction}")
        opcode, destination, source = parsed.groups()
        if destination == "esp":
            raise ValueError("direct ESP assignment is outside this oracle")
        result = address(source) if opcode == "lea" else value(source)
        if destination in registers:
            registers[destination] = result
        elif opcode == "mov":
            writes.append((address(destination), result))
        else:
            raise ValueError(f"unsupported LEA destination: {destination}")
    return WindowEffects(registers, tuple(writes))
