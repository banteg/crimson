"""Classify reviewed freeware executable gaps from their bytes and references."""

from __future__ import annotations

import struct
from typing import Any

import capstone
from capstone import x86

from . import match as matchlib
from . import match_builds, match_gap_references


def _dense_count(compare: Any, guard: Any, jump: Any, targets: set[int]) -> int:
    """The same 32-bit index must reach the jump through an unsigned bounds check."""
    if (compare.mnemonic != "cmp" or len(compare.operands) != 2
            or compare.operands[0].type != x86.X86_OP_REG or compare.operands[0].size != 4
            or compare.operands[0].reg != jump.operands[0].mem.index
            or compare.operands[1].type != x86.X86_OP_IMM or not 0 <= compare.operands[1].imm <= 255
            or guard.mnemonic != "ja" or guard.operands[0].type != x86.X86_OP_IMM
            or guard.address in targets or jump.address in targets):
        return 0
    return compare.operands[1].imm + 1


def _tables(
    image: matchlib.LoadedImage, function: dict[str, Any], gap: dict[str, Any], pointer_sites: dict[int, set[int]],
) -> list[tuple[int, int, dict[str, Any]]] | None:
    """Prove the exact extents of dense and byte-remapped VC6 switch tables."""
    start, end = function["address"], function["end"]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    instructions = tuple(md.disasm(image.function_bytes(start, end), start))
    if not instructions or instructions[-1].address + instructions[-1].size != end:
        return None
    indices = {ins.address: idx for idx, ins in enumerate(instructions)}
    sparse = {jump: (lookup, count) for (lookup, jump), count in matchlib._vc6_sparse_switch_bounds(instructions).items()}
    direct_targets = {
        operand.imm for ins in instructions if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)
        for operand in ins.operands if operand.type == x86.X86_OP_IMM
    }
    spans = []
    for i, jump in enumerate(instructions):
        if jump.mnemonic != "jmp" or len(jump.operands) != 1 or jump.operands[0].type != x86.X86_OP_MEM:
            continue
        operand = jump.operands[0]
        mem = operand.mem
        table = mem.disp
        if table not in pointer_sites:
            continue
        if (operand.size != 4 or jump.disp_size != 4 or mem.base or not mem.index or mem.segment
                or mem.scale != 4 or table % 4):
            return None

        uses = []
        if jump.address in sparse:
            lookup_va, domain = sparse[jump.address]
            idx = indices[lookup_va]
            lookup = instructions[idx]
            guard = instructions[idx - 2] if instructions[idx - 1].mnemonic == "xor" else instructions[idx - 1]
            selectors = lookup.operands[1].mem.disp
            if not table < selectors < selectors + domain <= gap["end"]:
                return None
            count = max(image.function_bytes(selectors, selectors + domain)) + 1
            if table + 4 * count != selectors:
                return None
            uses.append((selectors, domain, 1, lookup, "switch_selectors"))
        else:
            if i < 2:
                return None
            compare, guard = instructions[i - 2 : i]
            count = _dense_count(compare, guard, jump, direct_targets)
            if not count:
                return None
        if guard.operands[0].imm not in indices or guard.operands[0].imm < jump.address + jump.size:
            return None
        table_end = table + 4 * count
        if table_end > gap["end"]:
            return None
        targets = struct.iter_unpack("<I", image.function_bytes(table, table_end))
        if any(dst not in indices for (dst,) in targets):
            return None
        uses.append((table, count, 4, jump, "switch_destinations"))
        for address, entries, width, ref, kind in uses:
            if pointer_sites.get(address) != {ref.address + ref.disp_offset}:
                return None
            spans.append((address, address + entries * width, {
                "function": start, "type": kind, "entries": entries, "entry_size": width,
                "reference": ref.address, "guard": guard.address,
            }))
    if {a for a, _, _ in spans} != pointer_sites.keys():
        return None
    return sorted(spans, key=lambda span: span[0])


def _padding(image: matchlib.LoadedImage, start: int, end: int, alignment: int) -> str | None:
    if start >= end or end % alignment or end - start >= alignment:
        return None
    data = image.function_bytes(start, end)
    if data == b"\x90" * (end - start):
        return "90"
    if alignment == 4 and data in (b"\x8b\xff", b"\x8d\x49\x00"):
        return data.hex()
    return None


def _classify_gap(
    image: matchlib.LoadedImage, function: dict[str, Any], gap: dict[str, Any], facts: match_gap_references.GapReferences,
) -> list[dict[str, Any]]:
    lo, hi = gap["address"], gap["end"]
    gap_sites = {va: facts.pointer_sites[va] for va in range(lo, hi) if va in facts.pointer_sites}
    if not facts.unsafe.isdisjoint(range(lo, hi)):
        return [gap]
    tables = _tables(image, function, gap, gap_sites) if gap_sites else []
    if tables is None:
        return [gap]
    result = []

    def append(start: int, end: int, kind: str, evidence: dict[str, Any]) -> None:
        incidental = []
        for site, reason in facts.incidental_sites.items():
            target = int.from_bytes(image.function_bytes(site, site + 4), "little")
            if start <= target < end:
                incidental.append({"storage": site, "apparent_target": target, "reason": reason})
        if incidental:
            evidence["incidental_references"] = incidental
        result.append({**gap, "address": start, "end": end, "size": end - start,
                       "native_kind": kind, "name": f"{evidence['type']}_{start:08x}", "gap_evidence": evidence})

    cursor = lo
    for start, end, evidence in tables:
        if start < cursor:
            return [gap]
        if start > cursor:
            encoding = _padding(image, cursor, start, 4)
            if encoding is None:
                return [gap]
            append(cursor, start, "padding", {"function": function["address"], "type": "alignment",
                                               "alignment": 4, "encoding": encoding})
        append(start, end, "embedded_data", evidence)
        cursor = end
    if cursor < hi:
        alignment = match_builds.FUNCTION_ALIGNMENT
        encoding = _padding(image, cursor, hi, alignment)
        if encoding is None:
            return [gap]
        append(cursor, hi, "padding", {"function": function["address"], "type": "alignment",
                                       "alignment": alignment, "encoding": encoding})
    return result


def classify(
    image: matchlib.LoadedImage, rows: list[dict[str, Any]], discovered: list[dict[str, Any]],
    *, entry_points: set[int],
) -> list[dict[str, Any]]:
    """Leave non-game and unsupported gaps unresolved, without changing byte ownership."""
    facts = match_gap_references.inspect(image, rows, discovered, entry_points=entry_points)
    result = []
    for i, row in enumerate(rows):
        if (row["native_kind"] == "unresolved" and row["ownership"] == "game" and 0 < i < len(rows) - 1
                and row["end"] % match_builds.FUNCTION_ALIGNMENT == 0
                and rows[i + 1]["native_kind"] == "function" and rows[i + 1]["address"] == row["end"]
                and rows[i - 1]["native_kind"] == "function" and rows[i - 1]["end"] == row["address"]):
            result.extend(_classify_gap(image, rows[i - 1], row, facts))
        else:
            result.append(row)
    return result
