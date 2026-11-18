"""Check native game/engine gaps for entry points, incoming flow and address-taken bytes."""
from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import match as matchlib


@dataclass
class GapReferences:
    unsafe: set[int]
    pointer_sites: dict[int, set[int]]  # Target VA to storage VAs of full 32-bit pointers.
    incidental_sites: dict[int, str]  # Storage VA to the verified data contents it overlaps.


def pe_entry_points(path: Path) -> set[int]:
    """Include PE entry and export addresses, which are encoded as RVAs."""
    import pefile

    with pefile.PE(str(path), fast_load=True) as pe:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        entries = {base + rva} if rva else set()
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exports:
            entries.update(base + symbol.address for symbol in exports.symbols if symbol.address and not symbol.forwarder)
        return entries


def _incidental_data(image: matchlib.LoadedImage, site: int) -> str | None:
    # A base relocation or loader-owned slot is stronger evidence than even an exact literal match.
    if any(lo < site + 4 and site < hi for lo, hi in image.content_exclusions):
        return None
    # The complete relocation-free .data section of VC6 libcmt.lib(constpow.obj) is present.
    # crt_multtenpow12 indexes the 12-byte __pow10pos records through the address at 0x426094.
    if site in {0x42E299, 0x42E2A5} and hashlib.sha256(image.function_bytes(0x42E248, 0x42E504)).hexdigest() == (
        "1be6b9bcfbebc370831ae298fcf28d4fbfe45d9537d311ef7b9ab09ac525e9f0"
    ):
        return "straddles two 12-byte records of constpow.obj::__pow10pos at 0x42e248"
    # These two independently accessed IEEE floats straddle the apparent pointer in the 1.4.0 EXE.
    if (
        site == 0x42D40D
        and image.function_bytes(0x42D40C, 0x42D414) == bytes.fromhex("9a991940 00409244")
        and image.function_bytes(0x41EF05, 0x41EF0B) == bytes.fromhex("d80d 0cd44200")  # fmul [2.4f]
        and image.function_bytes(0x41EEA4, 0x41EEAA) == bytes.fromhex("d805 10d44200")  # fadd [1170.0f]
    ):
        return "straddles the 2.4f and 1170.0f operands at 0x42d40c and 0x42d410"
    # DirectX 8.1 d3dx8.lib(d3dxmathx86.obj) supplies this complete, relocation-free float table.
    if site == 0x10049E86 and hashlib.sha256(image.function_bytes(0x10049CA0, 0x1004ACA0)).hexdigest() == (
        "eb0f36f3077c316b810db07ef265e08363ee902ae52cba4f08eb5ae477963d41"
    ):
        return "straddles two float coefficients of d3dxmathx86.obj::_invSqrtTab at 0x10049ca0"
    return None


def _pointer_sites(image: matchlib.LoadedImage, gaps: set[int]) -> tuple[dict[int, set[int]], dict[int, str]]:
    # A callback table can live in writable data and a packed pointer can be unaligned.
    data = memoryview(image.mapped)
    pointers: dict[int, set[int]] = defaultdict(set)
    incidental: dict[int, str] = {}
    for alignment in range(4):
        span = data[alignment:]
        end = len(span) - len(span) % 4
        for index, (target,) in enumerate(struct.iter_unpack("<I", span[:end])):
            if target in gaps:
                site = image.image_base + alignment + 4 * index
                reason = _incidental_data(image, site)
                if reason:
                    incidental[site] = reason
                else:
                    pointers[target].add(site)
    return dict(pointers), incidental


def inspect(
    image: matchlib.LoadedImage,
    rows: list[dict[str, Any]],
    discovered: list[dict[str, Any]],
    *,
    entry_points: Iterable[int] = (),
) -> GapReferences:
    """Find references before treating the space after a retained body as data or alignment.

    Scan both the retained instruction streams and independently discovered basic blocks.
    They can have different entry points. A missing or ambiguous terminal instruction
    leaves the corresponding gap unsafe. Unrecognized absolute pointers stay in the result.
    """
    import capstone

    gaps = [row for row in rows if row["ownership"] == "game" and row["native_kind"] == "unresolved"]
    gap_bytes = {va for row in gaps for va in range(row["address"], row["end"])}
    if not gap_bytes:
        return GapReferences(set(), {}, {})
    starts = {row["address"] for row in gaps}
    unsafe = gap_bytes.intersection(entry_points)
    blocks = {(block["address"], block["end"]) for function in discovered for block in function["blocks"]}
    for start, end in blocks:
        unsafe.update(gap_bytes.intersection(range(start, end)))
    unsafe.update(function["address"] for function in discovered if function["address"] in gap_bytes)

    spans = blocks.union((row["address"], row["end"]) for row in rows if row["native_kind"] == "function")
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    terminal: set[int] = set()
    for start, end in sorted(spans):
        for address, size, mnemonic, operand in disassembler.disasm_lite(image.function_bytes(start, end), start):
            mnemonic = mnemonic.rsplit(" ", 1)[-1]  # Strip any instruction prefix.
            following = address + size
            if following in starts:
                if mnemonic in {"ret", "retf", "jmp", "ljmp"}:
                    terminal.add(following)
                else:
                    unsafe.add(following)
            if mnemonic.startswith(("j", "loop")) or mnemonic in {"call", "lcall", "ljmp", "xbegin"}:
                # Direct far transfers include a segment selector before the offset.
                destination = operand.rsplit(", ", 1)[-1]
                if destination.startswith("0x") or destination.isdecimal():
                    target = int(destination, 0)
                    if target in gap_bytes:
                        unsafe.add(target)
    unsafe.update(starts - terminal)
    pointers, incidental = _pointer_sites(image, gap_bytes)
    return GapReferences(unsafe, pointers, incidental)
