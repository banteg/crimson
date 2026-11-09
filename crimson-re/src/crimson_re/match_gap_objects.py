"""Verify classified freeware gaps against the COFF bytes following their source functions."""

from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import match, match_builds, match_source_receipt


def _expected_tails(
    inventory: list[dict[str, Any]], image_paths: dict[str, Path],
) -> Iterator[tuple[dict[str, Any], match.LoadedImage, dict[str, Any]]]:
    functions = {(r["image"], r["address"]): r for r in inventory if r.get("native_kind") == "function"}
    tails = defaultdict(list)
    for row in inventory:
        if row.get("ownership") == "game" and row.get("native_kind") in {"padding", "embedded_data"}:
            tails[row["image"], row["gap_evidence"]["function"]].append(row)
    images = {name: match.load_image(path) for name, path in image_paths.items()}
    for (name, address), ranges in sorted(tails.items()):
        function = functions[name, address]
        proof = function.get("proof")
        if not (function.get("candidate") == "source" and function["matched"] and proof and proof["body_byte_exact"]):
            continue
        start = cursor = function["end"]
        sites = []
        for gap in sorted(ranges, key=lambda r: r["address"]):
            if gap["address"] != cursor or gap["end"] <= cursor:
                raise ValueError(f"{name}/{address:#x}: noncontiguous executable gap")
            if gap["gap_evidence"]["type"] == "switch_destinations":
                sites.extend(range(cursor, gap["end"], 4))
            cursor = gap["end"]
        image = images[name]
        original = image.function_bytes(start, cursor)
        if len(original) != cursor - start:
            raise ValueError(f"{name}/{start:#x}: gap exceeds the original image")
        yield function, image, {
            "image": name, "function": address, "start": start, "end": cursor,
            "candidate_object_sha256": proof["candidate_object_sha256"],
            "sha256": hashlib.sha256(original).hexdigest(), "relocations": sites,
        }


def _check_object(
    obj: match.CoffObject, symbol_name: str | None, image: match.LoadedImage, receipt: dict[str, Any],
) -> None:
    candidates = [
        sym for sym in obj.symbols if match._is_function_symbol(sym)
        and (symbol_name is None or match._symbol_matches(sym.name, symbol_name))
    ]
    if len(candidates) != 1:
        raise ValueError(f"expected one COFF function symbol for {symbol_name!r}")
    symbol = candidates[0]
    section = obj.sections[symbol.section_number - 1]
    address, start, end = receipt["function"], receipt["start"], receipt["end"]
    offset = symbol.value + start - address
    stop = offset + end - start
    if stop > len(section.data) or any(
        match._is_function_symbol(sym) and sym.section_number == symbol.section_number and symbol.value < sym.value < stop
        for sym in obj.symbols
    ):
        raise ValueError(f"{symbol.name}: gap extends beyond its COFF function contribution")
    data = bytearray(section.data[offset:stop])
    relocations = [r for r in section.relocations if offset - 3 <= r.virtual_address < stop]
    sites = sorted(start + r.virtual_address - offset for r in relocations)
    if sites != receipt["relocations"]:
        raise ValueError(f"{symbol.name}: COFF relocations differ from the classified case table slots")
    if relocations:
        symbols = {sym.raw_index: sym for sym in obj.symbols}
        instructions = {
            va for va, *_ in match_builds._flow_disassembler().disasm_lite(image.function_bytes(address, start), address)
        }
        for relocation in relocations:
            target = symbols[relocation.symbol_index]
            if relocation.relocation_type != match.IMAGE_REL_I386_DIR32 or target.section_number != symbol.section_number:
                raise ValueError(f"{symbol.name}: expected a function-local DIR32 case relocation")
            index = relocation.virtual_address - offset
            addend, = struct.unpack_from("<I", data, index)
            dest = (address + target.value - symbol.value + addend) & 0xFFFFFFFF
            if dest not in instructions:
                raise ValueError(f"{symbol.name}: case target {dest:#x} is outside the function's instructions")
            struct.pack_into("<I", data, index, dest)
    if data != image.function_bytes(start, end):
        raise ValueError(f"{symbol.name}: emitted COFF bytes differ from the executable gap {start:#x}..{end:#x}")


def verify_tails(
    inventory: list[dict[str, Any]], statuses: list[match.ScratchStatus], image_paths: dict[str, Path],
) -> list[dict[str, Any]]:
    """Compare original gap bytes with the selected objects, after applying their local case relocations."""
    configs = {(status.config.image, status.address): status.config for status in statuses}
    receipts = []
    for function, image, receipt in _expected_tails(inventory, image_paths):
        config = configs.get((function["image"], function["address"]))
        if config is None:
            raise ValueError(f"{function['name']}: missing selected source candidate")
        raw = match._scratch_object_path(config).read_bytes()
        if match_source_receipt.candidate_object_sha256(raw, config) != receipt["candidate_object_sha256"]:
            raise ValueError(f"{function['name']}: candidate object differs from its source proof")
        _check_object(match.parse_coff_object(raw), config.symbol, image, receipt)
        receipts.append(receipt)
    return receipts


def validate_tails(
    inventory: list[dict[str, Any]], receipts: list[dict[str, Any]], image_paths: dict[str, Path],
) -> None:
    """Check saved coverage, original bytes, source object identities and relocation slots without the compiler."""
    if receipts != [receipt for _, _, receipt in _expected_tails(inventory, image_paths)]:
        raise ValueError("freeware gap object receipts differ from the original bytes, case slots or source proofs")
