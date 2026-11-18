"""Attribute complete VC6/DirectX archive contributions in freeware data sections."""

from __future__ import annotations

import hashlib
import json
import struct
from collections import defaultdict
from pathlib import Path
from typing import Any

import capstone
import pefile
from capstone import x86

from . import library_match, match_builds, match_data_report
from . import match as matchlib

PLAN = matchlib.REPO_ROOT / "tools/native/freeware_library_sections.json"
PROVIDERS = matchlib.REPO_ROOT / "tools/native/providers/crimsonland.exe.json"
OWNERS = {"directx-8.1-d3dx8": "libs.d3dx8", "vc6-sp6-libcmt": "libs.msvc6-crt"}


def _verify_member(row: dict[str, Any], raw: bytes) -> None:
    obj = matchlib.parse_coff_object(raw)
    section = obj.sections[row["section"] - 1]
    symbols = {s.raw_index: s for s in obj.symbols}
    relocations = []
    for reloc in section.relocations:
        target = symbols[reloc.symbol_index]
        # These DIR32s are relative to a symbol at the start of their own section.
        if (reloc.relocation_type != matchlib.IMAGE_REL_I386_DIR32 or target.section_number != section.index
                or target.value != 0):
            raise ValueError(f"unsupported library initializer relocation in {row['member']}")
        addend, = struct.unpack_from("<I", section.data, reloc.virtual_address)
        relocations.append([reloc.virtual_address, addend])
    anchor = bytes.fromhex(row["anchor_hex"])
    start = row["anchor_offset"]
    if (section.name != row["section_name"] or section.logical_size != len(section.data)
            or len(section.data) != row["size"] or hashlib.sha256(section.data).hexdigest() != row["sha256"]
            or section.data[start:start + len(anchor)] != anchor or sorted(relocations) != row["relocations"]):
        raise ValueError(f"archive section differs from freeware data proof: {row['member']}")
    names = {(s.value, s.name) for s in obj.symbols if s.section_number == section.index}
    member = row["member"].split("\\")[-1]
    if ((0, row["symbol"]) not in names and row["symbol"] != f"{member}({section.name})"
            or any((offset, name) not in names for offset, name in row["symbols"])):
        raise ValueError(f"archive symbol differs from freeware data proof: {row['member']}")


def _plan() -> list[dict[str, Any]]:
    payload = json.loads(PLAN.read_text())
    if payload.get("schema") != 1:
        raise ValueError("unsupported freeware library data plan")
    providers = {r["id"]: r for r in json.loads(PROVIDERS.read_text())["archives"]}
    sections = payload["sections"]
    seen = set()
    for row in sections:
        key = row["archive"], row["member"], row["section"]
        if (key in seen or row["archive"] not in OWNERS or row["size"] < 64 or row["section"] < 1
                or row["section_name"] not in match_data_report.DATA_SECTIONS):
            raise ValueError(f"invalid or duplicate archive data section: {key}")
        seen.add(key)
        anchor = bytes.fromhex(row["anchor_hex"])
        if not anchor or not 0 <= row["anchor_offset"] <= row["size"] - len(anchor):
            raise ValueError(f"invalid archive data anchor: {key}")
        previous = -4
        for slot, target in row["relocations"]:
            if slot < previous + 4 or slot > row["size"] - 4 or not 0 <= target < row["size"]:
                raise ValueError(f"invalid local archive relocation: {key}")
            previous = slot
    for archive_id in sorted({row["archive"] for row in sections}):
        provider = providers[archive_id]
        archive_path = matchlib.REPO_ROOT / provider["path"]
        if archive_path.is_file():
            raw = archive_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != provider["sha256"]:
                raise ValueError(f"library archive differs from its provider pin: {archive_id}")
            members = {m.name: m.data for m in library_match.parse_coff_archive(raw)}
            for row in (r for r in sections if r["archive"] == archive_id):
                _verify_member(row, members[row["member"]])
    return sections


def _locate(
    row: dict[str, Any], regions: list[tuple[int, bytes]], relocations: dict[int, int] | None,
) -> int | None:
    """Find a unique complete contribution, normalizing only its actual local relocations."""
    anchor = bytes.fromhex(row["anchor_hex"])
    found = None
    for region, raw in regions:
        cursor = 0
        while (index := raw.find(anchor, cursor)) >= 0:
            cursor = index + 1
            start = index - row["anchor_offset"]
            if start < 0 or start + row["size"] > len(raw):
                continue
            va = region + start
            if relocations is not None:
                actual = {site - va: kind for site, kind in relocations.items() if va - 3 <= site < va + row["size"]}
                if actual != {offset: 3 for offset, _ in row["relocations"]}:
                    continue
            original = bytearray(raw[start:start + row["size"]])
            for slot, target in row["relocations"]:
                pointer, = struct.unpack_from("<I", original, slot)
                if pointer != va + target:
                    break
                struct.pack_into("<I", original, slot, target)
            else:
                if hashlib.sha256(original).hexdigest() == row["sha256"]:
                    if found is not None:
                        return None
                    found = va
    return found


def _references(
    image: matchlib.LoadedImage, functions: list[dict[str, Any]], addresses: set[int],
) -> dict[int, dict[str, tuple[int, int]]]:
    """Capture a decoded address operand from each possible owner at each data address."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    result: dict[int, dict[str, tuple[int, int]]] = defaultdict(dict)
    owners = {"game", *OWNERS.values()}
    for function in functions:
        owner = function.get("ownership")
        if function.get("native_kind") != "function" or owner not in owners:
            continue
        start, end = function["address"], function["end"]
        for ins in md.disasm(image.function_bytes(start, end), start):
            for operand in ins.operands:
                if operand.type == x86.X86_OP_MEM:
                    target = operand.mem.disp
                elif operand.type == x86.X86_OP_IMM:
                    target = operand.imm
                else:
                    continue
                if target in addresses:
                    result[target].setdefault(owner, (start, ins.address))
    return result


def attributions(version: str, image_paths: dict[str, Path], functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return ownership-only evidence for archive sections with independently corroborated placements."""
    sections = _plan()
    registry = match_builds.load_registry()
    result = []
    for image, path in sorted(image_paths.items()):
        with pefile.PE(str(path), fast_load=True) as pe:
            base = pe.OPTIONAL_HEADER.ImageBase
            regions: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
            for section in pe.sections:
                name = section.Name.rstrip(b"\0").decode("ascii")
                if name in match_data_report.DATA_SECTIONS and not (section.Characteristics & match_builds.IMAGE_SCN_MEM_EXECUTE):
                    raw = section.get_data()[:section.Misc_VirtualSize]
                    regions[name].append((base + section.VirtualAddress, raw))
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
            relocations = None if pe.FILE_HEADER.Characteristics & 1 else {
                base + r.rva: r.type for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ()) for r in block.entries if r.type
            }
        placements = [(va, row) for row in sections if row["section_name"] in regions
                      and (va := _locate(row, regions[row["section_name"]], relocations)) is not None]
        target = registry.image(version, image)
        names = {(matchlib.parse_int(r["address"]), r["name"])
                 for r in json.loads(target.target.data_map_path.read_text())["entries"]}
        addresses = {p for va, row in placements for p in range(va, va + row["size"])}
        refs = _references(matchlib.load_image(path), [r for r in functions if r["image"] == image], addresses)
        for va, row in placements:
            owner = OWNERS[row["archive"]]
            observed = [(p, refs[p]) for p in range(va, va + row["size"]) if p in refs]
            if any("game" in consumers for _, consumers in observed):
                continue  # A pooled value used by game code has ambiguous ownership.
            label = next((symbol for offset, symbol in row["symbols"] if (va + offset, symbol) in names), None)
            ref = next(([p, *consumers[owner]] for p, consumers in observed if owner in consumers), None)
            if not (label or ref or row["relocations"]):
                continue
            evidence = {"archive": row["archive"], "member": row["member"], "section": row["section"],
                        "section_sha256": row["sha256"], "section_label": row["symbol"], "local_dir32": row["relocations"]}
            if label:
                evidence["mapped_symbol"] = label
            if ref:
                address, function, instruction = ref
                evidence["native_reference"] = {"target": address, "function": function, "instruction": instruction}
            member = row["member"].split("\\")[-1]
            result.append({"image": image, "address": va, "size": row["size"], "name": f"{member}({row['section_name']})",
                           "owner": "libraries", "evidence": evidence})
    return sorted(result, key=lambda r: (r["image"], r["address"], r["name"]))
