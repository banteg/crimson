"""Locate the linker-collected VC6 C++ initializer registrations in the original data section."""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, cast

import pefile

# libcmt.lib(crt0dat.obj)::__cinit. Its two push pairs relocate to __xi_z/a and __xc_z/a;
# both calls relocate to __initterm. The first load is the optional FP initializer hook.
CINIT = re.compile(
    rb"\xa1....\x85\xc0\x74\x02\xff\xd0\x68....\x68....\xe8(....)"
    rb"\x68(....)\x68(....)\xe8(....)\x83\xc4\x10\xc3", re.DOTALL,
)
# __initterm walks [begin, end) in four-byte steps and calls each non-null pointer.
INITTERM = bytes.fromhex("56 8b 74 24 08 3b 74 24 0c 73 0d 8b 06 85 c0 74 02 ff d0 83 c6 04 eb ed 5e c3")


def _rows(pe: pefile.PE, image: str, functions: dict[int, str]) -> list[dict[str, Any]]:
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    sections = {s.Name.rstrip(b"\0"): s for s in cast(list[Any], pe.sections)}
    text, data = sections[b".text"], sections[b".data"]
    code, storage = text.get_data()[:text.Misc_VirtualSize], data.get_data()[:data.Misc_VirtualSize]
    text_base = base + text.VirtualAddress
    matches = list(CINIT.finditer(code))
    if len(matches) != 1:
        raise ValueError(f"{image}: missing or ambiguous VC6 C++ initializer caller")
    call = matches[0]
    targets = [call.end(i) + int.from_bytes(call[i], "little", signed=True) for i in (1, 4)]
    walker = targets[0]
    if walker != targets[1] or walker < 0 or code[walker:walker + len(INITTERM)] != INITTERM:
        raise ValueError(f"{image}: initializer range walker differs from VC6 __initterm")
    end, start = (int.from_bytes(call[i], "little") for i in (2, 3))
    # __xc_a and __xc_z are each a four-byte zero supplied by crt0init.obj.
    if (start != base + data.VirtualAddress or end <= start + 4 or (end - start) % 4
            or end - start + 4 > len(storage) or storage[:4] != bytes(4)
            or storage[end - start:end - start + 4] != bytes(4)):
        raise ValueError(f"{image}: inconsistent C++ initializer boundaries")
    slots = []
    for index, (destination,) in enumerate(struct.iter_unpack("<I", storage[4:end - start]), start=1):
        if destination not in functions:
            raise ValueError(f"{image}: C++ initializer slot references an unknown native function")
        slots.append({"address": start + 4 * index, "target": destination, "name": functions[destination]})
    if not pe.FILE_HEADER.Characteristics & 1:  # PE has retained base relocations.
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
        relocs = sorted((base + reloc.rva, reloc.type) for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ())
                        for reloc in block.entries if reloc.type and start - 3 <= base + reloc.rva < end + 4)
        if relocs != [(s["address"], 3) for s in slots]:
            raise ValueError(f"{image}: C++ initializer slots disagree with PE HIGHLOW relocations")

    def sentinel(address: int, name: str, section: str) -> dict[str, Any]:
        return {"image": image, "address": address, "size": 4, "name": name, "owner": "libraries",
                "member": "crt0init.obj", "input_section": section}

    return [
        sentinel(start, "crt_xc_begin", ".CRT$XCA"),
        {"image": image, "address": start + 4, "size": end - start - 4, "name": "crt_static_initializer_slots",
         "owner": "unknown", "cinit": text_base + call.start(), "initterm": text_base + walker, "slots": slots},
        sentinel(end, "crt_xc_end", ".CRT$XCZ"),
    ]


def attributions(image_paths: dict[str, Path], functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for image, path in sorted(image_paths.items()):
        native = {r["address"]: r["name"] for r in functions if r["image"] == image and r.get("native_kind") == "function"}
        with pefile.PE(str(path), fast_load=True) as pe:
            rows.extend(_rows(pe, image, native))
    return rows
