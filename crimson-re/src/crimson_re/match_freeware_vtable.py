"""Recover the freeware Grim interface table from the versioned C++ interface and its matched methods."""

from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pefile

from . import match, match_builds, match_freeware_data_maps, match_freeware_storage

HEADER = "tools/match/include/grim2d_cpp.h"
VTABLE = "??_7IGrim2D_cpp@@6B@"
IMAGE = "grim.dll"


def _compile(version: str) -> bytes:
    # The API header marks methods pure for its callers. Make only their declarations
    # concrete in this probe so VC6 emits their real symbols instead of _purecall.
    header = (match.REPO_ROOT / HEADER).read_text()
    concrete = re.sub(r"\)\s*=\s*0;", ");", header)
    build = match_builds.load_registry().image(version, IMAGE)
    with tempfile.TemporaryDirectory(prefix="grim-vtable-") as temporary:
        directory = Path(temporary)
        (directory / "table.cpp").write_text(concrete + "\nIGrim2D_cpp interface_table_instance;\n")
        result = subprocess.run(
            [str(match.DEFAULT_MATCH_ROOT / "cl.sh"), "/c", "/O2", "/GR-", "/Zl",
             f"/DCL_BUILD={build.cl_build}", "/Fotable.obj", "table.cpp"],
            cwd=directory, env={**os.environ, "MSVC_VER": "msvc6.5"}, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise ValueError(f"VC6 failed to materialize the Grim interface:\n{result.stdout}{result.stderr}")
        return (directory / "table.obj").read_bytes()


def _method_bindings(contexts: list[match_freeware_data_maps.Context]) -> dict[str, int]:
    bindings: dict[str, int] = {}
    for function, config, obj, _ in contexts:
        if function["image"] != IMAGE:
            continue
        methods = [
            s.name for s in obj.symbols if match._is_function_symbol(s) and "@IGrim2D_cpp@@" in s.name
            and (config.symbol is None or match._symbol_matches(s.name, config.symbol))
        ]
        if len(methods) == 1:
            name, = methods
            if name in bindings and bindings[name] != function["address"]:
                raise ValueError(f"ambiguous Grim method linkage: {name}")
            bindings[name] = function["address"]
    return bindings


def _original(
    address: int, path: Path, target: match.LoadedImage, definitions: dict[int, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[int, int]]:
    with pefile.PE(str(path), fast_load=True) as pe:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        relocs = {base + entry.rva: entry.type for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ())
                  for entry in block.entries if entry.type}
        section = pe.get_section_by_rva(address - base)
        if section is None or section.Name.rstrip(b"\0") != b".rdata":
            raise ValueError("Grim interface table outside .rdata")
        end = base + section.VirtualAddress + section.Misc_VirtualSize
    methods = []
    cursor = address
    while cursor < end and relocs.get(cursor) == 3:
        pointer, = struct.unpack("<I", target.function_bytes(cursor, cursor + 4))
        if pointer not in definitions:
            raise ValueError(f"Grim virtual method at slot {cursor:#x} lacks an exact source proof")
        methods.append(definitions[pointer])
        cursor += 4
    if not methods or cursor in relocs:
        raise ValueError("invalid Grim virtual table relocation extent")
    return methods, relocs


def candidates(
    version: str, globals_: list[dict[str, Any]], functions: list[dict[str, Any]], image_paths: dict[str, Path],
    *, contexts: list[match_freeware_data_maps.Context] | None = None, saved: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    functions_by_va = {f["address"]: f for f in functions if f["image"] == IMAGE and match_freeware_data_maps._exact(f)}
    constructors = {a for a, f in functions_by_va.items() if f["name"] == "GRIM__GetInterface"}
    addresses = {g["address"] for g in globals_ if g["image"] == IMAGE and "grim_interface_vtable" in g["names"]
                 and any(ref["function"] in constructors and ref["addend"] == 0
                         and ref["symbol"] == "?grim_interface_vtable@@3PAXA" for ref in g["references"])}
    if not addresses and not saved:
        return []
    if len(addresses) != 1:
        raise ValueError("missing or ambiguous Grim interface construction witness")
    address, = addresses
    target = match.load_image(image_paths[IMAGE])
    all_functions = {f["address"]: f for f in functions if f["image"] == IMAGE and f.get("native_kind") == "function"}
    methods, pe_relocs = _original(address, image_paths[IMAGE], target, all_functions)
    if any(m["address"] not in functions_by_va for m in methods):
        if saved:
            raise ValueError("Grim vtable receipt depends on an unverified method")
        return []
    size = 4 * len(methods)
    metadata = {"name": "grim_interface_vtable", "image": IMAGE, "owner": "game", "address": address, "size": size,
                "source": HEADER, "proof_kind": "engine-vtable", "compiler": "msvc6.5", "symbol": VTABLE,
                "method_object_sha256": [m["proof"]["candidate_object_sha256"] for m in methods]}
    row: dict[str, Any]
    if saved is not None:
        if len(saved) != 1 or any(saved[0].get(k) != v for k, v in metadata.items()):
            raise ValueError("Grim interface table differs from the mapped method proofs")
        row = saved[0]
        if (not re.fullmatch(r"[0-9a-f]{64}", row.get("object_sha256", "")) or row["storage"] != "coff-data"
                or row["extent_evidence"] != "vc6-vtable-comdat"):
            raise ValueError("invalid Grim interface object receipt")
    else:
        if contexts is None:
            raise ValueError("missing compiled methods for the Grim interface table")
        raw = _compile(version)
        obj = match.parse_coff_object(raw)
        tables = [sym for sym in obj.symbols if sym.name == VTABLE and sym.section_number > 0]
        if len(tables) != 1:
            raise ValueError("VC6 did not emit the primary Grim interface table")
        table, = tables
        section = obj.sections[table.section_number - 1]
        if table.value or section.comdat_key != VTABLE or section.logical_size != size:
            raise ValueError("Grim vtable COMDAT extent differs from the original")
        bindings = _method_bindings(contexts)
        receipt = match_freeware_storage.prove(
            obj, table, address, target, relocations=pe_relocs,
            bindings={sym.raw_index: bindings[sym.name] for sym in obj.symbols if sym.name in bindings},
        )
        if receipt is None:
            raise ValueError("compiled Grim vtable bytes or symbolic slots differ from the original")
        row = {**metadata, **receipt, "object_sha256": match.coff_sha256(raw)}
    match_freeware_storage.validate(row, target, relocations=pe_relocs)
    fixups = row["relocations"]
    if not isinstance(fixups, list) or len(fixups) != len(methods):
        raise ValueError("incomplete Grim vtable")
    for i, (fixup, method) in enumerate(zip(fixups, methods, strict=True)):
        if (fixup["offset"] != 4 * i or fixup["target"] != method["address"] or fixup["addend"]
                or not fixup["symbol"].startswith(f"?{method['name']}@IGrim2D_cpp@@")):
            raise ValueError(f"Grim vtable slot {i} differs from its source method")
    # Bind the decorated method signatures in the saved section to its complete
    # source object receipt. Native bytes independently verify the slot destinations.
    linkage = "\0".join([str(row["object_sha256"]), *(f["symbol"] for f in fixups)])
    abi_sha256 = hashlib.sha256(linkage.encode("ascii")).hexdigest()
    if saved is not None and row.get("abi_sha256") != abi_sha256:
        raise ValueError("Grim vtable symbolic COFF receipt differs")
    return [{**row, "abi_sha256": abi_sha256}]
