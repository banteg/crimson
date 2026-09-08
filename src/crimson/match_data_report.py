"""Source-built data evidence for the public matching report.

Native definitions locate and describe reference objects; they do not themselves
earn matching credit. C and C++ definitions are compiled by VC6 with sizeof assertions;
their COFF storage and symbolic pointer relocations are checked against the reference.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import match as matchlib
from . import native_link

MANIFEST = matchlib.REPO_ROOT / "tools/native/data_candidates.json"
DATA_SECTIONS = frozenset({".rdata", ".data", ".data1", ".bss"})


def section_inventory() -> list[dict[str, Any]]:
    """Count virtual section extents, including zero-fill but not file padding."""
    import pefile

    sections = []
    for image in matchlib.TRACKED_IMAGE_NAMES:
        with pefile.PE(str(matchlib._paths_for_image(image)[0]), fast_load=True) as pe:
            base = int(pe.OPTIONAL_HEADER.ImageBase)
            for section in pe.sections:
                name = section.Name.rstrip(b"\0").decode("ascii")
                if name not in DATA_SECTIONS or not section.Misc_VirtualSize:
                    continue
                if section.Characteristics & 0x20000000:
                    raise ValueError(f"executable data section: {image}:{name}")
                sections.append({
                    "image": image, "name": name,
                    "address": base + int(section.VirtualAddress),
                    "size": int(section.Misc_VirtualSize),
                })
    return sections


def _load_plan() -> tuple[str, list[dict[str, Any]]]:
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("schema") != 1:
        raise ValueError("unsupported data candidate manifest")
    definitions = {}
    for image in matchlib.TRACKED_IMAGE_NAMES:
        payload = native_link.load_native_data_definitions(
            image, reference_image_path=matchlib._paths_for_image(image)[0],
        )
        if payload is None:
            raise ValueError(f"missing native data definitions for {image}")
        definitions[image] = {row["name"]: row for row in payload["entries"]}
    reference_relocations = _reference_relocations()
    seen = set()
    sources = []
    for source in manifest["sources"]:
        image = source["image"]
        path = Path(source["source"])
        if path.is_absolute() or ".." in path.parts or not path.is_relative_to("tools/match/data"):
            raise ValueError(f"invalid data source path: {path}")
        if path.suffix not in {".c", ".cpp"}:
            raise ValueError(f"unsupported data source language: {path}")
        internal = source.get("internal_symbols", [])
        if len(set(internal)) != len(internal) or not set(internal).issubset(source["symbols"]):
            raise ValueError(f"invalid internal data symbols: {path}")
        if internal and path.suffix != ".c":
            raise ValueError(f"internal data symbols require C linkage: {path}")
        rows = []
        for name in source["symbols"]:
            if re.fullmatch(r"[A-Za-z_]\w*", name) is None or (image, name) in seen:
                raise ValueError(f"invalid or duplicate data symbol: {image}:{name}")
            seen.add((image, name))
            definition = definitions[image][name]
            if not definition.get("size"):
                raise ValueError(f"data candidate has no independently recorded extent: {name}")
            rows.append({
                "image": image, "name": name, "source": path.as_posix(),
                "linkage": "internal" if name in internal else "external",
                "address": definition["address"], "size": definition["size"],
                **_initializer_plan(definition, reference_relocations[image]),
            })
        if not rows:
            raise ValueError(f"empty data source: {path}")
        sources.append({"source": path.as_posix(), "rows": rows})
    return manifest["compiler"], sources


def _reference_relocations() -> dict[str, list[tuple[int, int]] | None]:
    import pefile

    result = {}
    for image in matchlib.TRACKED_IMAGE_NAMES:
        with pefile.PE(str(matchlib._paths_for_image(image)[0])) as pe:
            base = int(pe.OPTIONAL_HEADER.ImageBase)
            result[image] = None if pe.FILE_HEADER.Characteristics & 1 else [(base + relocation.rva, relocation.type)
                             for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
                             for relocation in block.entries if relocation.type]
    return result


def _initializer_plan(definition: dict[str, Any], reference_relocations: list[tuple[int, int]] | None) -> dict[str, Any]:
    """Keep expected bytes and symbolic targets independent of compiled output."""
    size = definition["size"]
    target = definition.get("initializer_target")
    symbols = definition.get("initializer_symbols") or []
    if target:
        symbols = [{"offset": 0, "address": target["address"], "symbol": "_" + target["name"]}]
    if symbols:
        expected = native_link._symbol_initializer_bytes(size, symbols)
    elif definition.get("initializer_hex") is not None:
        expected = bytes.fromhex(definition["initializer_hex"])
    elif definition.get("initializer_fill") is not None:
        expected = bytes.fromhex(definition["initializer_fill"]) * size
    else:
        raise ValueError(f"missing reference initializer: {definition['name']}")
    if len(expected) != size:
        raise ValueError(f"invalid reference initializer size: {definition['name']}")
    # Literal pointer bytes do not establish the target's identity. Require the
    # symbol recipe before accepting any object containing PE base relocations.
    start = definition["address"]
    offsets = []
    for address, kind in reference_relocations or []:
        if kind and start - 3 <= address < start + size:
            if kind != 3 or address < start or address + 4 > start + size:
                raise ValueError(f"unsupported reference relocation: {definition['name']}")
            offsets.append(address - start)
    if reference_relocations is not None and sorted(offsets) != sorted(item["offset"] for item in symbols):
        raise ValueError(f"pointer initializer needs symbolic relocation evidence: {definition['name']}")
    return {"initializer_sha256": hashlib.sha256(expected).hexdigest(),
            "initializer_hex": expected.hex(), "relocations": symbols}


def _check_storage(
    obj: matchlib.CoffObject, name: str, size: int, *,
    expected: bytes | None = None, relocations: list[dict[str, Any]] | None = None,
    linkage: str = "external",
) -> str:
    expected = bytes(size) if expected is None else expected
    relocations = [] if relocations is None else relocations
    if size <= 0 or len(expected) != size:
        raise ValueError(f"invalid data object size: {name}")
    if linkage not in {"external", "internal"}:
        raise ValueError(f"invalid data linkage: {name}")
    storage_class = matchlib.IMAGE_SYM_CLASS_STATIC if linkage == "internal" else matchlib.IMAGE_SYM_CLASS_EXTERNAL
    symbols = [symbol for symbol in obj.symbols
               if symbol.storage_class == storage_class
               and (symbol.name == f"_{name}" or (linkage == "external" and symbol.name.startswith(f"?{name}@@3")))]
    if len(symbols) != 1:
        raise ValueError(f"data object does not define exactly one {name}")
    symbol = symbols[0]
    if linkage == "external" and symbol.section_number == 0 and symbol.value == size:
        if expected != bytes(size) or relocations:
            raise ValueError(f"common storage differs from reference initializer: {name}")
        return "coff-common"
    if symbol.section_number <= 0:
        raise ValueError(f"data object has no storage for {name}")
    section = obj.sections[symbol.section_number - 1]
    start, end = symbol.value, symbol.value + size
    if section.characteristics & 0x20000000 or section.logical_size is None or end > section.logical_size:
        raise ValueError(f"invalid data object extent: {name}")
    actual_relocations = []
    for relocation in section.relocations:
        width = matchlib.IMAGE_REL_I386_WIDTHS.get(relocation.relocation_type)
        if width is None:
            raise ValueError(f"unsupported COFF relocation: {name}")
        if relocation.virtual_address < end and relocation.virtual_address + width > start:
            actual_relocations.append(relocation)
    if len(actual_relocations) != len(relocations):
        raise ValueError(f"data relocation count differs: {name}")
    data = bytearray(bytes(size) if section.characteristics & matchlib.IMAGE_SCN_CNT_UNINITIALIZED_DATA
                     else section.data[start:end])
    expected_by_offset = {row["offset"]: row for row in relocations}
    if len(expected_by_offset) != len(relocations):
        raise ValueError(f"duplicate reference relocation: {name}")
    seen = set()
    symbol_by_index = {row.raw_index: row for row in obj.symbols}
    for relocation in actual_relocations:
        offset = relocation.virtual_address - start
        target = expected_by_offset.get(offset)
        if (target is None or offset in seen or offset < 0 or offset + 4 > size
                or relocation.relocation_type != matchlib.IMAGE_REL_I386_DIR32):
            raise ValueError(f"data relocation offset/type differs: {name}")
        seen.add(offset)
        ref = symbol_by_index.get(relocation.symbol_index)
        if ref is None or ref.name != target["symbol"]:
            raise ValueError(f"data relocation target differs: {name}")
        # A literal address hidden in the COFF addend must not earn pointer credit.
        if struct.unpack_from("<I", data, offset)[0] != 0:
            raise ValueError(f"unexpected pointer addend: {name}")
        struct.pack_into("<I", data, offset, target["address"])
    if data != expected:
        raise ValueError(f"compiled data differs from reference initializer: {name}")
    return "coff-bss" if section.characteristics & matchlib.IMAGE_SCN_CNT_UNINITIALIZED_DATA else "coff-data"


def refresh_evidence(configs: list[matchlib.ScratchConfig]) -> dict[str, Any]:
    compiler, sources = _load_plan()
    # The function report's external-input recorder pins this same compiler and
    # runner, including CRIMSON_MSVC_ROOT/WIBO overrides.
    if not any(c.compiler == compiler and c.archive is None and c.import_thunk is None for c in configs):
        raise ValueError(f"data compiler is not covered by the report toolchain fingerprint: {compiler}")
    candidates = []
    for source in sources:
        source_path = matchlib.REPO_ROOT / source["source"]
        include = "Z:" + source_path.as_posix().replace("/", "\\")
        assertions = "\n".join(
            f"typedef char data_size_{index}[(sizeof({row['name']}) == {row['size']}) ? 1 : -1];"
            for index, row in enumerate(source["rows"])
        )
        with tempfile.TemporaryDirectory(prefix="crimson-data-") as temporary:
            directory = Path(temporary)
            harness = "verify" + source_path.suffix
            (directory / harness).write_text(f'#include "{include}"\n{assertions}\n')
            result = subprocess.run(
                [str(matchlib.DEFAULT_MATCH_ROOT / "cl.sh"), "/c", "/O2", "/Zl", "/Fodata.obj", harness],
                cwd=directory, env={**os.environ, "MSVC_VER": compiler},
                capture_output=True, text=True, check=False,
            )
            if result.returncode:
                raise ValueError(f"data compilation failed for {source['source']}:\n{result.stdout}{result.stderr}")
            object_bytes = (directory / "data.obj").read_bytes()
        obj = matchlib.parse_coff_object(object_bytes)
        digest = native_link._normalized_coff_sha256(object_bytes)
        for row in source["rows"]:
            storage = _check_storage(obj, row["name"], row["size"],
                                     expected=bytes.fromhex(row["initializer_hex"]), relocations=row["relocations"],
                                     linkage=row["linkage"])
            candidates.append({**{key: value for key, value in row.items() if key != "initializer_hex"},
                               "storage": storage, "object_sha256": digest})
    from . import match_data_inventory

    evidence = {"sections": section_inventory(), "candidates": candidates,
                "ownership": match_data_inventory.ownership_plan(match_data_inventory.catalog())}
    validate_evidence(evidence)
    return evidence


def validate_evidence(evidence: dict[str, Any]) -> None:
    if evidence["sections"] != section_inventory():
        raise ValueError("data denominator differs from the reference PE sections")
    _, sources = _load_plan()
    expected = [{key: value for key, value in row.items() if key != "initializer_hex"}
                for source in sources for row in source["rows"]]
    actual = [
        {key: row[key] for key in ("image", "name", "source", "linkage", "address", "size", "initializer_sha256", "relocations")}
        for row in evidence["candidates"]
    ]
    if actual != expected:
        raise ValueError("data candidates differ from the verified definition plan")
    for row in evidence["candidates"]:
        if (
            row["storage"] not in {"coff-common", "coff-bss", "coff-data"}
            or re.fullmatch(r"[0-9a-f]{64}", row["object_sha256"]) is None
        ):
            raise ValueError(f"invalid data compilation evidence: {row['name']}")
        containing = [
            section for section in evidence["sections"]
            if section["image"] == row["image"]
            and section["address"] <= row["address"]
            and row["address"] + row["size"] <= section["address"] + section["size"]
        ]
        if len(containing) != 1:
            raise ValueError(f"data candidate is outside the data denominator: {row['name']}")

    from . import match_data_inventory

    if evidence.get("ownership") != match_data_inventory.ownership_plan(match_data_inventory.catalog()):
        raise ValueError("data ownership differs from the evidenced object assignments")
    report_spans(evidence)


def report_spans(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Partition complete sections, counting overlapping declarations only once."""
    previous_end: dict[str, int] = {}
    for section in sorted(evidence["sections"], key=lambda section: (section["image"], section["address"])):
        if section["size"] <= 0 or section["address"] < previous_end.get(section["image"], 0):
            raise ValueError("invalid or overlapping data sections")
        previous_end[section["image"]] = section["address"] + section["size"]
    for row in evidence["candidates"] + evidence.get("ownership", []):
        if row["size"] <= 0 or sum(
            section["image"] == row["image"]
            and section["address"] <= row["address"]
            and row["address"] + row["size"] <= section["address"] + section["size"]
            for section in evidence["sections"]
        ) != 1:
            raise ValueError(f"data candidate is outside the data denominator: {row['name']}")
    spans = []
    for section in evidence["sections"]:
        start, end = section["address"], section["address"] + section["size"]
        candidates = [
            row for row in evidence["candidates"]
            if row["image"] == section["image"] and start <= row["address"] < end
        ]
        ownership = [row for row in evidence.get("ownership", [])
                     if row["image"] == section["image"] and start <= row["address"] < end]
        boundaries = sorted({start, end, *(value for row in candidates + ownership for value in (row["address"], row["address"] + row["size"]))})
        for left, right in pairwise(boundaries):
            owners = [row for row in candidates if row["address"] <= left and right <= row["address"] + row["size"]]
            owner = min(owners, key=lambda row: (-row["size"], row["name"])) if owners else None
            categories = {row["owner"] for row in ownership
                          if row["address"] <= left and right <= row["address"] + row["size"]}
            if len(categories) > 1 or categories - {"game", "libraries"}:
                raise ValueError(f"invalid or conflicting data ownership: {section['image']}:0x{left:x}")
            spans.append({
                "owner": next(iter(categories), "unknown"),
                "image": section["image"], "section": section["name"], "address": left, "size": right - left,
                "name": owner["name"] if owner else "unmatched", "source": owner["source"] if owner else None,
                "matched": owner is not None,
            })
    return spans
