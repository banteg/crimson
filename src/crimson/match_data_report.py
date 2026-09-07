"""Source-built data evidence for the public matching report.

Native definitions locate and describe reference objects; they do not themselves
earn matching credit. Zero-initialized C++ definitions are compiled by VC6, with
sizeof assertions, and their COFF storage is checked against the reference.
"""

from __future__ import annotations

import json
import os
import re
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
    seen = set()
    sources = []
    for source in manifest["sources"]:
        image = source["image"]
        path = Path(source["source"])
        if path.is_absolute() or ".." in path.parts or not path.is_relative_to("tools/match/data"):
            raise ValueError(f"invalid data source path: {path}")
        rows = []
        for name in source["symbols"]:
            if re.fullmatch(r"[A-Za-z_]\w*", name) is None or (image, name) in seen:
                raise ValueError(f"invalid or duplicate data symbol: {image}:{name}")
            seen.add((image, name))
            definition = definitions[image][name]
            if definition.get("initializer_fill") != "00" or not definition.get("size"):
                raise ValueError(f"data candidate is not an explicit zero-filled object: {name}")
            rows.append({
                "image": image, "name": name, "source": path.as_posix(),
                "address": definition["address"], "size": definition["size"],
            })
        if not rows:
            raise ValueError(f"empty data source: {path}")
        sources.append({"source": path.as_posix(), "rows": rows})
    return manifest["compiler"], sources


def _check_storage(obj: matchlib.CoffObject, name: str, size: int) -> str:
    symbols = [
        symbol for symbol in obj.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
        and (symbol.name == f"_{name}" or symbol.name.startswith(f"?{name}@@3"))
    ]
    if len(symbols) != 1:
        raise ValueError(f"data object does not define exactly one {name}")
    symbol = symbols[0]
    if symbol.section_number == 0 and symbol.value == size:
        return "coff-common"
    if symbol.section_number <= 0:
        raise ValueError(f"data object has no storage for {name}")
    section = obj.sections[symbol.section_number - 1]
    start, end = symbol.value, symbol.value + size
    if section.characteristics & 0x20000000 or section.logical_size is None or end > section.logical_size:
        raise ValueError(f"invalid data object extent: {name}")
    if any(
        relocation.virtual_address < end
        and relocation.virtual_address + matchlib.IMAGE_REL_I386_WIDTHS[relocation.relocation_type] > start
        for relocation in section.relocations
    ):
        raise ValueError(f"zero-filled data object has a relocation: {name}")
    if section.characteristics & matchlib.IMAGE_SCN_CNT_UNINITIALIZED_DATA:
        return "coff-bss"
    if section.data[start:end] != bytes(size):
        raise ValueError(f"data object is not zero-initialized: {name}")
    return "coff-data"


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
            (directory / "verify.cpp").write_text(f'#include "{include}"\n{assertions}\n')
            result = subprocess.run(
                [str(matchlib.DEFAULT_MATCH_ROOT / "cl.sh"), "/c", "/O2", "/Zl", "/Fodata.obj", "verify.cpp"],
                cwd=directory, env={**os.environ, "MSVC_VER": compiler},
                capture_output=True, text=True, check=False,
            )
            if result.returncode:
                raise ValueError(f"data compilation failed for {source['source']}:\n{result.stdout}{result.stderr}")
            object_bytes = (directory / "data.obj").read_bytes()
        obj = matchlib.parse_coff_object(object_bytes)
        digest = native_link._normalized_coff_sha256(object_bytes)
        for row in source["rows"]:
            storage = _check_storage(obj, row["name"], row["size"])
            candidates.append({**row, "storage": storage, "object_sha256": digest})
    evidence = {"sections": section_inventory(), "candidates": candidates}
    validate_evidence(evidence)
    return evidence


def validate_evidence(evidence: dict[str, Any]) -> None:
    if evidence["sections"] != section_inventory():
        raise ValueError("data denominator differs from the reference PE sections")
    _, sources = _load_plan()
    expected = [row for source in sources for row in source["rows"]]
    actual = [
        {key: row[key] for key in ("image", "name", "source", "address", "size")}
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


def report_spans(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Partition complete sections, counting overlapping declarations only once."""
    previous_end: dict[str, int] = {}
    for section in sorted(evidence["sections"], key=lambda section: (section["image"], section["address"])):
        if section["size"] <= 0 or section["address"] < previous_end.get(section["image"], 0):
            raise ValueError("invalid or overlapping data sections")
        previous_end[section["image"]] = section["address"] + section["size"]
    for row in evidence["candidates"]:
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
        boundaries = sorted({start, end, *(value for row in candidates for value in (row["address"], row["address"] + row["size"]))})
        for left, right in pairwise(boundaries):
            owners = [row for row in candidates if row["address"] <= left and right <= row["address"] + row["size"]]
            owner = min(owners, key=lambda row: (-row["size"], row["name"])) if owners else None
            spans.append({
                "image": section["image"], "section": section["name"], "address": left, "size": right - left,
                "name": owner["name"] if owner else "unmatched", "source": owner["source"] if owner else None,
                "matched": owner is not None,
            })
    return spans
