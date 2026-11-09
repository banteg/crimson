"""Reconcile the freeware PE data sections against verified globals and source storage."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import replace
from itertools import pairwise
from pathlib import Path
from typing import Any

import pefile

from . import match as matchlib
from . import match_builds, match_data_report, match_freeware_pe_metadata, match_freeware_startup_data

POLICY = "freeware-pe-data-virtual-extents-v1"
Row = dict[str, Any]


def _layout(images: Iterable[match_builds.BuildImage]) -> tuple[list[Row], list[Row], list[Row]]:
    sections = []
    excluded = []
    metadata = []
    for image in sorted(images, key=lambda im: im.name):
        original = image.path.read_bytes()
        if hashlib.sha256(original).hexdigest() != image.sha256:
            raise ValueError(f"freeware data image differs from its registry pin: {image.build}/{image.name}")
        with pefile.PE(data=original, fast_load=True) as pe:
            base = int(pe.OPTIONAL_HEADER.ImageBase)
            end = base
            for section in sorted(pe.sections, key=lambda s: s.VirtualAddress):
                name = section.Name.rstrip(b"\0").decode("ascii")
                start = base + int(section.VirtualAddress)
                size = int(section.Misc_VirtualSize)
                if not size:
                    continue
                if start < end or start + size > base + int(pe.OPTIONAL_HEADER.SizeOfImage):
                    raise ValueError(f"invalid PE section extent: {image.name}/{name}")
                end = start + size
                row = {"image": image.name, "name": name, "address": start, "size": size}
                executable = bool(section.Characteristics & match_builds.IMAGE_SCN_MEM_EXECUTE)
                if name not in match_data_report.DATA_SECTIONS:
                    reason = "executable" if executable else {
                        ".rsrc": "resources", ".reloc": "base-relocations",
                    }.get(name, "outside-data-policy")
                    excluded.append({**row, "reason": reason})
                    continue
                if executable:
                    raise ValueError(f"executable PE data section: {image.name}/{name}")
                backed = min(size, int(section.SizeOfRawData))
                offset = int(section.PointerToRawData)
                if backed and (not offset or offset + backed > len(original)):
                    raise ValueError(f"truncated PE data section: {image.name}/{name}")
                contents = original[offset:offset + backed] + bytes(size - backed)
                sections.append({**row, "file_size": backed, "sha256": hashlib.sha256(contents).hexdigest()})
            metadata.extend({"image": image.name, "address": start, "size": end - start, "kind": kind}
                            for start, end, kind in match_freeware_pe_metadata.metadata_ranges(pe))
    return sections, excluded, metadata


def section_inventory(images: Iterable[match_builds.BuildImage]) -> list[Row]:
    return _layout(images)[0]


def _indexed(sections: list[Row], rows: list[Row], *, labels: bool = False) -> dict[tuple[str, int], list[Row]]:
    """Reject wrong-image, boundary-crossing and out-of-section attributions."""
    result = {(s["image"], s["address"]): [] for s in sections}
    for row in rows:
        size = row.get("size")
        start = row["address"]
        if (type(start) is not int or (size is None and not labels)
                or (size is not None and (type(size) is not int or size <= 0))):
            raise ValueError(f"invalid freeware data extent at {row['image']}/{start}")
        extent = size or 1  # A label must lie in a section but does not claim this byte.
        containing = [s for s in sections if s["image"] == row["image"] and s["address"] <= start
                      and start + extent <= s["address"] + s["size"]]
        if len(containing) != 1:
            raise ValueError(f"freeware data extent outside a unique PE data section: {row['image']}/{start:#x}")
        if size is not None:
            result[row["image"], containing[0]["address"]].append(row)
    return result


def _partition(
    sections: list[Row], globals_: list[Row], candidates: list[Row], libraries: list[Row], metadata: list[Row],
) -> list[Row]:
    placements = _indexed(sections, globals_, labels=True)
    objects = _indexed(sections, candidates)
    attribution = _indexed(sections, libraries)
    structures = _indexed(sections, metadata)
    spans = []
    for section in sections:
        start = section["address"]
        backed_end = start + section["file_size"]
        key = section["image"], start
        # Overlaid declarations may alias. Split at every evidence boundary so
        # each physical byte contributes to exactly one public measure.
        mapped = placements[key] + attribution[key]
        sources = objects[key]
        members = mapped + sources + structures[key]
        cuts = sorted({start, start + section["size"], backed_end,
                       *(p for r in members for p in (r["address"], r["address"] + r["size"]))})
        for left, right in pairwise(cuts):
            named = [r for r in mapped if r["address"] <= left < r["address"] + r["size"]]
            compiled = [r for r in sources if r["address"] <= left < r["address"] + r["size"]]
            pe = [r for r in structures[key] if r["address"] <= left < r["address"] + r["size"]]
            owners = {r["owner"] for r in named + compiled if r.get("owner", "unknown") != "unknown"}
            if len(owners) > 1 or owners - {"game", "libraries"}:
                raise ValueError(f"conflicting freeware data owners: {section['image']}/{left:#x}")
            if len(pe) > 1 or (pe and (owners or compiled)):
                raise ValueError(f"PE metadata overlaps attributed storage: {section['image']}/{left:#x}")
            names = sorted({alias for r in named + compiled for alias in (r["names"] if "names" in r else [r["name"]])})
            owner = "pe" if pe else next(iter(owners), "unknown")
            source = None
            if compiled:
                representative = min(compiled, key=lambda r: (-r["size"], r["name"], r["source"]))
                name, source, status = representative["name"], representative["source"], "source-matched"
            elif pe:
                name, status = pe[0]["kind"], "pe-metadata"
            elif names:
                name, status = names[0], "mapped-unmatched"
            else:
                name, status = "unmatched", "unattributed"
            spans.append({
                "image": section["image"], "section": section["name"], "address": left, "size": right - left,
                "storage": "file-backed" if left < backed_end else "zero-fill", "status": status,
                "owner": owner, "matched": bool(compiled), "name": name, "source": source,
                **({"objects": names} if names else {}),
                **({"metadata_kind": pe[0]["kind"]} if pe else {}),
            })
    return spans


def build_evidence(
    images: Iterable[match_builds.BuildImage], globals_: list[Row], candidates: list[Row],
    library_objects: list[Row] | None = None, startup_tables: list[Row] | None = None,
) -> Row:
    sections, excluded, metadata = _layout(images)
    libraries = library_objects or []
    startup = startup_tables or []
    spans = _partition(sections, globals_, candidates, libraries + startup, metadata)
    ownership = [
        {"image": row["image"], "address": row["address"], "size": row["size"], "owner": row["owner"]}
        for row in spans if row["owner"] in {"game", "libraries"}
    ]
    return {"policy": POLICY, "sections": sections, "excluded_sections": excluded, "globals": globals_,
            "library_objects": libraries, "startup_tables": startup, "candidates": candidates, "ownership": ownership, "spans": spans}


def _images(version: str, paths: dict[str, Path]) -> list[match_builds.BuildImage]:
    images = match_builds.load_registry().builds[version]
    if images.keys() != paths.keys() or any(image.native_inventory is None for image in images.values()):
        raise ValueError(f"incomplete or unsupported freeware data image set for {version}")
    return [replace(image, path=paths[name]) for name, image in images.items()]


def refresh_evidence(
    version: str, functions: list[Row], statuses: list[matchlib.ScratchStatus], image_paths: dict[str, Path],
) -> Row:
    from . import match_freeware_globals, match_freeware_library_data

    images = _images(version, image_paths)
    globals_, candidates = match_freeware_globals.refresh(version, functions, statuses)
    libraries = match_freeware_library_data.attributions(version, image_paths, functions)
    startup = match_freeware_startup_data.attributions(image_paths, functions)
    return build_evidence(images, globals_, candidates, libraries, startup)


def validate_evidence(version: str, data: Row, functions: list[Row], image_paths: dict[str, Path]) -> None:
    from . import match_freeware_globals, match_freeware_library_data

    images = _images(version, image_paths)
    match_freeware_globals.validate(version, functions, data["globals"], data["candidates"])
    libraries = match_freeware_library_data.attributions(version, image_paths, functions)
    startup = match_freeware_startup_data.attributions(image_paths, functions)
    expected = build_evidence(images, data["globals"], data["candidates"], libraries, startup)
    if data != expected:
        raise ValueError("freeware data inventory differs from its original PE sections, attributions or byte partition")


def report_spans(data: Row) -> list[Row]:
    """The ordinary evidence verifier rederives these spans from the pinned images."""
    if data["policy"] != POLICY:
        raise ValueError("unsupported freeware data inventory policy")
    return data["spans"]
