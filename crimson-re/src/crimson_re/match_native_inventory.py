"""Native function discovery and a conservative partition of every executable byte.

Donor maps supply identities, never the denominator. Verified unchanged bodies
bound physical extents; independent control-flow discovery supplies other starts.
Shared/interior entry points stay in the raw inventory. Every byte outside a
retained function is an uncredited executable remainder, including alignment.
"""
from __future__ import annotations

import bisect
import hashlib
import json
from itertools import pairwise
from typing import Any

from . import match as matchlib
from . import match_builds

POLICY = "native-functions-and-full-executable-remainder-v1"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _library_owners(image: match_builds.BuildImage) -> dict[int, str]:
    source = match_builds.load_registry().canonical(image)
    scope = matchlib._load_matching_scope_definition("port")
    provenance = json.loads((matchlib.REPO_ROOT / "analysis/library_provenance.json").read_text())
    regions = [
        (matchlib.parse_int(region["start"]), matchlib.parse_int(region["end"]), f"libs.{component['id']}")
        for artifact in provenance["artifacts"] if artifact["id"] == source.name
        for component in artifact.get("components", ()) for region in component.get("ranges", ())
    ]
    excluded = {row.address for row in scope.function_dispositions[source.name] if row.disposition == "third-party"}
    result = {}
    for row in json.loads(image.target.functions_path.read_text()):
        if row["evidence"] != "exact":
            continue
        canonical = matchlib.parse_int(row["canonical_address"])
        owners = {owner for lo, hi, owner in regions if lo <= canonical < hi}
        if len(owners) == 1:
            result[matchlib.parse_int(row["address"])] = owners.pop()
        elif canonical in excluded:
            result[matchlib.parse_int(row["address"])] = "libs.other"
    return result


def _partition(
    sections: list[tuple[int, int]], discovered: list[dict[str, Any]],
    mapped: list[dict[str, Any]], ownership: list[dict[str, Any]], library_owners: dict[int, str],
    image: matchlib.LoadedImage, image_name: str,
) -> list[dict[str, Any]]:
    by_address = {matchlib.parse_int(row["address"]): row for row in mapped}
    verified = sorted(
        (start, matchlib.parse_int(row["end"])) for start, row in by_address.items() if row["evidence"] == "exact"
    )
    protected_starts = [start for start, _ in verified]
    functions = {row["address"]: row for row in discovered}
    starts = []
    for start in sorted(functions):
        previous = bisect.bisect_left(protected_starts, start) - 1
        if previous >= 0 and start < verified[previous][1]:
            continue  # Interior/shared entry remains in native.json, not a duplicate byte owner.
        starts.append(start)

    def owner(lo: int, hi: int) -> str:
        return next((row["owner"] for row in ownership if row["start"] <= lo and hi <= row["end"]), "unknown")

    result = []
    for section_start, section_end in sections:
        cursor = section_start
        section_starts = [start for start in starts if section_start <= start < section_end]

        def remainder(end: int) -> None:
            nonlocal cursor
            cuts = sorted({cursor, end, *(value for region in ownership for value in (region["start"], region["end"]) if cursor < value < end)})
            for lo, hi in pairwise(cuts):
                result.append({"image": image_name, "address": lo, "end": hi, "size": hi - lo,
                               "name": f"unresolved_executable_{lo:08x}", "native_kind": "unresolved",
                               "ownership": owner(lo, hi)})
            cursor = end

        for index, start in enumerate(section_starts):
            native = functions[start]
            end = min(max(block["end"] for block in native["blocks"]),
                      section_starts[index + 1] if index + 1 < len(section_starts) else section_end)
            identity = by_address.get(start)
            if identity is not None and identity["evidence"] == "exact":
                end = matchlib.parse_int(identity["end"])
            if not cursor <= start < end <= section_end:
                raise ValueError("overlapping or invalid native function partition")
            if cursor < start:
                remainder(start)
            lines = matchlib.disassemble_normalized_function(image.function_bytes(start, end), base_address=start)
            size = max((line.offset + line.size for line in lines), default=0)
            if size <= 0:
                remainder(end)
                continue
            retained_end = start + size
            row = {"image": image_name, "address": start, "end": retained_end, "size": size,
                   "name": identity["name"] if identity is not None else native["name"],
                   "native_kind": "function", "ownership": owner(start, retained_end)}
            if row["ownership"] == "unknown" and start in library_owners:
                row["ownership"] = library_owners[start]
            if identity is not None:
                row["canonical_address"] = matchlib.parse_int(identity["canonical_address"])
            result.append(row)
            cursor = retained_end
        if cursor < section_end:
            remainder(section_end)
    return result


def load(image: match_builds.BuildImage) -> list[dict[str, Any]]:
    if image.native_inventory is None:
        raise ValueError("build has no independent native inventory")
    payload = json.loads(image.native_inventory.read_text())
    if (payload.get("schema"), payload.get("build"), payload.get("image"), payload.get("sha256")) != (
        1, image.build, image.name, image.sha256,
    ) or image.state() != "ok":
        raise ValueError("native inventory image identity mismatch")
    if payload["maps_sha256"] != _digest(image.target.functions_path.read_bytes()):
        raise ValueError("native inventory donor maps changed; export again")
    native = matchlib.load_image(image.path)
    sections = match_builds._code_ranges(image.path)
    seen = set()
    for function in payload["functions"]:
        start = function["address"]
        if (type(start) is not int or start in seen or not any(lo <= start < hi for lo, hi in sections)
            or not any(block["address"] == start for block in function["blocks"])):
            raise ValueError("invalid or duplicate native function start")
        seen.add(start)
        for block in function["blocks"]:
            lo, hi = block["address"], block["end"]
            if not any(a <= lo < hi <= b for a, b in sections) or _digest(native.function_bytes(lo, hi)) != block["sha256"]:
                raise ValueError("native inventory block extent or bytes changed")
    ownership = payload["ownership_ranges"]
    previous = 0
    for region in sorted(ownership, key=lambda row: row["start"]):
        lo, hi = region["start"], region["end"]
        if lo < previous or not any(a <= lo < hi <= b for a, b in sections) or region["owner"] != "game":
            raise ValueError("invalid native ownership range")
        if _digest(native.function_bytes(hi, hi + 64)) != region["boundary_sha256"]:
            raise ValueError("native ownership boundary changed")
        previous = hi
    mapped = json.loads(image.target.functions_path.read_text())
    return _partition(sections, payload["functions"], mapped, ownership, _library_owners(image), native, image.name)


def function_bounds(image: match_builds.BuildImage) -> dict[int, int]:
    return {row["address"]: row["end"] for row in load(image) if row["native_kind"] == "function"}
