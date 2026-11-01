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
    source = match_builds.load_registry().identity(image)
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
        if row.get("build_only") or row["evidence"] not in {"exact", "interface", "recovered"}:
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
    verified_ends = {
        start: matchlib.parse_int(row["end"]) for start, row in by_address.items()
        if row["evidence"] in {"exact", "interface", "recovered"} and not row.get("identity_only")
    }
    protected_starts = sorted(verified_ends)
    functions = {row["address"]: row for row in discovered}
    starts = []
    for start in sorted(functions):
        previous = bisect.bisect_left(protected_starts, start) - 1
        if previous >= 0 and start < verified_ends[protected_starts[previous]]:
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
            end = verified_ends.get(start, end)
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
            if identity is not None and identity.get("identity_only"):
                # Compare the fingerprinted body, but keep this entry's independent byte ownership.
                row["comparison_end"] = matchlib.parse_int(identity["end"])
            if row["ownership"] == "unknown" and start in library_owners:
                row["ownership"] = library_owners[start]
            if identity is not None and not identity.get("build_only"):
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
    rows = _partition(sections, payload["functions"], mapped, ownership, _library_owners(image), native, image.name)
    _apply_port_scope(rows, payload["platform_replaced"])
    return rows


def _apply_port_scope(rows: list[dict[str, Any]], exclusions: list[dict[str, Any]]) -> None:
    # The image and discovered extents are already pinned. Donor names, including
    # weak ordered placements, are deliberately irrelevant to this decision.
    owned = {r["address"]: r for r in rows if r["native_kind"] == "function" and r["ownership"] == "game"}
    for row in owned.values():
        row["platform_replaced"] = None
    for entry in exclusions:
        address, reason = entry["address"], entry["reason"]
        if type(address) is not int or address not in owned or not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"invalid platform exclusion for native game/engine function: {entry}")
        if owned[address]["platform_replaced"] is not None:
            raise ValueError(f"duplicate platform exclusion at {address:#x}")
        owned[address]["platform_replaced"] = reason


def in_port_scope(row: dict[str, Any]) -> bool:
    return row["native_kind"] == "function" and row["ownership"] == "game" and row["platform_replaced"] is None


def scoped_functions(image: match_builds.BuildImage, scope: str) -> dict[int, dict[str, Any]]:
    if scope not in {"all", "port"}:
        raise ValueError(f"unknown native function scope: {scope}")
    return {
        row["address"]: row for row in load(image)
        if row["native_kind"] == "function" and (scope == "all" or in_port_scope(row))
    }


def function_bounds(image: match_builds.BuildImage) -> dict[int, int]:
    return {address: row["end"] for address, row in scoped_functions(image, "all").items()}


def build_functions(
    registry: match_builds.Registry, build: str, scope: str, *, image_name: str | None = None,
) -> dict[str, dict[int, dict[str, Any]]]:
    if build not in registry.builds:
        raise ValueError(f"unknown matching build {build!r}")
    images = [registry.image(build, image_name)] if image_name else registry.builds[build].values()
    inventory = {}
    for image in images:
        rows = scoped_functions(image, scope)
        for placement in json.loads(image.target.functions_path.read_text()):
            address = matchlib.parse_int(placement["address"])
            if address in rows:
                rows[address]["name_evidence"] = placement["evidence"]
        inventory[image.name] = rows
    return inventory
