"""A byte-accounted backlog and explicit ownership of the full data denominator."""
from __future__ import annotations

import json
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import match as matchlib
from . import match_data_report, native_link

OWNERSHIP = matchlib.REPO_ROOT / "tools/native/data_ownership.json"
DEFAULT_INVENTORY = matchlib.REPO_ROOT / "analysis/decomp/data-inventory.json"
DEFAULT_SUMMARY = matchlib.REPO_ROOT / "analysis/decomp/DATA.md"
OWNERS = {"game", "libraries", "unknown"}


def catalog() -> list[dict[str, Any]]:
    mapped = {(row["program"], matchlib.parse_int(row["address"]), row["name"]): row
              for row in json.loads(matchlib.DEFAULT_DATA_MAP_PATH.read_text())["entries"]}
    rows = []
    defined = set()
    for image in matchlib.TRACKED_IMAGE_NAMES:
        payload = native_link.load_native_data_definitions(image, reference_image_path=matchlib._paths_for_image(image)[0])
        if payload is None:
            raise ValueError(f"missing data definitions: {image}")
        for definition in payload["entries"]:
            key = (image, definition["address"], definition["name"])
            defined.add(key)
            annotation = mapped.get(key, {})
            rows.append({**definition, "image": image, "type": annotation.get("type"),
                         "comment": annotation.get("comment", "")})
    # A mapped label without a definition is still a recovery task. It cannot
    # acquire a guessed extent or disappear merely because the linker has not
    # needed a provider for it yet.
    for (image, address, name), annotation in sorted(mapped.items()):
        if image in matchlib.TRACKED_IMAGE_NAMES and (image, address, name) not in defined:
            rows.append({"image": image, "address": address, "name": name,
                         "size": None, "size_source": None, "type": annotation.get("type"),
                         "comment": annotation.get("comment", "")})
    return rows


def ownership_plan(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    plan = json.loads(OWNERSHIP.read_text())
    if plan.get("schema") != 1:
        raise ValueError("unsupported data ownership schema")
    definitions = {(row["image"], row["name"]): row for row in rows}
    seen = set()
    assignments = []
    for item in plan["objects"]:
        key = (item["image"], item["name"])
        if key in seen or key not in definitions or item["owner"] not in {"game", "libraries"}:
            raise ValueError(f"invalid or duplicate data ownership object: {key}")
        seen.add(key)
        proof = item["evidence"]
        path = Path(proof["path"])
        if path.is_absolute() or ".." in path.parts or not (matchlib.REPO_ROOT / path).is_file() or not proof["reason"].strip():
            raise ValueError(f"invalid data ownership evidence: {key}")
        row = definitions[key]
        if not row.get("size") or row["size"] <= 0:
            raise ValueError(f"ownership requires an explicit extent: {key}")
        assignments.append({"image": row["image"], "name": row["name"], "address": row["address"],
                            "size": row["size"], "owner": item["owner"], "evidence": proof})
    return assignments


def _contained(row: dict[str, Any], section: dict[str, Any]) -> bool:
    size = row.get("size") or 0
    return (row["image"] == section["image"] and size > 0
            and section["address"] <= row["address"]
            and row["address"] + size <= section["address"] + section["size"])


def _covering(rows: list[dict[str, Any]], left: int, right: int) -> list[dict[str, Any]]:
    return [row for row in rows if row["address"] <= left and right <= row["address"] + row["size"]]


def partition(evidence: dict[str, Any], definitions: list[dict[str, Any]], assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every byte appears once, including unknown ownership and unnamed gaps."""
    # Reuse the report's strict section/candidate containment validation.
    match_data_report.report_spans({**evidence, "ownership": assignments})
    spans = []
    for section in evidence["sections"]:
        start, end = section["address"], section["address"] + section["size"]
        objects = [row for row in definitions if _contained(row, section)]
        candidates = [row for row in evidence["candidates"] if _contained(row, section)]
        owners = [row for row in assignments if _contained(row, section)]
        points = sorted({start, end, *(point for row in objects + candidates + owners
                                       for point in (row["address"], row["address"] + row["size"]))})
        for left, right in pairwise(points):
            named = _covering(objects, left, right)
            matched = _covering(candidates, left, right)
            ownership = {row["owner"] for row in _covering(owners, left, right)}
            if len(ownership) > 1:
                raise ValueError(f"conflicting data ownership at {section['image']}:0x{left:x}")
            candidate = min(matched, key=lambda row: (-row["size"], row["name"])) if matched else None
            spans.append({"image": section["image"], "section": section["name"], "address": left,
                          "size": right - left, "owner": next(iter(ownership), "unknown"),
                          "objects": sorted(row["name"] for row in named), "matched": bool(matched),
                          "name": candidate["name"] if candidate else "unmatched",
                          "source": candidate["source"] if candidate else None})
    return spans


def build_inventory(evidence: dict[str, Any]) -> dict[str, Any]:
    definitions = catalog()
    assignments = ownership_plan(definitions)
    spans = partition(evidence, definitions, assignments)
    exclusions = json.loads(match_data_report.MANIFEST.read_text()).get("excluded", [])
    rejected = {(row["image"], row["name"]): row["reason"] for row in exclusions}
    objects: list[dict[str, Any]] = []
    unbounded = []
    for row in definitions:
        if not row.get("size"):
            if any(section["image"] == row["image"]
                   and section["address"] <= row["address"] < section["address"] + section["size"]
                   for section in evidence["sections"]):
                unbounded.append({"image": row["image"], "name": row["name"], "address": row["address"],
                                  "type": row.get("type"), "blocker": "missing-extent"})
            continue
        covered = [span for span in spans if span["image"] == row["image"] and row["name"] in span["objects"]]
        if not covered:
            continue  # Code-local tables are outside the data denominator.
        remaining = sum(span["size"] for span in covered if not span["matched"])
        reason = rejected.get((row["image"], row["name"]))
        blocker = ("matched" if not remaining else "declaration-conflict" if reason else
                   "missing-type" if not row.get("type") else
                   "symbolic-pointers" if row.get("initializer_target") or row.get("initializer_symbols") else
                   "uncompiled-zero-definition" if row.get("initializer_fill") == "00" else
                   "initialized-definition")
        objects.append({"image": row["image"], "name": row["name"], "address": row["address"],
                        "size": row["size"], "unmatched_bytes": remaining, "type": row.get("type"),
                        "owners": sorted({span["owner"] for span in covered}), "blocker": blocker,
                        "reason": reason if remaining else None,
                        **({"declaration_note": reason} if reason else {}),
                        "extent_evidence": row["size_source"]})
    objects.sort(key=lambda row: (-row["unmatched_bytes"], row["image"], row["address"], row["name"]))
    owner_totals = {}
    for owner in sorted(OWNERS):
        owned = [span for span in spans if span["owner"] == owner]
        owner_totals[owner] = {"total_bytes": sum(span["size"] for span in owned),
                               "matched_bytes": sum(span["size"] for span in owned if span["matched"])}
    totals = {"total_bytes": sum(span["size"] for span in spans),
              "matched_bytes": sum(span["size"] for span in spans if span["matched"]),
              "unnamed_bytes": sum(span["size"] for span in spans if not span["objects"])}
    totals["unmatched_bytes"] = totals["total_bytes"] - totals["matched_bytes"]
    return {"schema": 1, "totals": totals, "ownership": owner_totals,
            "ownership_complete": owner_totals["unknown"]["total_bytes"] == 0,
            "objects": objects, "unbounded_objects": sorted(unbounded, key=lambda row: (row["image"], row["address"], row["name"])),
            "spans": spans}


def render_summary(inventory: dict[str, Any]) -> str:
    totals = inventory["totals"]
    lines = ["# Data recovery inventory", "", "Generated by `crimson match data-inventory` from the pinned images, compiled evidence, native definitions, and explicit ownership assignments.", "",
             f"**{totals['matched_bytes']:,} / {totals['total_bytes']:,} bytes matched**; {totals['unmatched_bytes']:,} remain. {totals['unnamed_bytes']:,} bytes are outside every recorded object extent.", "",
             "## Ownership", "", "| Owner | Total bytes | Matched bytes |", "|---|---:|---:|"]
    for owner, measures in inventory["ownership"].items():
        lines.append(f"| {owner} | {measures['total_bytes']:,} | {measures['matched_bytes']:,} |")
    lines += ["", "Ownership covers unmatched objects as well as matches. Unattributed regions stay in the full denominator. The attributed data filters are subsets, not a complete Game & Engine denominator; its code filter remains code-only until all data ownership is resolved.", "",
              "## Largest uncredited objects", "", "Objects may overlap; these opportunities must not be summed. The JSON spans partition every byte exactly once.", "",
              "| Image | Object | Unmatched bytes | Blocker |", "|---|---|---:|---|"]
    for row in [row for row in inventory["objects"] if row["unmatched_bytes"]][:30]:
        lines.append(f"| {row['image']} | `{row['name']}` | {row['unmatched_bytes']:,} | {row['blocker']} |")
    lines += ["", "## Largest unnamed regions", "", "| Image | Start | End (exclusive) | Bytes |", "|---|---|---|---:|"]
    for span in sorted((span for span in inventory["spans"] if not span["objects"]), key=lambda span: -span["size"])[:20]:
        lines.append(f"| {span['image']} | `0x{span['address']:08x}` | `0x{span['address']+span['size']:08x}` | {span['size']:,} |")
    unbounded = inventory.get("unbounded_objects", [])
    lines += ["", "## Labels without proven extents", "",
              f"**{len(unbounded)} mapped data labels** need an independent size before compilation or ownership assignment. Their bytes remain in the section denominator; nearby labels do not establish array bounds. The JSON retains the complete list.", "",
              "| Image | Address | Label | Type |", "|---|---|---|---|"]
    for row in unbounded[:30]:
        lines.append(f"| {row['image']} | `0x{row['address']:08x}` | `{row['name']}` | {row['type'] or 'unknown'} |")
    lines += ["", "## Rejected declarations", ""]
    rejected = [row for row in inventory["objects"] if row["reason"]]
    for row in rejected:
        lines.append(f"- `{row['image']}:{row['name']}`: {row['reason']}")
    if not rejected:
        lines.append("None with unresolved byte debt.")
    return "\n".join(lines) + "\n"


def write_inventory(inventory: dict[str, Any], *, output: Path = DEFAULT_INVENTORY, summary: Path = DEFAULT_SUMMARY) -> None:
    matchlib.write_match_json(output, inventory)
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(render_summary(inventory))


def validate_inventory(inventory: dict[str, Any], *, output: Path = DEFAULT_INVENTORY, summary: Path = DEFAULT_SUMMARY) -> None:
    if not output.is_file() or json.loads(output.read_text()) != inventory:
        raise ValueError("data inventory differs from current evidence; run crimson match data-inventory")
    if not summary.is_file() or summary.read_text() != render_summary(inventory):
        raise ValueError("data inventory summary differs from current evidence; run crimson match data-inventory")
