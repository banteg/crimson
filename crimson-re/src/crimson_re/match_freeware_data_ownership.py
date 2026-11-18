"""Source-backed ownership for names verified at native freeware addresses."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Collection
from pathlib import Path

from . import match, match_builds

FREEWARE = "tools/native/freeware_data_ownership.json"
CANONICAL = "tools/native/data_ownership.json"


def _assignments(root: Path, build: str, image_name: str) -> dict[str, set[tuple[str, str]]]:
    """Retain competing assignments so conflicting aliases cannot transfer ownership."""
    plan = json.loads((root / FREEWARE).read_text())
    canonical = json.loads((root / CANONICAL).read_text())
    if plan["schema"] != 1 or canonical["schema"] != 1 or build not in plan["builds"]:
        raise ValueError("unsupported freeware data ownership plan")
    assignments: dict[str, set[tuple[str, str]]] = defaultdict(set)
    canonical_image = "crimsonland.exe" if image_name == "crimson.exe" else image_name
    aliases: dict[str, set[str]] = defaultdict(set)
    addresses: dict[str, set[int]] = defaultdict(set)
    for row in json.loads((root / "analysis/ghidra/maps/data_map.json").read_text())["entries"]:
        if row.get("program") == canonical_image and row.get("kind", "data") == "data":
            for name in (row["name"], *row.get("aliases", [])):
                aliases[row["name"]].add(name)
                addresses[name].add(match.parse_int(row["address"]))
    for row in canonical["objects"]:
        if row["image"] != canonical_image or len(addresses[row["name"]]) > 1:
            continue
        for name in {row["name"], *aliases[row["name"]]}:
            if len(addresses[name]) <= 1:
                assignments[name].add((row["owner"], row["evidence"]["path"]))
    for group in plan["groups"]:
        if group["image"] != image_name:
            continue
        owner, source = group["owner"], group["source"]
        path = Path(source)
        if owner not in {"game", "libraries"} or path.is_absolute() or ".." in path.parts or not (root / path).is_file():
            raise ValueError(f"invalid freeware data ownership evidence: {source}")
        for name in group["names"]:
            assignments[name].add((owner, source))
    return dict(assignments)


def _placements(map_path: Path, program: str) -> dict[str, set[int]]:
    placements: dict[str, set[int]] = defaultdict(set)
    for row in json.loads(map_path.read_text())["entries"]:
        if row["program"] == program:
            placements[row["name"]].add(match.parse_int(row["address"]))
    return dict(placements)


class LabelOwnership:
    """Source-verified names must have a unique historical placement at the native address."""

    def __init__(self, image: match_builds.BuildImage) -> None:
        self.by_name = _assignments(match.REPO_ROOT, image.build, image.name)
        self.placed = _placements(image.target.data_map_path, image.target.image_name)

    def lookup(self, address: int, names: Collection[str]) -> tuple[str, list[str]]:
        evidence = {
            record for name in names if self.placed.get(name) == {address}
            for record in self.by_name.get(name, ())
        }
        owners = {owner for owner, _ in evidence}
        return next(iter(owners)) if len(owners) == 1 else "unknown", sorted({path for _, path in evidence})
