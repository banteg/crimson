from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from itertools import pairwise
from pathlib import Path

import pytest

from crimson_re import match as matchlib
from crimson_re import match_builds, match_native_inventory, match_report


@pytest.mark.parametrize("build", ["1.0.2", "1.3.0", "1.4.0"])
def test_freeware_denominator_includes_unique_functions_and_every_executable_byte(build: str) -> None:
    images = match_report._images(build)
    if any(not image.path.is_file() for image in images):
        pytest.skip("pinned freeware images unavailable")
    rows = match_report._inventory(build)
    assert {image.name for image in images} == {"crimson.exe", "grim.dll"}
    assert any(row["native_kind"] == "function" and "canonical_address" not in row for row in rows)
    assert all(row["name"] == f"native_function_{row['address']:08x}" for row in rows
               if row["native_kind"] == "function" and "canonical_address" not in row)
    assert any(row["native_kind"] == "unresolved" for row in rows)
    for image in images:
        image_rows = [row for row in rows if row["image"] == image.name]
        for left, right in pairwise(image_rows):
            assert left["end"] == right["address"]
        assert sum(row["size"] for row in image_rows) == sum(hi-lo for lo, hi in match_builds._code_ranges(image.path))
    reconciliation = match_report.accounting.code_inventory(rows, match_report._image_paths(build))
    assert sum(section["size"] for section in reconciliation) == sum(row["size"] for row in rows)
    assert all(section["size"] == section["totals"]["retained_code"] + section["totals"]["unresolved"] for section in reconciliation)


@pytest.mark.parametrize("invalid", ["image", "maps", "block", "extent", "duplicate", "boundary", "ownership"])
def test_native_inventory_rejects_unbound_boundaries_and_ownership(tmp_path: Path, invalid: str) -> None:
    image = match_builds.load_registry().image("1.0.2", "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware image unavailable")
    assert image.native_inventory is not None
    payload = deepcopy(json.loads(image.native_inventory.read_text()))
    if invalid == "image":
        payload["sha256"] = "0" * 64
    elif invalid == "maps":
        payload["maps_sha256"] = "0" * 64
    elif invalid == "block":
        payload["functions"][0]["blocks"][0]["sha256"] = "0" * 64
    elif invalid == "extent":
        payload["functions"][0]["blocks"][0]["end"] += 1
    elif invalid == "duplicate":
        payload["functions"].append(payload["functions"][0])
    elif invalid == "boundary":
        payload["ownership_ranges"][0]["boundary_sha256"] = "0" * 64
    else:
        payload["ownership_ranges"][0]["start"] = 0
    path = tmp_path / "native.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        match_native_inventory.load(replace(image, native_inventory=path))


def test_native_partition_keeps_unmapped_functions_and_uncredited_gaps() -> None:
    data = bytes.fromhex("31c0c3") + b"\xcc" * 5 + bytes.fromhex("b801000000c3") + b"\xcc" * 2
    image = matchlib.LoadedImage(data, 0x1000, len(data))
    discovered = [
        {"address": start, "name": f"sub_{start:x}", "blocks": [{"address": start, "end": end}]}
        for start, end in [(0x1000, 0x1003), (0x1001, 0x1003), (0x1008, 0x100e)]
    ]
    mapped = [{"address": "0x1000", "end": "0x1003", "name": "known", "evidence": "exact", "canonical_address": "0x2000"}]
    rows = match_native_inventory._partition([(0x1000, 0x1010)], discovered, mapped,
        [{"start": 0x1000, "end": 0x1008, "owner": "game"}], {}, image, "crimson.exe")
    assert [(row["address"], row["size"], row["native_kind"]) for row in rows] == [
        (0x1000, 3, "function"), (0x1003, 5, "unresolved"), (0x1008, 6, "function"), (0x100e, 2, "unresolved"),
    ]
    assert rows[2]["name"] == "sub_1008" and rows[2]["ownership"] == "unknown"
    assert sum(row["size"] for row in rows) == len(data)


def test_unresolved_executable_bytes_are_not_functions_or_source_credit() -> None:
    rows = [{"image": "crimson.exe", "address": 0x401000, "name": "gap", "size": 100,
             "native_kind": "unresolved", "ownership": "game", "candidate": None, "source": None,
             "ratio": 0.0, "matched": False, "linked": False}]
    report = match_report.build_report(rows)
    assert report["measures"]["total_code"] == "100"
    assert report["measures"]["total_functions"] == 0
    assert report["measures"]["matched_code"] == "0"
    assert report["units"][0]["functions"] == []
    assert report["units"][0]["metadata"]["progress_categories"] == ["exe", "game", "unresolved"]
    with pytest.raises(ValueError, match="remainders cannot earn"):
        match_report.build_report([{**rows[0], "candidate": "source", "source": "bad.cpp", "ratio": 1.0, "matched": True}])


def test_native_ownership_changes_measurement_identity_without_inheriting_donor_scope() -> None:
    row = {"image": "crimson.exe", "address": 0x400000, "size": 100, "native_kind": "function",
           "ownership": "unknown", "canonical_address": 0x401000, "name": "helper", "candidate": None,
           "source": None, "ratio": 0.0, "matched": False, "linked": False}
    before = match_report.accounting.identities([row], {}, {})
    after = match_report.accounting.identities([{**row, "ownership": "game"}], {}, {})
    assert before["inventory"] != after["inventory"]
    report = match_report.build_report([row])
    categories = {category["id"]: category["measures"] for category in report["categories"]}
    assert categories["game"]["total_code"] == "0"
    assert categories["unknown"]["total_code"] == "100"


def test_native_inventory_is_a_pinned_report_input() -> None:
    assert match_report._input_path("analysis/decomp/1.4.0/crimson.exe/native.json")
    assert match_report._input_path("crimson-re/src/crimson_re/match_native_inventory.py")
