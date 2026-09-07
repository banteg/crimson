from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from crimson import match_data_inventory as inventory
from crimson import match_data_report, match_report


def object_row(address: int, size: int, name: str) -> dict[str, Any]:
    return {"image": "crimsonland.exe", "address": address, "size": size, "name": name}


def test_complete_partition_retains_unnamed_unknown_and_unmatched_owned_bytes() -> None:
    definitions = [object_row(110, 30, "game"), object_row(115, 5, "field"), object_row(160, 10, "library")]
    assignments = [{**definitions[0], "owner": "game"}, {**definitions[2], "owner": "libraries"}]
    candidate = {**object_row(110, 10, "game_head"), "source": "game.cpp"}
    evidence = {"sections": [{"image": "crimsonland.exe", "name": ".data", "address": 100, "size": 100}],
                "candidates": [candidate], "ownership": assignments}
    spans = inventory.partition(evidence, definitions, assignments)
    assert sum(row["size"] for row in spans) == 100
    assert sum(row["size"] for row in spans if row["matched"]) == 10
    assert sum(row["size"] for row in spans if row["owner"] == "game") == 30
    assert sum(row["size"] for row in spans if row["owner"] == "unknown") == 60
    assert sum(row["size"] for row in spans if not row["objects"]) == 60
    # Ownership and the complete denominator do not disappear when credit disappears.
    evidence["candidates"] = []
    no_matches = inventory.partition(evidence, definitions, assignments)
    assert sum(row["size"] for row in no_matches if row["owner"] == "game") == 30


def test_cross_owner_overlap_is_rejected() -> None:
    section = {"image": "crimsonland.exe", "name": ".data", "address": 100, "size": 100}
    assignments = [{**object_row(110, 30, "game"), "owner": "game"},
                   {**object_row(120, 10, "library"), "owner": "libraries"}]
    evidence = {"sections": [section], "candidates": [], "ownership": assignments}
    with pytest.raises(ValueError, match="conflicting"):
        inventory.partition(evidence, assignments, assignments)
    with pytest.raises(ValueError, match="conflicting"):
        match_data_report.report_spans(evidence)


def test_partial_ownership_filters_never_silently_narrow_game_code_category() -> None:
    evidence = {"sections": [{"image": "crimsonland.exe", "name": ".data", "address": 100, "size": 100}],
                "candidates": [{**object_row(110, 10, "game"), "source": "game.cpp"}],
                "ownership": [{**object_row(110, 30, "game"), "owner": "game"}]}
    report = match_report.build_report([], data=evidence)
    categories = {row["id"]: row for row in report["categories"]}
    assert "attributed" in categories["game.data"]["name"]
    assert categories["game.data"]["measures"]["total_data"] == "30"
    assert categories["game.data"]["measures"]["matched_data"] == "10"
    assert categories["data_unknown"]["measures"]["total_data"] == "70"
    assert "total_data" not in categories["game"]["measures"]
    assert report["measures"]["total_data"] == "100"


def test_successful_compilation_does_not_assign_ownership() -> None:
    evidence = {"sections": [{"image": "crimsonland.exe", "name": ".data", "address": 100, "size": 20}],
                "candidates": [{**object_row(100, 20, "unattributed"), "source": "new.cpp"}],
                "ownership": []}
    spans = inventory.partition(evidence, [object_row(100, 20, "unattributed")], [])
    assert all(row["matched"] and row["owner"] == "unknown" for row in spans)
    report = match_report.build_report([], data=evidence)
    categories = {row["id"]: row["measures"] for row in report["categories"]}
    assert categories["data_unknown"]["matched_data"] == "20"
    assert "total_data" not in categories["game.data"]


def test_inventory_files_must_agree_with_evidence(tmp_path: Path) -> None:
    data = {"totals": {"matched_bytes": 0, "total_bytes": 20, "unmatched_bytes": 20, "unnamed_bytes": 20},
            "ownership": {"unknown": {"total_bytes": 20, "matched_bytes": 0}}, "objects": [], "spans": []}
    output, summary = tmp_path / "data.json", tmp_path / "DATA.md"
    inventory.write_inventory(data, output=output, summary=summary)
    inventory.validate_inventory(data, output=output, summary=summary)
    summary.write_text(summary.read_text() + "stale narrative")
    with pytest.raises(ValueError, match="summary differs"):
        inventory.validate_inventory(data, output=output, summary=summary)
    inventory.write_inventory(data, output=output, summary=summary)
    output.write_text("{}")
    with pytest.raises(ValueError, match="inventory differs"):
        inventory.validate_inventory(data, output=output, summary=summary)
