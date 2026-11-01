from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from crimson_re import match as matchlib
from crimson_re import match_builds, match_native_inventory, match_report


@pytest.mark.parametrize("invalid", ["maps", "block"])
def test_native_inventory_rejects_unbound_boundaries_and_ownership(tmp_path: Path, invalid: str) -> None:
    image = match_builds.load_registry().image("1.0.2", "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware image unavailable")
    assert image.native_inventory is not None
    payload = deepcopy(json.loads(image.native_inventory.read_text()))
    if invalid == "maps":
        payload["maps_sha256"] = "0" * 64
    else:
        payload["functions"][0]["blocks"][0]["sha256"] = "0" * 64
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


def test_identity_only_pin_preserves_native_entries_inside_dispatcher() -> None:
    image = matchlib.LoadedImage(bytes.fromhex("9090c3c3"), 0x1000, 4)
    discovered = [
        {"address": 0x1000, "name": "first", "blocks": [{"address": 0x1000, "end": 0x1004}]},
        {"address": 0x1003, "name": "second", "blocks": [{"address": 0x1003, "end": 0x1004}]},
    ]
    mapped = [{"address": "0x1000", "end": "0x1004", "name": "dispatcher", "evidence": "recovered",
               "build_only": True, "identity_only": True}]
    rows = match_native_inventory._partition([(0x1000, 0x1004)], discovered, mapped, [], {}, image, "crimson.exe")
    assert [(row["name"], row["size"]) for row in rows] == [("dispatcher", 3), ("second", 1)]


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


def test_port_scope_uses_native_addresses_and_retains_unnamed_engine_code() -> None:
    rows = [
        {"address": 1, "name": "native_function_1", "native_kind": "function", "ownership": "game"},
        {"address": 2, "name": "misleading_donor_name", "native_kind": "function", "ownership": "game"},
        {"address": 3, "native_kind": "unresolved", "ownership": "game"},
        {"address": 4, "native_kind": "function", "ownership": "unknown"},
        {"address": 5, "native_kind": "function", "ownership": "libs.other"},
    ]
    device = {"address": 2, "reason": "Releases the FMOD device."}
    match_native_inventory._apply_port_scope(rows, [device])
    assert [r["address"] for r in rows if match_native_inventory.in_port_scope(r)] == [1]
    assert rows[1]["platform_replaced"] == device["reason"]
    for invalid in ([device, device], [{**device, "reason": " "}], *[[{**device, "address": a}] for a in (3, 4, 5, 6)]):
        with pytest.raises(ValueError, match="platform exclusion"):
            match_native_inventory._apply_port_scope(rows, invalid)


def test_report_and_triage_share_the_native_function_denominator() -> None:
    def record(address: int, name: str, kind: str, owner: str) -> dict:
        return {"image": "crimson.exe", "address": address, "end": address + 8, "size": 8, "name": name,
                "native_kind": kind, "ownership": owner, "candidate": None, "source": None, "ratio": 0.0,
                "matched": False, "linked": False}

    rows = [
        record(8, "fx_queue_add_shell", "function", "game"),
        record(16, "native_function_00000010", "function", "game"),
        record(24, "driver", "function", "game"),
        record(32, "remainder", "unresolved", "game"),
        record(40, "unidentified", "function", "unknown"),
    ]
    rows[0]["name_evidence"] = "recovered"
    rows[2]["name_evidence"] = "ordered"
    match_native_inventory._apply_port_scope(rows, [{"address": 24, "reason": "Device polling."}])
    scoped = {r["address"]: r for r in rows if match_native_inventory.in_port_scope(r)}
    triage = matchlib.collect_triage_rows([], native_functions={"crimson.exe": scoped})
    assert [(r.address, r.state) for r in triage] == [(8, "missing"), (16, "missing")]
    all_rows = matchlib.collect_triage_rows([], native_functions={"crimson.exe": {r["address"]: r for r in rows if r["native_kind"] == "function"}})
    device = matchlib.triage_row_payload(next(r for r in all_rows if r.address == 24))
    assert device["name_evidence"] == "ordered" and device["platform_replaced"] == "Device polling."
    report = match_report.build_report(rows)
    metrics = {c["id"]: c["measures"] for c in report["categories"]}
    for category, functions, size in (("port", 2, 16), ("platform", 1, 8), ("game", 3, 32), ("unknown", 1, 8)):
        assert (metrics[category]["total_functions"], int(metrics[category]["total_code"])) == (functions, size)
    assert report["measures"]["total_functions"] == 4
    before = match_report.accounting.identities(rows, {}, {})["inventory"]
    rows[2]["platform_replaced"] = None
    assert match_report.accounting.identities(rows, {}, {})["inventory"] != before


@pytest.mark.parametrize(("version", "port_count", "platform_count"), [
    ("1.0.2", 176, 26), ("1.3.0", 238, 36), ("1.4.0", 313, 43),
])
def test_shipped_port_scopes_preserve_behavior_and_reject_backend_leaves(
    version: str, port_count: int, platform_count: int,
) -> None:
    registry = match_builds.load_registry()
    if not all(image.path.is_file() for image in registry.builds[version].values()):
        pytest.skip("pinned freeware images unavailable")
    inventory = match_native_inventory.build_functions(registry, version, "all")
    port = [row for functions in inventory.values() for row in functions.values() if match_native_inventory.in_port_scope(row)]
    assert len(port) == port_count
    assert sum(bool(r.get("platform_replaced")) for functions in inventory.values() for r in functions.values()) == platform_count
    names = {r["name"] for r in port}
    assert {"creature_update_all", "grim_timing_update", "grim_was_key_pressed", "grim_draw_quad"} <= names
    assert names.isdisjoint({"grim_d3d_init", "grim_keyboard_poll", "grim_load_interface", "DllMain"})
    assert any(name.startswith("native_function_") for name in names)
    if version == "1.0.2":
        # Ordered donor names misidentify both FMOD functions. Only the device leaf is excluded.
        assert inventory["crimson.exe"][0x401600]["platform_replaced"]
        assert match_native_inventory.in_port_scope(inventory["crimson.exe"][0x401470])
    if version == "1.4.0":
        assert {"fx_queue_add_shell", "freeware_level_render_layer", "sfx_play_panned", "game_startup_init"} <= names
