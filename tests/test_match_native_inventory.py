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
    assert rows[0]["end"] == 0x1003 and rows[0]["comparison_end"] == 0x1004
    assert "comparison_end" not in rows[1]


@pytest.mark.parametrize(("version", "end"), [("1.0.2", 0x40ed76), ("1.3.0", 0x4183a3)])
def test_scoped_scratch_and_scan_compare_the_pinned_dispatcher(
    version: str, end: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = match_builds.load_registry()
    image = registry.image(version, "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware image unavailable")
    directory = matchlib.DEFAULT_MATCH_ROOT / "scratches/game_frame_update"
    config = matchlib.load_scratch_config(directory)
    assert image.scratch_config(config, scope="port").end_va == end

    (tmp_path / "scratches").mkdir()
    (tmp_path / "scratches" / directory.name).symlink_to(directory, target_is_directory=True)
    def evaluate(configs, *args, **kwargs):
        return [matchlib.ScratchStatus(config, 0, 0, None, 0, 0, 0, "stub") for config in configs]

    monkeypatch.setattr(matchlib, "evaluate_scratch_configs", evaluate)
    scan = match_builds.scan_build(registry, version, tmp_path, native_inventory=True)
    assert [row.status.config.end_va for row in scan] == [end]


@pytest.mark.parametrize(("version", "start", "end", "next_start", "interior"), [
    ("1.0.2", 0x40C110, 0x40ED76, 0x40EDA0, (0x40C38C, 0x40CF97, 0x40D9E8, 0x40DA6D, 0x40DAA4, 0x40E4FA)),
    ("1.3.0", 0x412FD0, 0x4183A3, 0x4183E0, (0x41445D, 0x4161CF, 0x4171CB, 0x417237, 0x4172F3, 0x4175F9, 0x417885)),
])
def test_verified_frame_dispatcher_preserves_raw_entries_and_uncredited_tables(
    version: str, start: int, end: int, next_start: int, interior: tuple[int, ...],
) -> None:
    image = match_builds.load_registry().image(version, "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware image unavailable")
    assert image.native_inventory is not None
    discovery = json.loads(image.native_inventory.read_text())
    raw = {row["address"] for row in discovery["functions"] if start < row["address"] < end}
    assert raw == set(interior)
    rows = match_native_inventory.load(image)
    retained = [row for row in rows if start <= row["address"] < next_start]
    assert [(row["address"], row["end"], row["native_kind"]) for row in retained] == [
        (start, end, "function"), (end, next_start, "unresolved"),
    ]
    dispatcher, tables = retained
    assert dispatcher["name"] == "game_frame_update" and match_native_inventory.in_port_scope(dispatcher)
    assert "comparison_end" not in dispatcher
    assert tables["size"] == next_start - end
    assert sum(row["size"] for row in rows) == sum(hi - lo for lo, hi in match_builds._code_ranges(image.path))


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
    ("1.0.2", 169, 26), ("1.3.0", 233, 36), ("1.4.0", 311, 43),
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
    assert not any(name.startswith("native_function_") for name in names)
    if version == "1.0.2":
        assert inventory["crimson.exe"][0x40B180]["name"] == "freeware_encounter_update"
        assert 0x40B1AE not in inventory["crimson.exe"]
        # Ordered donor names misidentify both FMOD functions. Only the device leaf is excluded.
        assert inventory["crimson.exe"][0x401600]["platform_replaced"]
        assert match_native_inventory.in_port_scope(inventory["crimson.exe"][0x401470])
    if version == "1.3.0":
        assert inventory["crimson.exe"][0x4017A0]["name"] == "freeware_brush_register_atexit"
        assert inventory["crimson.exe"][0x405D60]["name"] == "gameplay_reset_state"
    if version == "1.4.0":
        assert inventory["crimson.exe"][0x403AF0]["name"] == "freeware_brush_register_atexit"
        assert inventory["crimson.exe"][0x41E320]["name"] == "freeware_editor_offset_destroy"
        # Four former interior entries belong to the arithmetic command's switch.
        assert inventory["crimson.exe"][0x4019F0]["end"] == 0x401AC6
        assert 0x401A45 not in inventory["crimson.exe"]
        assert inventory["crimson.exe"][0x401EE0]["name"] == "console_init"
        assert inventory["grim.dll"][0x10005F30]["ownership"] != "game"
        assert {"fx_queue_add_shell", "freeware_level_render_layer", "sfx_play_panned", "crimsonland_main"} <= names
