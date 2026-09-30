from copy import deepcopy
from typing import Any

import pytest

from crimson_re import match_report
from crimson_re import match_report_accounting as accounting


def function() -> dict[str, Any]:
    return {"image": "crimsonland.exe", "address": 100, "size": 10, "name": "example",
            "candidate": "source", "source": "example.cpp", "ratio": 1.0, "matched": True, "linked": False,
            "proof": {"state": "match", "target_size": 10, "target_instructions": 2, "candidate_instructions": 2,
                      "references": {"ok": 1, "unresolved": 0, "mismatched": 0, "positional": True},
                      "body_byte_exact": True, "candidate_object_sha256": "a" * 64,
                      "compared_target_ranges": [[100, 110]], "excluded_target_ranges": [],
                      "unexplained_target_ranges": [], "candidate_padding_bytes": 0}}


def test_credit_requires_full_compared_coverage():
    row = function()
    accounting.validate_function(row)
    row["proof"]["compared_target_ranges"] = [[100, 108]]
    row["proof"]["excluded_target_ranges"] = [{"start": 108, "end": 110, "reason": "recognized terminal padding"}]
    assert not accounting.normalized_exact(row)
    with pytest.raises(ValueError, match="normalized credit"):
        accounting.validate_function(row)
    row["matched"] = False
    accounting.validate_function(row)
    row["proof"]["excluded_target_ranges"] = []
    with pytest.raises(ValueError, match="coverage"):
        accounting.validate_function(row)


@pytest.mark.parametrize("change", ["overlap", "reference_debt", "nonpositional", "encoded_partial", "bad_hash"])
def test_forged_proof_is_rejected(change):
    row = function()
    if change == "overlap":
        row["proof"]["compared_target_ranges"] = [[100, 108], [107, 110]]
    elif change == "reference_debt":
        row["proof"]["references"]["mismatched"] = 1
    elif change == "nonpositional":
        row["proof"]["references"]["positional"] = False
    elif change == "encoded_partial":
        row.update(ratio=0.5, matched=False)
    else:
        row["proof"]["candidate_object_sha256"] = "garbage"
    with pytest.raises(ValueError):
        accounting.validate_function(row)


def test_executable_partition_retains_unknown_gaps_and_rejects_overlap():
    sections = [{"image": "crimsonland.exe", "name": ".text", "address": 90, "size": 40}]
    result = accounting.reconcile_sections(sections, [function()])[0]
    assert result["totals"] == {"retained_code": 10, "unresolved": 30, "padding": 0, "embedded_data": 0}
    assert sum(r["end"] - r["start"] for r in result["ranges"]) == 40
    with pytest.raises(ValueError, match="overlapping"):
        accounting.reconcile_sections(sections, [function(), {**function(), "address": 105}])
    with pytest.raises(ValueError, match="outside"):
        accounting.reconcile_sections(sections, [{**function(), "address": 130}])


def test_readable_unit_names_preserve_native_function_identity():
    before = match_report.build_report([function()])["units"][0]
    after = match_report.build_report([{**function(), "name": "recovered"}])["units"][0]
    assert before["name"] == "example"
    assert after["name"] == "recovered"
    assert before["functions"][0]["name"] == after["functions"][0]["name"]
    assert after["functions"][0]["metadata"]["demangled_name"] == "recovered"


def test_ownership_categories_partition_all():
    result = match_report.build_report([function(), {**function(), "address": 0x401000},
                                       {**function(), "address": 0x452ef0}])
    categories = {c["id"]: c["measures"] for c in result["categories"]}
    assert sum(int(categories[k]["total_code"]) for k in ("game", "libs", "unknown")) == 30
    assert int(categories["unknown"]["total_code"]) == 10


def test_encoded_tier_and_measurement_delta():
    rows = [function(), {**function(), "address": 200, "candidate": "archive", "source": None}]
    evidence: dict[str, Any] = {"functions": rows, "verification": accounting.VERIFICATION, "code_inventory": [],
                "identities": {"target": "a", "inventory": "b", "scoring": "c"}}
    previous = deepcopy(evidence)
    previous["functions"][0]["matched"] = False
    result = accounting.diagnostics(evidence, previous)
    assert result["encoded_body_matched_code"] == 10
    assert result["unmatched_code"] == 10
    assert result["delta"]["comparable"]
    assert result["delta"]["newly_matched_code"] == 10
    previous["identities"]["scoring"] = "old"
    delta = accounting.diagnostics(evidence, previous)["delta"]
    assert not delta["comparable"]
    assert delta["newly_matched_code"] is None
    assert delta["regressed_code"] is None
    # Older schemas establish a baseline without needing their old row layout.
    assert not accounting.diagnostics(evidence, {"schema": 1})["delta"]["comparable"]


@pytest.mark.parametrize("instruction,kind", [("mov eax, [ADDR]", "disp"), ("call ADDR", "imm")])
def test_swapped_reference_identities_cannot_cross_instruction_positions(instruction, kind):
    from crimson_re import match as matchlib

    def line(index, identity):
        reference = matchlib.MaskedReference(0, kind, "test", None, identity, (identity,), True)
        return matchlib.DisassemblyLine(index * 5, index * 5, instruction, 5, (reference,))

    arithmetic = matchlib.DisassemblyLine(5, 5, "add ecx, eax", 2)
    target = (line(0, "a"), arithmetic, line(2, "b"))
    candidate = (line(0, "b"), arithmetic, line(2, "a"))
    audit = matchlib.audit_masked_operands(target, candidate)
    assert audit.mismatch_count == 2
    assert [(e.target_index, e.candidate_index) for e in audit.entries] == [(0, 0), (2, 2)]


def test_measurement_identities_separate_renames_ownership_and_toolchains():
    row = function()
    toolchains = {"vc6": {"config": "scratch/a.conf", "fingerprint": {"compiler_trees": "original"}}}
    before = accounting.identities([row], {}, {}, toolchains)
    renamed = accounting.identities([{**row, "name": "recovered"}], {}, {}, toolchains)
    assert before == renamed
    moved = accounting.identities([row], {}, {}, {"vc6": {**toolchains["vc6"], "config": "scratch/b.conf"}})
    assert moved == before
    compiler = accounting.identities([row], {}, {}, {"vc6": {**toolchains["vc6"], "fingerprint": "changed"}})
    assert compiler["scoring"] != before["scoring"]
    assert compiler["inventory"] == before["inventory"]
    owner = accounting.identities([row], {"analysis/matching_scope.json": "changed"}, {}, toolchains)
    assert owner["inventory"] != before["inventory"]
    assert owner["scoring"] == before["scoring"]


def test_encoded_scope_uses_same_denominator_as_normalized_report():
    row = function()
    row["proof"]["body_byte_exact"] = False
    evidence = {"functions": [row], "verification": accounting.VERIFICATION, "code_inventory": [], "identities": {}}
    result = accounting.diagnostics(evidence, report=match_report.build_report([row]))
    assert result["scopes"]["exe"] == {
        "measures": match_report.build_report([row])["measures"],
        "total_code": 10, "normalized_matched_code": 10,
        "encoded_body_matched_code": 0, "encoded_body_matched_percent": 0,
    }


def test_historical_remapping_changes_inventory_identity():
    row = {**function(), "canonical_address": 0x401000}
    before = accounting.identities([row], {}, {})
    after = accounting.identities([{**row, "canonical_address": 0x452ef0}], {}, {})
    assert before["inventory"] != after["inventory"]
    assert before["scoring"] == after["scoring"]
    # Reordering and renaming functions do not change their byte inventory.
    other = {**row, "address": 200}
    assert accounting.identities([row, other], {}, {}) == accounting.identities([other, row], {}, {})


def test_data_baseline_distinguishes_unmeasured_extents_ownership_and_source_progress():
    section = {"image": "crimsonland.exe", "name": ".data", "address": 1000, "size": 10}
    data = {"sections": [section], "candidates": []}
    before = accounting.identities([function()], {}, {}, data=data)
    assert before["inventory"] != accounting.identities([function()], {}, {})["inventory"]
    changed = {**data, "sections": [{**section, "size": 20}]}
    assert before["inventory"] != accounting.identities([function()], {}, {}, data=changed)["inventory"]
    assert before["inventory"] != accounting.identities(
        [function()], {"tools/native/data_ownership.json": "changed"}, {}, data=data,
    )["inventory"]
    # Matched declarations affect progress, not the denominator.
    assert before == accounting.identities([function()], {}, {}, data={**data, "candidates": ["new match"]})


@pytest.mark.parametrize("version", match_report.match_builds.load_registry().reported)
def test_each_reported_version_has_reconciled_scopes_and_an_explicit_summary(version):
    import json

    evidence = json.loads(match_report.evidence_path(version).read_text())
    report = match_report.build_report(evidence["functions"], data=evidence["data"], linking=evidence.get("linking"))
    metrics = accounting.diagnostics(evidence, report=report)
    assert metrics["version"] == version
    assert metrics["data_measured"] == (evidence["data"] is not None)
    coverage = metrics["executable_coverage"]
    assert coverage["total_bytes"] == sum(coverage[k] for k in ("retained_code", "embedded_data", "padding", "unresolved"))
    if evidence["identities"]["inventory_policy"] == "native-functions-and-full-executable-remainder-v1":
        assert coverage["total_bytes"] == int(report["measures"]["total_code"])
    else:
        assert coverage["retained_code"] == int(report["measures"]["total_code"])
    scopes = {c["id"]: c["measures"] for c in report["categories"]}
    for key in ("total_code", "matched_code", "total_functions", "matched_functions"):
        assert int(report["measures"][key]) == sum(int(scopes[c][key]) for c in ("game", "libs", "unknown"))
        assert int(report["measures"][key]) == sum(int(scopes[c][key]) for c in ("exe", "dll"))
    for category, measures in [(None, report["measures"]), *scopes.items()]:
        units = [u for u in report["units"] if category is None or category in u["metadata"]["progress_categories"]]
        code = sum(int(u["measures"]["total_code"]) for u in units)
        weighted = sum(int(u["measures"]["total_code"]) * u["measures"]["fuzzy_match_percent"] for u in units)
        assert int(measures["total_code"]) == code
        assert measures["fuzzy_match_percent"] == pytest.approx(weighted / code if code else 0)
        assert int(measures.get("total_data", 0)) == sum(int(s["size"]) for u in units for s in u.get("sections", []))
        assert int(measures["complete_code"]) == sum(int(u["measures"]["complete_code"]) for u in units)
        assert int(measures.get("complete_data", 0)) == sum(int(u["measures"].get("complete_data", 0)) for u in units)
    summary = accounting.render_summary(evidence, report, metrics)
    assert f"## Crimsonland {version}" in summary
    assert "Game & Engine" in summary and "Unresolved executable bytes" in summary
    assert "not measured" in summary if evidence["data"] is None else "outside scope" in summary
