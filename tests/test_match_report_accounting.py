from copy import deepcopy
from typing import Any

import pytest

from crimson import match_report
from crimson import match_report_accounting as accounting


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
    assert not accounting.diagnostics(evidence, previous)["delta"]["comparable"]


@pytest.mark.parametrize("instruction,kind", [("mov eax, [ADDR]", "disp"), ("call ADDR", "imm")])
def test_swapped_reference_identities_cannot_cross_instruction_positions(instruction, kind):
    from crimson import match as matchlib

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
    before = accounting.identities([row], {}, {}, {"vc6": "original"})
    renamed = accounting.identities([{**row, "name": "recovered"}], {}, {}, {"vc6": "original"})
    assert before == renamed
    compiler = accounting.identities([row], {}, {}, {"vc6": "changed"})
    assert compiler["scoring"] != before["scoring"]
    assert compiler["inventory"] == before["inventory"]
    owner = accounting.identities([row], {"analysis/matching_scope.json": "changed"}, {}, {"vc6": "original"})
    assert owner["inventory"] != before["inventory"]
    assert owner["scoring"] == before["scoring"]


def test_encoded_scope_uses_same_denominator_as_normalized_report():
    row = function()
    row["proof"]["body_byte_exact"] = False
    evidence = {"functions": [row], "verification": accounting.VERIFICATION, "code_inventory": [], "identities": {}}
    result = accounting.diagnostics(evidence, report=match_report.build_report([row]))
    assert result["scopes"]["exe"] == {
        "total_code": 10, "normalized_matched_code": 10,
        "encoded_body_matched_code": 0, "encoded_body_matched_percent": 0,
    }
