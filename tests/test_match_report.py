from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from crimson import match_report as report


def _function(address: int, size: int, **changes: Any) -> dict[str, Any]:
    return {
        "image": "crimsonland.exe", "address": address, "name": f"function_{address}", "size": size,
        "candidate": "source", "source": f"src/{address}.c", "ratio": 1.0, "matched": True, "linked": False,
        **changes,
    }


def test_public_score_uses_full_denominator_without_crediting_prebuilt_libraries() -> None:
    result = report.build_report([
        _function(1, 100),
        _function(2, 300, ratio=0.5, matched=False),
        _function(3, 500, candidate="archive", source=None),
        _function(4, 40, candidate="import-thunk", source=None),
        _function(5, 60, candidate=None, source=None, ratio=0.0, matched=False),
    ])
    m = result["measures"]
    assert m["total_code"] == "1000"
    assert m["matched_code"] == "100"
    assert m["matched_code_percent"] == 10.0
    assert m["fuzzy_match_percent"] == 25.0
    assert m["matched_functions"] == 1
    assert m["total_functions"] == 5
    assert m["complete_code"] == "0"
    assert m["complete_units"] == 0
    assert result["version"] == 2
    assert next(c for c in result["categories"] if c["id"] == "exe")["measures"] == m
    assert result["units"][0]["metadata"]["source_path"] == "src/1.c"
    assert result["units"][2]["functions"][0]["fuzzy_match_percent"] == 0


def test_reference_debt_never_paints_a_perfect_match() -> None:
    result = report.build_report([_function(1, 100, matched=False)])
    assert result["measures"]["matched_functions"] == 0
    assert result["units"][0]["functions"][0]["fuzzy_match_percent"] < 100


def test_library_filters_overlap_images_without_double_counting() -> None:
    result = report.build_report([
        _function(0x00401000, 100),
        _function(0x00452EF0, 200, candidate="archive", source=None),
        _function(0x1000A8D0, 300, image="grim.dll", ratio=0.5, matched=False),
        _function(0x1000AAA6, 400, image="grim.dll"),
    ])
    categories = {c["id"]: c["measures"] for c in result["categories"]}
    assert categories["exe"]["total_code"] == "300"
    assert categories["dll"]["total_code"] == "700"
    assert categories["libs"]["total_code"] == "900"
    assert categories["libs.d3dx8"]["total_code"] == "600"
    assert categories["libs.msvc6-crt"]["total_code"] == "300"
    assert categories["libs"]["matched_code"] == "400"
    assert categories["libs"]["fuzzy_match_percent"] == pytest.approx(55000 / 900)
    assert result["measures"]["total_code"] == "1000"
    assert result["units"][2]["metadata"]["progress_categories"] == ["dll", "libs", "libs.msvc6-crt"]
    assert result["units"][3]["metadata"]["progress_categories"] == ["dll", "libs", "libs.d3dx8"]


def test_game_category_keeps_platform_code_but_excludes_known_libraries() -> None:
    ownership = report.matchlib._load_matching_scope_definition("port")
    platform = next(d for d in ownership.function_dispositions["crimsonland.exe"] if d.disposition == "platform-replaced")
    library = next(d for d in ownership.function_dispositions["grim.dll"] if d.disposition == "third-party")
    result = report.build_report([
        _function(platform.address, 100),
        _function(library.address, 200, image="grim.dll"),
        _function(0x00452EF0, 300),
        _function(0x1004B5B0, 400, image="grim.dll"),
    ])
    categories = {c["id"]: c["measures"] for c in result["categories"]}
    assert categories["game"]["total_code"] == "100"
    assert categories["libs"]["total_code"] == "500"
    assert categories["libs.other"]["total_code"] == "200"
    assert result["measures"]["total_code"] == "1000"


def test_function_identity_includes_the_image_and_names_are_disambiguated() -> None:
    rows = [_function(1, 100, name="same"), _function(2, 50, image="grim.dll", name="same")]
    result = report.build_report(rows)
    assert len({unit["name"] for unit in result["units"]}) == 2
    assert result["measures"]["total_code"] == "150"
    with pytest.raises(ValueError, match="duplicate"):
        report.build_report([rows[0], rows[0]])


@pytest.mark.parametrize("changes", [
    {"ratio": float("nan")}, {"ratio": 1.1}, {"size": -1}, {"ratio": 0.8}, {"linked": True},
])
def test_invalid_or_unsupported_credit_is_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        report.build_report([{**_function(1, 100), **changes}])


def test_evidence_is_bound_to_inputs_and_full_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    function = _function(1, 100)
    evidence: dict[str, Any] = {
        "schema": 2, "version": "1.9.93", "scope": "all", "inputs": {"scratch.c": "original"},
        "external_inputs": {}, "toolchains": {}, "functions": [function], "data": {},
    }
    monkeypatch.setattr(report, "repository_inputs", lambda: {"scratch.c": "original"})
    monkeypatch.setattr(report.match_data_report, "validate_evidence", lambda _: None)
    monkeypatch.setattr(report, "_inventory", lambda: [{k: function[k] for k in ("image", "address", "name", "size")}])
    report.validate_evidence(evidence)
    altered = deepcopy(evidence)
    altered["functions"][0]["size"] = 99
    with pytest.raises(ValueError, match="denominator"):
        report.validate_evidence(altered)
    monkeypatch.setattr(report, "repository_inputs", lambda: {"scratch.c": "changed"})
    with pytest.raises(ValueError, match="stale"):
        report.validate_evidence(evidence)


def test_missing_reference_images_fail_even_when_ci_lacks_compilers(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = {
        "schema": 2, "version": "1.9.93", "scope": "all", "inputs": {},
        "external_inputs": {"game_bins/reference.exe": "a" * 64}, "toolchains": {}, "functions": [],
    }
    monkeypatch.setattr(report, "repository_inputs", dict)
    monkeypatch.setattr(report.match_toolchain, "file_sha256", lambda _: None)
    with pytest.raises(ValueError, match="artifact changed or missing"):
        report.validate_evidence(evidence)


def test_input_selection_ignores_research_notes_but_tracks_builds() -> None:
    assert report._input_path("tools/match/scratches/new_function/scratch.conf")
    assert report._input_path("tools/match/include/shared.h")
    assert report._input_path("analysis/ida/raw/grim.dll/functions.json")
    assert report._input_path("analysis/matching_scope.json")
    assert report._input_path("tools/native/data_candidates.json")
    assert report._input_path("src/crimson/native_link.py")
    assert not report._input_path("analysis/decomp/1.9.93.json")
    assert not report._input_path("tools/match/scratches/new_function/experiments.jsonl")
    assert not report._input_path("tools/match/STATUS.md")
    assert not report._input_path("analysis/native/grim.dll/link/link.json")


def test_added_and_deleted_build_inputs_invalidate_snapshot(tmp_path: Path) -> None:
    # Exercise real git file enumeration: new untracked source counts as an
    # input, and a deleted tracked source cannot leave a publishable snapshot.
    import shutil
    import subprocess

    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)
    source = tmp_path / "tools/match/scratches/example/scratch.c"
    source.parent.mkdir(parents=True)
    source.write_text("void example(void) {}")
    assert source.relative_to(tmp_path).as_posix() in report.repository_inputs(tmp_path)
    subprocess.run([git, "-C", str(tmp_path), "add", "."], check=True)
    source.unlink()
    with pytest.raises(ValueError, match="missing report input"):
        report.repository_inputs(tmp_path)
