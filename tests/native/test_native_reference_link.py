from __future__ import annotations

import copy
import json
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pefile
import pytest

from crimson_re import match as matchlib
from crimson_re import match_report
from crimson_re import native_reference_link as link


@pytest.fixture
def evidence() -> dict[str, Any]:
    if not matchlib._paths_for_image("grim.dll")[0].is_file():
        pytest.skip("canonical reference image unavailable")
    return json.loads(match_report.evidence_path("1.9.93").read_text())


def test_only_proven_source_ranges_receive_linked_credit(evidence: dict[str, Any]) -> None:
    receipt = evidence["linking"]
    report = match_report.build_report(evidence["functions"], data=evidence["data"], linking=receipt)
    unlinked = match_report.build_report(evidence["functions"], data=evidence["data"])
    assert report["measures"]["complete_code"] == "64"
    assert report["measures"]["complete_data"] == "1024"
    assert report["measures"]["complete_units"] == 6
    for field in ("total_code", "matched_code", "total_data", "matched_data", "fuzzy_match_percent"):
        assert report["measures"][field] == unlinked["measures"][field]
    completed = [u for u in report["units"] if u["metadata"]["complete"]]
    assert len(completed) == 6
    assert all(u["metadata"]["source_path"] in {"decomp/1.9/grim/state/slot_state.cpp", "tools/match/data/grim_slot_state.cpp"}
               for u in completed)
    scopes = {c["id"]: c["measures"] for c in report["categories"]}
    assert scopes["game"]["complete_code"] == "64"
    assert scopes["game.data"]["complete_data"] == "1024"
    assert scopes["libs"]["complete_code"] == scopes["exe"]["complete_code"] == "0"
    assert unlinked["measures"]["complete_code"] == unlinked["measures"]["complete_data"] == "0"


@pytest.mark.parametrize("field,value", [("address", 0x100072C1), ("sha256", "0" * 64)])
def test_link_receipt_rejects_wrong_range_proof(evidence: dict[str, Any], field: str, value: Any) -> None:
    receipt = copy.deepcopy(evidence["linking"])
    receipt["components"][0]["records"][0][field] = value
    with pytest.raises(ValueError):
        link.validate(receipt, evidence["functions"], evidence["data"])


@pytest.mark.parametrize("change", ["missing-relocation", "wrong-target"])
def test_link_receipt_rejects_incomplete_or_false_closure(evidence: dict[str, Any], change: str) -> None:
    receipt = copy.deepcopy(evidence["linking"])
    component = receipt["components"][0]
    if change == "missing-relocation":
        component["relocations"].pop()
    else:
        component["relocations"][0]["target"] += 4
    with pytest.raises(ValueError):
        link.validate(receipt, evidence["functions"], evidence["data"])


def test_reservations_contain_only_uncredited_zero_storage() -> None:
    raw = link._reservation_object([(".text$A", 32, 0x60000020), (".data$A", 16, 0xC0000040)])
    obj = matchlib.parse_coff_object(raw)
    assert not obj.symbols
    assert [s.data for s in obj.sections] == [bytes(32), bytes(16)]
    assert not any(s.relocations for s in obj.sections)
    with pytest.raises(ValueError):
        link._reservation_object([(".text$A", -1, 0x60000020)])


@pytest.mark.parametrize("kind", ["code", "data", "base-relocation", "permissions", "entry"])
def test_final_pe_proof_rejects_changed_bytes_and_loader_metadata(
    evidence: dict[str, Any], tmp_path: Path, kind: str,
) -> None:
    saved = evidence["linking"]["components"][0]
    artifact = matchlib.REPO_ROOT / saved["artifact"]
    if not artifact.is_file():
        pytest.skip("local linked component unavailable")
    raw = bytearray(artifact.read_bytes())
    with pefile.PE(data=raw) as pe:
        if kind in {"code", "data"}:
            row = next(r for r in saved["records"] if r["kind"] == kind)
            offset = pe.get_offset_from_rva(row["address"] - pe.OPTIONAL_HEADER.ImageBase)
            raw[offset] ^= 1
        elif kind == "base-relocation":
            entry = next(e for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type)
            struct.pack_into("<H", raw, entry.struct.get_file_offset(), 0)
        elif kind == "entry":
            offset = pe.OPTIONAL_HEADER.get_field_absolute_offset("AddressOfEntryPoint")
            struct.pack_into("<I", raw, offset, 0x72C0)
        else:
            section = link._section(pe, saved["records"][0]["address"], 14)
            struct.pack_into("<I", raw, section.get_field_absolute_offset("Characteristics"), section.Characteristics | 0x80000000)
    path = tmp_path / "changed.dll"
    path.write_bytes(raw)
    component = link._plan(evidence["functions"], evidence["data"])[0]
    with pytest.raises(ValueError):
        link._verify_pe(path, component, saved["relocations"])


def test_adapter_preserves_source_code_and_relocation_records(evidence: dict[str, Any]) -> None:
    component = link._plan(evidence["functions"], evidence["data"])[0]
    path = matchlib._scratch_object_path(component["config"])
    if not path.is_file():
        pytest.skip("local source object unavailable")
    raw = path.read_bytes()
    adapted, relocations, size = link._adapt_code(raw, component["code"])
    original, output = matchlib.parse_coff_object(raw), matchlib.parse_coff_object(adapted)
    assert size == 96  # Only 64 decoded body bytes are credited.
    assert len(relocations) == 4
    for left, right in zip(original.sections, output.sections, strict=True):
        assert left.data == right.data and left.relocations == right.relocations
    for left, right in zip(original.symbols, output.symbols, strict=True):
        if left.storage_class == 3 and left.name == ".text":
            assert right.name == ".text$M" and replace(left, name=right.name) == right
        else:
            assert left == right
    wrong = copy.deepcopy(component["code"])
    wrong[1]["address"] += 1
    with pytest.raises(ValueError, match="organization"):
        link._adapt_code(raw, wrong)


def test_duplicate_loader_relocations_are_rejected() -> None:
    relocation = SimpleNamespace(rva=0x72C7, type=3)
    pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x10000000),
                         DIRECTORY_ENTRY_BASERELOC=[SimpleNamespace(entries=[relocation, relocation])])
    with pytest.raises(ValueError, match="duplicate"):
        link._relocations(cast(pefile.PE, pe))


def test_ci_checks_source_bound_receipts_without_ignored_build_artifacts(
    evidence: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = link._plan(evidence["functions"], evidence["data"])[0]
    missing = {
        matchlib._scratch_object_path(matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches" / row["name"]))
        for row in component["code"]
    }
    missing.add(matchlib._compiler_executable_path(component["config"], matchlib.DEFAULT_MATCH_ROOT).parent / "LINK.EXE")
    missing.add(matchlib.REPO_ROOT / evidence["linking"]["components"][0]["archive"]["file"]["path"])
    is_file = Path.is_file
    exists = Path.exists

    def available(path: Path) -> bool:
        return False if path in missing or path.is_relative_to(link.OUTPUT) else is_file(path)

    monkeypatch.setattr(Path, "is_file", available)
    monkeypatch.setattr(Path, "exists", lambda path: False if path in missing or path.is_relative_to(link.OUTPUT) else exists(path))
    link.validate(evidence["linking"], evidence["functions"], evidence["data"])
    altered = copy.deepcopy(evidence["linking"])
    altered["components"][0]["relocations"].pop()
    with pytest.raises(ValueError, match="relocation proof"):
        link.validate(altered, evidence["functions"], evidence["data"])
