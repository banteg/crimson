from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, Self

import pytest

from crimson import match as matchlib
from crimson import match_data_report as data_report
from crimson import match_report


def _candidate(address: int, size: int, *, image: str = "crimsonland.exe", name: str = "pool") -> dict[str, Any]:
    return {"image": image, "address": address, "size": size, "name": name, "source": "tools/match/data/pool.cpp"}


def test_partition_retains_gaps_and_deduplicates_overlapping_definitions() -> None:
    evidence = {
        "sections": [
            {"image": "crimsonland.exe", "name": ".data", "address": 100, "size": 100},
            {"image": "grim.dll", "name": ".data", "address": 100, "size": 20},
        ],
        "candidates": [
            _candidate(110, 20), _candidate(115, 5, name="field"),
            _candidate(100, 4, image="grim.dll"),
        ],
    }
    spans = data_report.report_spans(evidence)
    assert sum(span["size"] for span in spans) == 120
    assert sum(span["size"] for span in spans if span["matched"]) == 24
    assert all(span["name"] == "pool" for span in spans if span["matched"])
    # Merely locating or specifying a data object must not create match credit.
    evidence["candidates"] = []
    unmatched = data_report.report_spans(evidence)
    assert sum(span["size"] for span in unmatched) == 120
    assert not any(span["matched"] for span in unmatched)


def test_data_totals_are_image_scoped_and_do_not_change_code_progress() -> None:
    function = {
        "image": "crimsonland.exe", "address": 0x401000, "name": "function", "size": 100,
        "candidate": "source", "source": "function.c", "ratio": 1.0, "matched": True, "linked": False,
    }
    data = {
        "sections": [{"image": "crimsonland.exe", "name": ".data", "address": 0x471000, "size": 40}],
        "candidates": [_candidate(0x471008, 8)],
    }
    report = match_report.build_report([function], data=data)
    measures = report["measures"]
    assert measures["total_data"] == "40"
    assert measures["matched_data"] == "8"
    assert measures["matched_data_percent"] == 20.0
    assert measures["complete_data"] == "0"
    assert measures["total_code"] == "100"
    assert measures["fuzzy_match_percent"] == 100.0
    assert measures["total_functions"] == 1
    assert measures["total_units"] == len(report["units"])
    categories = {c["id"]: c["measures"] for c in report["categories"]}
    assert categories["exe"]["total_data"] == "40"
    assert "total_data" not in categories["game"]
    assert sum(int(unit["measures"].get("matched_data", 0)) for unit in report["units"]) == 8


def test_denominator_uses_virtual_data_extents_including_zero_fill(monkeypatch: pytest.MonkeyPatch) -> None:
    import pefile

    class ReferencePE:
        OPTIONAL_HEADER = SimpleNamespace(ImageBase=0x400000)
        sections = (
            SimpleNamespace(Name=b".data\0", VirtualAddress=0x1000, Misc_VirtualSize=1025, SizeOfRawData=512, Characteristics=0xC0000040),
            SimpleNamespace(Name=b".rdata\0", VirtualAddress=0x2000, Misc_VirtualSize=17, SizeOfRawData=512, Characteristics=0x40000040),
            SimpleNamespace(Name=b".bss\0", VirtualAddress=0x3000, Misc_VirtualSize=256, SizeOfRawData=0, Characteristics=0xC0000080),
            SimpleNamespace(Name=b".text\0", Misc_VirtualSize=100),
            SimpleNamespace(Name=b".rsrc\0", Misc_VirtualSize=10000),
            SimpleNamespace(Name=b".reloc\0", Misc_VirtualSize=10000),
        )

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            pass

    monkeypatch.setattr(pefile, "PE", lambda *args, **kwargs: ReferencePE())
    monkeypatch.setattr(matchlib, "TRACKED_IMAGE_NAMES", ("crimsonland.exe",))
    sections = data_report.section_inventory()
    assert sum(section["size"] for section in sections) == 1298
    assert [section["name"] for section in sections] == [".data", ".rdata", ".bss"]


def _symbol(section: int, value: int) -> matchlib.CoffSymbol:
    return matchlib.CoffSymbol(0, "_pool", value, section, 0, matchlib.IMAGE_SYM_CLASS_EXTERNAL)


def test_coff_common_requires_a_definition_of_the_verified_size() -> None:
    assert data_report._check_storage(matchlib.CoffObject((), (_symbol(0, 16),)), "pool", 16) == "coff-common"
    for size in (0, 8, 32):
        with pytest.raises(ValueError, match="no storage"):
            data_report._check_storage(matchlib.CoffObject((), (_symbol(0, size),)), "pool", 16)


def test_coff_storage_rejects_nonzero_bytes_relocations_and_code() -> None:
    section = matchlib.CoffSection(".data", bytes(16), 0xC0000040, (), index=1, logical_size=16)
    obj = matchlib.CoffObject((section,), (_symbol(1, 8),))
    assert data_report._check_storage(obj, "pool", 4) == "coff-data"
    bss = replace(section, name=".bss", data=b"", characteristics=0xC0000080)
    assert data_report._check_storage(replace(obj, sections=(bss,)), "pool", 4) == "coff-bss"
    invalid = [
        replace(section, data=bytes(8) + b"\x01" + bytes(7)),
        replace(section, relocations=(matchlib.CoffRelocation(7, 0, 0x0006),)),
        replace(section, characteristics=0x60000020),
        replace(section, logical_size=10),
    ]
    for changed in invalid:
        with pytest.raises(ValueError):
            data_report._check_storage(replace(obj, sections=(changed,)), "pool", 4)


def test_saved_candidate_cannot_extend_beyond_the_data_denominator(monkeypatch: pytest.MonkeyPatch) -> None:
    row = _candidate(110, 20)
    sections = [{"image": "crimsonland.exe", "name": ".data", "address": 100, "size": 20}]
    monkeypatch.setattr(data_report, "section_inventory", lambda: sections)
    monkeypatch.setattr(data_report, "_load_plan", lambda: ("msvc6.5", [{"rows": [row]}]))
    with pytest.raises(ValueError, match="outside the data denominator"):
        data_report.validate_evidence({
            "sections": sections,
            "candidates": [{**row, "storage": "coff-common", "object_sha256": "a" * 64}],
        })
    with pytest.raises(ValueError, match="outside the data denominator"):
        data_report.report_spans({"sections": sections, "candidates": [row]})
