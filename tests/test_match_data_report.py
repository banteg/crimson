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


def test_internal_data_requires_explicit_static_storage_and_real_section() -> None:
    section = matchlib.CoffSection(".rdata", b"\x01\0\0\0", 0x40000040, (), index=1, logical_size=4)
    static = replace(_symbol(1, 0), storage_class=matchlib.IMAGE_SYM_CLASS_STATIC)
    obj = matchlib.CoffObject((section,), (static,))
    assert data_report._check_storage(obj, "pool", 4, expected=section.data, linkage="internal") == "coff-data"
    with pytest.raises(ValueError, match="exactly one"):
        data_report._check_storage(obj, "pool", 4, expected=section.data)
    external = replace(obj, symbols=(_symbol(1, 0),))
    with pytest.raises(ValueError, match="exactly one"):
        data_report._check_storage(external, "pool", 4, expected=section.data, linkage="internal")
    with pytest.raises(ValueError, match="no storage"):
        data_report._check_storage(replace(obj, symbols=(replace(static, section_number=0, value=4),)),
                                   "pool", 4, linkage="internal")
    with pytest.raises(ValueError, match="exactly one"):
        data_report._check_storage(replace(obj, symbols=(static, static)), "pool", 4, linkage="internal")


@pytest.mark.parametrize("internal,source", [(["missing"], "pool.c"), (["pool", "pool"], "pool.c"),
                                           (["pool"], "pool.cpp"), ([], "pool.h")])
def test_plan_rejects_ambiguous_internal_symbols_and_languages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, internal: list[str], source: str,
) -> None:
    import json

    manifest = tmp_path / "candidates.json"
    manifest.write_text(json.dumps({"schema": 1, "sources": [{
        "image": "grim.dll", "source": "tools/match/data/" + source,
        "symbols": ["pool"], "internal_symbols": internal,
    }]}))
    monkeypatch.setattr(data_report, "MANIFEST", manifest)
    monkeypatch.setattr(matchlib, "TRACKED_IMAGE_NAMES", ())
    monkeypatch.setattr(data_report, "_reference_relocations", dict)
    with pytest.raises(ValueError, match="internal data symbols|unsupported data source language"):
        data_report._load_plan()


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
    row = {**_candidate(110, 20), "initializer_hex": "00" * 20,
           "initializer_sha256": "a" * 64, "relocations": [], "linkage": "external"}
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


def test_initialized_scalar_requires_exact_bytes() -> None:
    import struct

    value = struct.pack("<f", 0.5)
    section = matchlib.CoffSection(".data", value, 0xC0000040, (), index=1, logical_size=4)
    obj = matchlib.CoffObject((section,), (_symbol(1, 0),))
    assert data_report._check_storage(obj, "pool", 4, expected=value) == "coff-data"
    with pytest.raises(ValueError, match="differs from reference"):
        data_report._check_storage(obj, "pool", 4, expected=struct.pack("<f", 1.0))
    with pytest.raises(ValueError, match="common storage"):
        data_report._check_storage(matchlib.CoffObject((), (_symbol(0, 4),)), "pool", 4, expected=value)


def test_symbolic_pointer_requires_correct_target_offset_type_and_addend() -> None:
    import struct

    target = matchlib.CoffSymbol(1, "_target", 0, 0, 0, matchlib.IMAGE_SYM_CLASS_EXTERNAL)
    relocation = matchlib.CoffRelocation(0, 1, matchlib.IMAGE_REL_I386_DIR32)
    section = matchlib.CoffSection(".data", bytes(4), 0xC0000040, (relocation,), index=1, logical_size=4)
    obj = matchlib.CoffObject((section,), (_symbol(1, 0), target))
    expected = struct.pack("<I", 0x471234)
    recipe = [{"offset": 0, "symbol": "_target", "address": 0x471234}]
    assert data_report._check_storage(obj, "pool", 4, expected=expected, relocations=recipe) == "coff-data"
    bad_objects = [
        replace(obj, symbols=(_symbol(1, 0), replace(target, name="_wrong"))),
        replace(obj, sections=(replace(section, relocations=(replace(relocation, virtual_address=1),)),)),
        replace(obj, sections=(replace(section, relocations=(replace(relocation, relocation_type=matchlib.IMAGE_REL_I386_REL32),)),)),
        replace(obj, sections=(replace(section, data=b"\x01\0\0\0"),)),
        # Exact final address bytes without a compiler relocation cannot earn pointer credit.
        replace(obj, sections=(replace(section, data=expected, relocations=()),)),
    ]
    for bad in bad_objects:
        with pytest.raises(ValueError):
            data_report._check_storage(bad, "pool", 4, expected=expected, relocations=recipe)


def test_reference_relocations_require_symbolic_recipes_and_complete_slots() -> None:
    definition = {"name": "pool", "address": 0x1000, "size": 4, "initializer_hex": "78563412"}
    with pytest.raises(ValueError, match="symbolic relocation evidence"):
        data_report._initializer_plan(definition, [(0x1000, 3)])
    with pytest.raises(ValueError, match="unsupported reference relocation"):
        data_report._initializer_plan(definition, [(0x0FFF, 3)])
    definition = {"name": "pool", "address": 0x1000, "size": 4,
                  "initializer_target": {"name": "target", "address": 0x12345678}}
    assert data_report._initializer_plan(definition, [(0x1000, 3)])["relocations"] == [
        {"offset": 0, "address": 0x12345678, "symbol": "_target"}]
    # The EXE has relocations stripped; a recorded symbolic recipe is still checked against COFF.
    assert data_report._initializer_plan(definition, None)["initializer_hex"] == "78563412"
