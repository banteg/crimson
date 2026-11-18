"""The original CRT relocations define startup table bounds independently of null runs."""

from __future__ import annotations

import json
from pathlib import Path

import pefile
import pytest

from crimson_re import library_match, match_builds, match_freeware_startup_data
from crimson_re import match as ml

ROOT = Path(__file__).resolve().parents[1]


def test_startup_witness_matches_vc6_coff_code_and_named_sentinels() -> None:
    cfg = ml.load_scratch_config(ml.DEFAULT_MATCH_ROOT / "scratches/crt_run_initializers")
    archive = ml._scratch_archive_path(cfg)
    if not archive.is_file():
        pytest.skip("VC6 static CRT archive unavailable")
    obj = ml.parse_coff_object(ml._archive_scratch_object_bytes(cfg))
    symbols = {s.name: s for s in obj.symbols}
    cinit = obj.sections[symbols["__cinit"].section_number - 1]
    assert match_freeware_startup_data.CINIT.fullmatch(cinit.data)
    reloc_names = {s.raw_index: s.name for s in obj.symbols}
    assert [(r.virtual_address, reloc_names[r.symbol_index], r.relocation_type) for r in cinit.relocations] == [
        (1, "__FPinit", 6), (12, "___xi_z", 6), (17, "___xi_a", 6), (22, "__initterm", 20),
        (27, "___xc_z", 6), (32, "___xc_a", 6), (37, "__initterm", 20),
    ]
    walker = obj.sections[symbols["__initterm"].section_number - 1]
    assert walker.data == match_freeware_startup_data.INITTERM and not walker.relocations
    sentinels = next(m for m in library_match.parse_coff_archive(archive.read_bytes()) if m.name.endswith(r"\crt0init.obj"))
    obj = ml.parse_coff_object(sentinels.data)
    for name, section in (("___xc_a", ".CRT$XCA"), ("___xc_z", ".CRT$XCZ")):
        symbol = next(s for s in obj.symbols if s.name == name)
        extent = obj.sections[symbol.section_number - 1]
        assert (symbol.value, extent.name, extent.data, list(extent.relocations)) == (0, section, bytes(4), [])


@pytest.mark.parametrize(("version", "exe_slots"), [("1.0.2", 18), ("1.3.0", 26), ("1.4.0", 33)])
def test_startup_registrations_name_only_verified_function_addresses(version: str, exe_slots: int) -> None:
    images = {name: image.path for name, image in match_builds.load_registry().builds[version].items()}
    if not all(path.is_file() for path in images.values()):
        pytest.skip("pinned freeware images unavailable")
    functions = json.loads((ROOT / f"analysis/decomp/{version}.json").read_text())["functions"]
    receipts = match_freeware_startup_data.attributions(images, functions)
    for image, count in (("crimson.exe", exe_slots), ("grim.dll", 6)):
        begin, slots, end = [r for r in receipts if r["image"] == image]
        assert begin["address"] + 4 == slots["address"] == end["address"] - 4 * count
        assert (begin["owner"], slots["owner"], end["owner"]) == ("libraries", "unknown", "libraries")
        targets = {r["address"]: r["name"] for r in functions if r["image"] == image and r.get("ownership") == "game"
                   and r.get("matched") and r.get("proof", {}).get("body_byte_exact")}
        assert [targets[s["target"]] for s in slots["slots"]] == [s["name"] for s in slots["slots"]]
        with pefile.PE(str(images[image]), fast_load=True) as pe, pytest.raises(ValueError, match="unknown native function"):
            match_freeware_startup_data._rows(pe, image, {})
