from __future__ import annotations

import json
from pathlib import Path

import pytest

from crimson_re import match as matchlib
from crimson_re import match_freeware_definitions as definitions


def test_versioned_extent_and_initializer_plan(tmp_path: Path) -> None:
    manifest = tmp_path / "plan.json"
    manifest.write_text(json.dumps([{
        "name": "setting", "sizes": {"1.0.2": 1, "1.3.0": 2},
        "extent_functions": {"1.0.2": "run_early", "1.3.0": "run_later"},
        "initializers": {"1.0.2": "03", "1.3.0": "0400"},
    }]))
    assert definitions._plan("1.4.0", manifest) == []
    assert definitions._plan("1.3.0", manifest) == [{
        "name": "setting", "size": 2, "extent_function": "run_later", "expected": b"\x04\x00",
    }]
    manifest.write_text(json.dumps([{"name": "bad", "size": 3, "extent_function": "init", "initializer_hex": "00"}]))
    with pytest.raises(ValueError, match="initializer length"):
        definitions._plan("1.0.2", manifest)


@pytest.mark.parametrize(("start", "expected", "fixups"), [
    (0xfff, bytes(4), set()),
    (0x100e, bytes(4), set()),
    (0x1000, b"\x01\x00", set()),
    (0x1004, bytes(4), {0x1007}),
])
def test_verified_extent_rejects_crossing_mismatched_and_loader_owned_bytes(
    start: int, expected: bytes, fixups: set[int],
) -> None:
    with pytest.raises(ValueError, match="native"):
        definitions._verify_original("value", start, expected, [(0x1000, bytes(16))], fixups)


def test_saved_definition_requires_both_source_placement_and_original_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "tools/match"
    (root / "data").mkdir(parents=True)
    source = root / "data/freeware_game_state.cpp"
    source.write_text('extern "C" { int setting; }\n')
    source.with_suffix(".json").write_text(json.dumps([{"name": "setting", "size": 4, "extent_function": "read_setting"}]))
    monkeypatch.setattr(matchlib, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(matchlib, "DEFAULT_MATCH_ROOT", root)
    image = "crimson.exe"
    monkeypatch.setattr(definitions, "PROVIDERS", {"freeware_game_state": image})
    originals = {image: ([(0x1000, bytes(16))], set())}
    monkeypatch.setattr(definitions, "_originals", lambda paths: originals)
    obj = matchlib.CoffObject((), (matchlib.CoffSymbol(0, "_setting", 4, 0, 0, 2, ()),))
    monkeypatch.setattr(definitions, "_compile", lambda *args: (obj, "a" * 64))
    functions = [{"image": image, "name": "read_setting", "address": 0x2000, "ownership": "game",
                  "candidate": "source", "matched": True, "proof": {"body_byte_exact": True}}]
    reference = {"symbol": "_setting", "site": 0x2004, "function": 0x2000}
    labels = [{"image": image, "address": 0x1004, "references": [reference]}]
    actual = definitions.candidates("1.0.2", labels, functions, {})
    assert len(actual) == 1 and actual[0]["storage"] == "coff-common"
    assert definitions.candidates("1.0.2", labels, functions, {}, saved=actual) == actual
    with pytest.raises(ValueError, match="missing or inconsistent"):
        definitions.candidates("1.0.2", labels, functions, {}, saved=[])
    with pytest.raises(ValueError, match="original bytes"):
        definitions.candidates("1.0.2", labels, functions, {}, saved=[{**actual[0], "reference_site": 0x2003}])
    with pytest.raises(ValueError, match="missing unique exact"):
        definitions.candidates("1.0.2", labels + [{**labels[0], "address": 0x1008}], functions, {})
    reference["symbol"] = "?setting@?1??unrelated@@YAXXZ@4HA"
    with pytest.raises(ValueError, match="missing unique exact"):
        definitions.candidates("1.0.2", labels, functions, {})
