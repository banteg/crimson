from __future__ import annotations

import hashlib
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
    (0xfff, bytes(4), {}),
    (0x100e, bytes(4), {}),
    (0x1000, b"\x01\x00", {}),
    (0x1004, bytes(4), {0x1007: 3}),
])
def test_verified_extent_rejects_crossing_mismatched_and_loader_owned_bytes(
    start: int, expected: bytes, fixups: dict[int, int],
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
    originals = {image: ([(0x1000, bytes(16))], {})}
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


def test_symbolic_signature_requires_unique_data_and_native_highlow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "tools/match"
    (root / "data").mkdir(parents=True)
    source = root / "data/freeware_grim.cpp"
    source.write_text('extern "C" { char signature[] = "paq"; }\nchar *magic = signature;\n')
    source.with_suffix(".json").write_text(json.dumps([
        {"name": "magic", "extent_function": "lookup", "size": 4, "points_to": "signature"},
        {"name": "signature", "extent_function": "lookup", "size": 4, "initializer_hex": "70617100",
         "located_through": "magic"},
    ]))
    monkeypatch.setattr(matchlib, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(matchlib, "DEFAULT_MATCH_ROOT", root)
    monkeypatch.setattr(definitions, "PROVIDERS", {"freeware_grim": "grim.dll"})
    sections = [(0x1000, b"paq\0" + (0x1000).to_bytes(4, "little"))]
    relocations = {0x1004: 3}
    monkeypatch.setattr(definitions, "_originals", lambda _: {"grim.dll": (sections, relocations)})
    fn = {"image": "grim.dll", "name": "lookup", "address": 0x2000, "ownership": "game",
          "candidate": "source", "matched": True, "proof": {"body_byte_exact": True}}
    labels = [{"image": "grim.dll", "address": 0x1004, "references": [
        {"symbol": "?magic@@3PADA", "site": 0x2008, "function": 0x2000},
    ]}]
    rows = [
        {"image": "grim.dll", "address": address, "size": 4, "name": name, "owner": "game",
         "source": "tools/match/data/freeware_grim.cpp", "compiler": "msvc6.5", "storage": "coff-data",
         "object_sha256": "a" * 64, "initializer_sha256": hashlib.sha256(contents).hexdigest(),
         "proof_kind": "reviewed-definition", "extent_function": 0x2000, "reference_site": 0x2008, **placement}
        for address, name, contents, placement in [
            (0x1000, "signature", b"paq\0", {"pointer_witness": 0x1004}),
            (0x1004, "magic", (0x1000).to_bytes(4, "little"), {
                "relocations": [{"offset": 0, "symbol": "_signature", "address": 0x1000}],
            }),
        ]
    ]
    assert definitions.candidates("1.0.2", labels, [fn], {}, saved=rows) == rows
    with pytest.raises(ValueError, match="original bytes"):
        definitions.candidates("1.0.2", labels, [fn], {}, saved=[rows[0], {**rows[1], "relocations": []}])
    relocations[0x1004] = 1
    with pytest.raises(ValueError, match="native initializer"):
        definitions.candidates("1.0.2", labels, [fn], {}, saved=rows)
    sections.append((0x1800, b"paq\0"))
    with pytest.raises(ValueError, match="ambiguous"):
        definitions.candidates("1.0.2", labels, [fn], {}, saved=rows)
