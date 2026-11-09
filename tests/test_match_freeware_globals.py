from __future__ import annotations

import struct
from pathlib import Path

import pytest

from crimson_re import match
from crimson_re import match_freeware_globals as globals_


def test_linker_folded_literals_can_reproduce_multiple_native_copies(monkeypatch):
    raw_name = "__real@4@3fff8000000000000000"
    value = struct.pack("<f", 1.0)
    image = match.LoadedImage(value * 2, 0x1000, 8)
    section = match.CoffSection(".rdata", value, match.IMAGE_SCN_LNK_COMDAT | 0x40,
                                (), index=1, logical_size=4, comdat_key=raw_name)
    symbol = match.CoffSymbol(0, raw_name, 0, 1, 0, match.IMAGE_SYM_CLASS_EXTERNAL)
    obj = match.CoffObject((section,), (symbol,))
    function = {"native_kind": "function", "matched": True, "ownership": "game", "candidate": "source",
                "source": "game.cpp", "address": 0x1100, "image": "game",
                "proof": {"candidate_object_sha256": "a" * 64, "body_byte_exact": True}}
    placements = [{"image": "game", "address": address, "names": [], "owner": "unknown",
                   "references": [{"function": 0x1100, "symbol": raw_name, "site": 0x1101 + i * 7, "name": None}]}
                  for i, address in enumerate((0x1000, 0x1004))]
    paths = {"game": Path("game.exe")}
    monkeypatch.setattr(match, "load_image", lambda _: image)
    monkeypatch.setattr(globals_, "_pe_relocations", lambda _: None)
    config = match.ScratchConfig(Path("."), "test", "game", "msvc6.5", "", "game.cpp", None, None, "")
    contexts = [(function, config, obj, {})]
    rows = globals_._emitted("1.4.0", placements, contexts, paths)
    assert [(r["address"], r["size"], r["owner"]) for r in rows] == [(0x1000, 4, "unknown"), (0x1004, 4, "unknown")]
    assert globals_._unsupported_storage("1.4.0", [function], placements, rows) == {}
    assert globals_._unsupported_storage("1.4.0", [function], placements, rows[:1]) == {("game", 0x1004): [raw_name]}
    globals_._validate_emitted("1.4.0", [function], placements, rows, paths)
    with pytest.raises(ValueError, match="source, object or reference differs"):
        globals_._validate_emitted("1.4.0", [function], placements, [{**rows[0], "reference_site": 0x1108}], paths)
    with pytest.raises(ValueError, match="unique byte-exact source placement"):
        globals_._validate_emitted("1.4.0", [function], placements, rows + rows, paths)
