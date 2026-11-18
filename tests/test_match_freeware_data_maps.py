from __future__ import annotations

import struct
from copy import deepcopy
from pathlib import Path

import pytest

from crimson_re import match, match_builds
from crimson_re import match_freeware_data_maps as maps


@pytest.mark.parametrize("mutation", ["valid", "missing", "operand", "addend", "symbol", "owner", "source"])
def test_positioned_global_requires_each_original_operand(
    mutation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first indexed load uses storage - 8, the second uses storage + 12.
    # The following call's REL32 resolves to code and carries no data credit.
    address, storage, callee = 0x4000, 0x4100, 0x4020

    def instructions(first: int, second: int, displacement: int) -> bytes:
        return (b"\x8b\x04\x8d" + struct.pack("<i", first) + b"\x8b\x0d" + struct.pack("<i", second)
                + b"\xe8" + struct.pack("<i", displacement) + b"\xc3")

    code = instructions(storage - 8, storage + 12, callee - (address + 18))
    native = object.__new__(maps._Image)
    native.target = match.LoadedImage(code + bytes(0x200 - len(code)), address, 0x200)
    native.ranges = [(0x4080, 0x4200)]
    native.imports = set()
    row = {"image": "grim.dll", "address": address, "end": address + len(code), "size": len(code),
           "name": "caller", "source": "caller.cpp", "ownership": "game", "native_kind": "function",
           "matched": True, "candidate": "source", "proof": {"body_byte_exact": True, "candidate_object_sha256": "a" * 64}}
    config = match.ScratchConfig(tmp_path, "caller", "grim.dll", "msvc6.5", "", "caller.cpp", None, "_caller", "")
    obj = match.CoffObject(
        (match.CoffSection(".text", instructions(-8, 12, 0), match.IMAGE_SCN_CNT_CODE, (
            match.CoffRelocation(3, 1, match.IMAGE_REL_I386_DIR32), match.CoffRelocation(9, 1, match.IMAGE_REL_I386_DIR32),
            match.CoffRelocation(14, 2, match.IMAGE_REL_I386_REL32),
        )),),
        (match.CoffSymbol(0, "_caller", 0, 1, match.SYM_TYPE_FUNCTION, match.IMAGE_SYM_CLASS_EXTERNAL),
         match.CoffSymbol(1, "_storage", 0, 0, 0, match.IMAGE_SYM_CLASS_EXTERNAL),
         match.CoffSymbol(2, "_callee", 0, 0, match.SYM_TYPE_FUNCTION, match.IMAGE_SYM_CLASS_EXTERNAL)),
    )
    bindings, refs = maps._bindings(native, row, config, obj)
    assert bindings == {1: storage, 2: callee}
    assert refs == [(storage, {"function": address, "site": address + 3, "symbol": "_storage", "name": "storage",
                               "addend": -8, "candidate_object_sha256": "a" * 64, "additional_operands": [[address + 9, 12]]})]
    image = match_builds.load_registry().image("1.4.0", "grim.dll")
    monkeypatch.setattr(maps, "_Image", lambda _: native)
    monkeypatch.setattr(maps, "_aliases_for_row", lambda *_: {})
    placements = {storage: [refs[0][1]]}
    catalog = maps._placements(image, placements)
    assert catalog[0]["names"] == ["storage"]
    duplicate = deepcopy(placements)
    duplicate[storage + 32] = [refs[0][1]]
    assert all(not r["names"] for r in maps._placements(image, duplicate))
    if mutation == "missing":
        del catalog[0]["references"][0]["additional_operands"]
    elif mutation == "operand":
        catalog[0]["references"][0]["site"] += 1
    elif mutation == "addend":
        catalog[0]["references"][0]["addend"] = 8
    elif mutation == "symbol":
        catalog[0]["references"][0]["symbol"] = "__imp__storage"
    elif mutation == "source":
        catalog[0]["references"][0]["candidate_object_sha256"] = "b" * 64
    elif mutation == "owner":
        catalog[0]["owner"] = "game"
    if mutation == "valid":
        maps.validate("1.4.0", [row], catalog)
    else:
        with pytest.raises(ValueError):
            maps.validate("1.4.0", [row], catalog)
