from __future__ import annotations

import json
from copy import deepcopy

import pytest

from crimson_re import match, match_builds, match_freeware_vtable


@pytest.mark.parametrize(("version", "address", "count"), [
    ("1.0.2", 0x1003e214, 40), ("1.3.0", 0x10040218, 47), ("1.4.0", 0x1004221c, 52),
])
def test_original_grim_vtable_bounds_and_exact_method_targets(version: str, address: int, count: int) -> None:
    image = match_builds.load_registry().image(version, "grim.dll")
    if not image.path.is_file():
        pytest.skip("pinned freeware DLL unavailable")
    evidence = json.loads((match.REPO_ROOT / "analysis/decomp" / f"{version}.json").read_text())
    functions = {f["address"]: f for f in evidence["functions"] if f["image"] == "grim.dll"}
    methods, relocs = match_freeware_vtable._original(address, image.path, match.load_image(image.path), functions)
    assert len(methods) == count
    assert all(m["proof"]["body_byte_exact"] and m["ownership"] == "game" for m in methods)
    assert all(relocs[site] == 3 for site in range(address, address + 4 * count, 4))
    assert address + 4 * count not in relocs

    # Every slot needs both a PE pointer and its own exact source proof.
    getter = next(f for f in functions.values() if f["name"] == "GRIM__GetInterface")
    placement = {"image": "grim.dll", "address": address, "names": ["grim_interface_vtable"],
                 "references": [{"function": getter["address"], "addend": 0, "symbol": "?grim_interface_vtable@@3PAXA"}]}
    paths = {"grim.dll": image.path}
    if evidence["data"] is not None:
        placements = evidence["data"]["globals"]
        saved = [c for c in evidence["data"]["candidates"] if c["proof_kind"] == "engine-vtable"]
        assert match_freeware_vtable.candidates(version, placements, list(functions.values()), paths, saved=saved) == saved
        tampered = deepcopy(saved)
        tampered[0]["relocations"][0]["symbol"] += "different_signature"
        with pytest.raises(ValueError, match="symbolic COFF receipt"):
            match_freeware_vtable.candidates(version, placements, list(functions.values()), paths, saved=tampered)
    methods[-1]["matched"] = False
    assert match_freeware_vtable.candidates(version, [placement], list(functions.values()), paths) == []
    with pytest.raises(ValueError, match="depends on an unverified method"):
        match_freeware_vtable.candidates(version, [placement], list(functions.values()), paths, saved=[{}])
