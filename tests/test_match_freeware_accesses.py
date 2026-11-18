from __future__ import annotations

from pathlib import Path

import pytest

from crimson_re import match, match_freeware_accesses


@pytest.mark.parametrize(("insn", "operand", "width"), [
    ("a1 00200000", 1, 4),             # mov eax, [0x2000]
    ("d9 05 00200000", 2, 4),          # fld dword ptr [0x2000]
    ("ff 15 00200000", 2, 4),          # call dword ptr [0x2000]
    ("0f b6 05 00200000", 3, 1),       # movzx eax, byte ptr [0x2000]
    ("8d 05 00200000", 2, 0),          # lea eax, [0x2000]
    ("8b 04 85 00200000", 3, 0),       # mov eax, [eax*4 + 0x2000]
    ("64 a1 00200000", 2, 0),          # mov eax, fs:[0x2000]
    ("b8 00200000", 1, 0),             # mov eax, offset 0x2000
])
def test_direct_storage_access_is_only_a_lower_bound(
    insn: str, operand: int, width: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = 0x1000
    raw = bytes.fromhex(insn + " c3")
    monkeypatch.setattr(match, "load_image", lambda _: match.LoadedImage(raw, base, len(raw)))
    fn = {"image": "sample", "address": base, "end": base + len(raw), "native_kind": "function", "ownership": "game",
          "candidate": "source", "matched": True, "proof": {"body_byte_exact": True}}
    site = base + operand
    place = {"image": "sample", "address": 0x2000, "owner": "game", "names": ["state"],
             "references": [{"name": "state", "function": base, "site": site, "addend": 0}]}
    section = {"image": "sample", "address": 0x2000, "size": 16}
    def access(places, bounded, section_size=16):
        return match_freeware_accesses.fixed_accesses(
            places, [fn], bounded, {"sample": Path("sample")}, [{**section, "size": section_size}],
        )
    found = access([place], [])
    assert [row["size"] for row in found] == ([width] if width else [])
    assert access([{**place, "references": [{**place["references"][0], "addend": 1}]}], []) == []
    assert access([place], [{"image": "sample", "address": 0x1fff, "size": 16}]) == []
    if width > 1:
        assert access([place, {**place, "references": [], "address": 0x2001}], []) == []
        assert access([place], [], 1) == []
