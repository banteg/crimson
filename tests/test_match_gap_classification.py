from __future__ import annotations

import struct

import pytest

from crimson_re import match as matchlib
from crimson_re import match_gap_classification


@pytest.mark.parametrize("change", ["", "guard", "index", "destination", "padding", "reference", "entry"])
def test_dense_switch_requires_a_bound_and_exclusive_table_use(change: str) -> None:
    # cmp eax, 1 / ja default / jmp [eax*4 + 0x1010] / ret / default: ret
    base, table = 0x1000, 0x1010
    body = bytearray.fromhex("83 f8 01 77 08 ff 24 85 10 10 00 00 c3 c3")
    pad = bytes.fromhex("8b ff")
    if change == "guard":
        body[3] = 0x74  # JE
    if change == "index":
        body[7] = 0x8d  # [ecx*4 + table]
    if change == "padding":
        pad = b"\x50\x58"
    first = base + (11 if change == "destination" else 12)
    data = bytes(body) + pad + struct.pack("<2I", first, base + 13) + b"\x90" * 8 + b"\xc3"
    if change == "reference":
        data += struct.pack("<I", table + 1)
    image = matchlib.LoadedImage(data, base, len(data))
    rows = [
        {"address": base, "end": base + len(body), "native_kind": "function", "ownership": "game"},
        {"address": base + len(body), "end": base + 32, "size": 18, "native_kind": "unresolved", "ownership": "game"},
        {"address": base + 32, "end": base + 33, "native_kind": "function", "ownership": "game"},
    ]
    result = match_gap_classification.classify(image, rows, [], entry_points={table + 2} if change == "entry" else set())
    if change:
        assert result == rows
    else:
        assert [(row["native_kind"], row["address"], row["end"]) for row in result[1:-1]] == [
            ("padding", 0x100e, 0x1010), ("embedded_data", 0x1010, 0x1018), ("padding", 0x1018, 0x1020),
        ]
        assert result[2]["gap_evidence"] == {
            "type": "switch_destinations", "entries": 2, "entry_size": 4,
            "function": 0x1000, "guard": 0x1003, "reference": 0x1005,
        }
