from __future__ import annotations

import struct

import pytest

from crimson_re import match as matchlib
from crimson_re import match_gap_references


def _row(start: int, end: int, kind: str) -> dict:
    return {"address": start, "end": end, "ownership": "game", "native_kind": kind}


def test_gap_references_include_interior_targets_and_packed_data_pointers() -> None:
    # jnz 0x1006, ret, followed by five NOPs. An unaligned data pointer addresses the second NOP.
    data = bytes.fromhex("7504 c3 9090909090 00") + struct.pack("<I", 0x1004)
    image = matchlib.LoadedImage(data, 0x1000, len(data))
    rows = [_row(0x1000, 0x1003, "function"), _row(0x1003, 0x1008, "unresolved")]
    result = match_gap_references.inspect(image, rows, [], entry_points=[0x1007])
    assert result.unsafe == {0x1006, 0x1007}
    assert result.pointer_sites == {0x1004: {0x1009}}
    assert result.incidental_sites == {}


@pytest.mark.parametrize("code", ["90", "e8 00000000", "0f"])
def test_gap_references_require_a_valid_nonfallthrough_predecessor(code: str) -> None:
    prefix = bytes.fromhex(code)
    image = matchlib.LoadedImage(prefix + b"\x90", 0x401000, len(prefix) + 1)
    gap = image.image_base + len(prefix)
    rows = [_row(image.image_base, gap, "function"), _row(gap, gap + 1, "unresolved")]
    assert match_gap_references.inspect(image, rows, []).unsafe == {gap}


def test_gap_references_retain_overlapping_discovery_and_interior_entry_flow() -> None:
    # The independently discovered branch at 0x1001 starts inside the mov immediate.
    image = matchlib.LoadedImage(bytes.fromhex("b8 eb050000 c3 909090"), 0x1000, 9)
    rows = [_row(0x1000, 0x1006, "function"), _row(0x1006, 0x1009, "unresolved")]
    discovered = [
        {"address": 0x1001, "blocks": [{"address": 0x1001, "end": 0x1003}]},
        {"address": 0x1007, "blocks": [{"address": 0x1007, "end": 0x1008}]},
    ]
    assert match_gap_references.inspect(image, rows, discovered).unsafe == {0x1007, 0x1008}


def test_far_call_recognizes_offset_after_segment_selector() -> None:
    image = matchlib.LoadedImage(bytes.fromhex("9a 08100000 0800 c3 90"), 0x1000, 9)
    rows = [_row(0x1000, 0x1008, "function"), _row(0x1008, 0x1009, "unresolved")]
    assert match_gap_references.inspect(image, rows, []).unsafe == {0x1008}


def test_apparent_float_pointer_requires_the_evidence_at_both_access_sites() -> None:
    data = bytearray(0x2D414)
    data[0x1998:0x199a] = bytes.fromhex("c3 90")
    data[0x1EF05:0x1EF0B] = bytes.fromhex("d80d 0cd44200")
    data[0x1EEA4:0x1EEAA] = bytes.fromhex("d805 10d44200")
    data[0x2D40C:0x2D414] = bytes.fromhex("9a991940 00409244")
    rows = [_row(0x401998, 0x401999, "function"), _row(0x401999, 0x40199A, "unresolved")]
    result = match_gap_references.inspect(matchlib.LoadedImage(bytes(data), 0x400000, len(data)), rows, [])
    assert result.pointer_sites == {}
    assert 0x42D40D in result.incidental_sites

    relocated = matchlib.LoadedImage(bytes(data), 0x400000, len(data), content_exclusions=((0x42D40D, 0x42D411),))
    assert match_gap_references.inspect(relocated, rows, []).pointer_sites == {0x401999: {0x42D40D}}

    data[0x1EF05] = 0x90
    changed = match_gap_references.inspect(matchlib.LoadedImage(bytes(data), 0x400000, len(data)), rows, [])
    assert changed.pointer_sites == {0x401999: {0x42D40D}}
    assert changed.incidental_sites == {}
