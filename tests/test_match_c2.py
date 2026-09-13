from __future__ import annotations

import copy
import json
import struct

import pytest

from crimson import match_c2 as c2

PROFILE = {"hooks": [{"site": 0x100, "target": 0x200, "return": True}]}


def trace_bytes(*, kind=1, temp=0x1234, count=1):
    node = [0] * c2.NODE_WORDS
    node[:4] = [0x5000, 0x163, 42, 0x100]
    node[4] = count
    node[5:12] = [0, 0, kind, 0, 0, 0, temp]
    node[12:28] = [0, 1, 0, 3, 0x100AC880, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1]
    return struct.pack("<6I", 0x43325431, 1, 0x10000000, 0, 0x2000, 1) + struct.pack(f"<{c2.NODE_WORDS}I", *node)


def test_decode_retains_operands_and_descriptor():
    events = c2.decode_trace(trace_bytes(), PROFILE)
    selected = c2.summarize(events, 42)[0]
    assert selected["temporaries"][0]["descriptor"]["register_descriptor_rva"] == 0xAC880
    assert selected["temporaries"][0]["occurrences"][0]["line"] == 42
    assert not c2.summarize(events, 99)[0]["selected_nodes"]


@pytest.mark.parametrize("data", [b"", trace_bytes()[:13], trace_bytes()[:-1], trace_bytes(count=17)])
def test_reject_corrupt_trace(data):
    with pytest.raises(ValueError):
        c2.decode_trace(data, PROFILE)


def test_recycled_function_address_starts_new_ordinal():
    data = trace_bytes()
    events = c2.decode_trace(data + data[12:], PROFILE)
    assert [event["function_ordinal"] for event in events] == [0, 1]


def test_compare_renames_arena_addresses_but_detects_value_and_cost_changes():
    left = c2.decode_trace(trace_bytes(), PROFILE)
    right = c2.decode_trace(trace_bytes(temp=0x9876), PROFILE)
    assert not c2.compare(left, right)["differences"]
    left[0]["phase"] = right[0]["phase"] = 21
    right[0]["nodes"][0]["src"][0]["temp_words"][15] = 2
    assert c2.compare(left, right)["first_shape_difference"]["phase"] == 21
    a = c2.decode_trace(trace_bytes(kind=7, temp=0), PROFILE)
    b = c2.decode_trace(trace_bytes(kind=7, temp=1), PROFILE)
    assert c2.compare(a, b)["differences"]


def test_compare_preserves_temporary_relationships():
    left = c2.decode_trace(trace_bytes(), PROFILE)
    left[0]["nodes"].append(copy.deepcopy(left[0]["nodes"][0]))
    right = copy.deepcopy(left)
    right[0]["nodes"][1]["src"][0]["raw"][6] += 4
    assert c2.compare(left, right)["differences"]


def test_compare_rebases_register_descriptors():
    left = c2.decode_trace(trace_bytes(), PROFILE)
    right = copy.deepcopy(left)
    right[0]["c2_base"] += 0x10000
    right[0]["nodes"][0]["src"][0]["temp_words"][4] += 0x10000
    assert not c2.compare(left, right)["differences"]


def test_compare_missing_event():
    left = c2.decode_trace(trace_bytes(), PROFILE)
    assert c2.compare(left, [])["first_shape_difference"]["right_event"] is None


def test_verified_reader_rejects_modified_snapshot(tmp_path):
    data = b"[]\n"
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "whole_coff_equal_except_timestamp": True,
                "snapshots_sha256": c2.replay.sha(data),
            },
        ),
    )
    (tmp_path / "snapshots.json").write_bytes(data + b" ")
    with pytest.raises(ValueError, match="digest"):
        c2.read_verified(tmp_path)


def test_observer_guards_before_restoring_flags():
    profile = {"invoke_rva": 0x57444, "hooks": [{"site": 0x100, "target": 0x200, "return": True}]}
    source = c2.observer_source(profile)
    assert "mov dword ptr [active+0],1\n popad\n popfd" in source
    assert "site[0] != 0xe8" in source
    assert "recursive_call:" in source
