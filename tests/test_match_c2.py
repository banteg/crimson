from __future__ import annotations

import copy
import dataclasses
import json
import shutil
import struct

import pytest

from crimson_re import match
from crimson_re import match_c2 as c2

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


@pytest.mark.parametrize("data", [trace_bytes()[:-1], trace_bytes(count=17)])
def test_reject_corrupt_trace(data):
    with pytest.raises(ValueError):
        c2.decode_trace(data, PROFILE)


def test_recycled_function_address_starts_new_ordinal():
    data = trace_bytes()
    events = c2.decode_trace(data + data[12:], PROFILE)
    assert [event["function_ordinal"] for event in events] == [0, 1]


def test_large_function_snapshot_and_node_limit():
    count = 4097
    single = trace_bytes()
    header = struct.pack("<6I", 0x43325431, 1, 0x10000000, 0, 0x2000, count)
    events = c2.decode_trace(header + single[24:] * count, PROFILE)
    assert len(events[0]["nodes"]) == count
    oversized = struct.pack("<6I", 0x43325431, 1, 0x10000000, 0, 0x2000, c2.MAX_NODES + 1)
    with pytest.raises(ValueError, match="node limit"):
        c2.decode_trace(oversized, PROFILE)


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


def coff_object(path, *, debug: bytes | None, text: bytes, timestamp: int = 0):
    """A two-section i386 object: an optional `.debug$S` (as msvc6.5pp writes first), then `.text`."""
    sections = ([(b".debug$S", debug, 0x42100040)] if debug is not None else []) + [(b".text", text, 0x60500020)]
    offset = 20 + 40 * len(sections)
    headers, raw, symbols = b"", b"", b""
    for number, (name, body, flags) in enumerate(sections, 1):
        headers += struct.pack("<8sIIIIIIHHI", name, 0, 0, len(body), offset, 0, 0, 0, 0, flags)
        raw += body
        offset += len(body)
        symbols += struct.pack("<8sIhHBB", name, 0, number, 0, 3, 1)
        symbols += struct.pack("<IHHIHB3x", len(body), 0, 0, sum(body), 0, 0)
    header = struct.pack("<HHIIIHH", 0x14C, len(sections), timestamp, offset, 2 * len(sections), 0, 0)
    path.write_bytes(header + headers + raw + symbols + struct.pack("<I", 4))
    return path


def test_normalized_coff_drops_only_the_object_path_record(tmp_path):
    scratch = coff_object(tmp_path / "a.obj", debug=b"\x04\x00\x00\x00 Z:\\b\\a.obj", text=b"\x90\xc3", timestamp=1)
    replayed = coff_object(tmp_path / "b.obj", debug=b"\x04\x00\x00\x00 Z:\\observed\\replay.obj", text=b"\x90\xc3")
    changed = coff_object(tmp_path / "c.obj", debug=b"\x04\x00\x00\x00 Z:\\b\\a.obj", text=b"\x91\xc3")
    assert c2.replay.normalized_coff(scratch) == c2.replay.normalized_coff(replayed)
    assert c2.replay.normalized_coff(scratch) != c2.replay.normalized_coff(changed)
    normalized = match.parse_coff_object(c2.replay.normalized_coff(replayed))
    assert [section.data for section in normalized.sections] == [b"", b"\x90\xc3"]


def test_normalized_coff_without_debug_section_ignores_only_the_timestamp(tmp_path):
    first = coff_object(tmp_path / "a.obj", debug=None, text=b"\x90\xc3", timestamp=1)
    data = bytearray(first.read_bytes())
    data[4:8] = bytes(4)
    assert c2.replay.normalized_coff(first) == bytes(data)


def test_copy_scratch_brings_a_recovered_source_beside_the_conf(tmp_path):
    scratch, recovered = tmp_path / "scratch", tmp_path / "decomp" / "unit"
    scratch.mkdir()
    recovered.mkdir(parents=True)
    (scratch / "scratch.conf").write_text("FUNCTION=f\n")
    (recovered / "f.cpp").write_text("int f() { return 1; }\n")
    (scratch / "local.cpp").write_text("int g() { return 2; }\n")
    config = match.ScratchConfig(
        directory=scratch,
        function="f",
        image="crimsonland.exe",
        compiler="msvc6.5pp",
        cflags="/O2",
        source="../decomp/unit/f.cpp",
        end_va=None,
        symbol=None,
        note="",
    )
    ignore = shutil.ignore_patterns("build")
    copied = c2.copy_scratch(config, tmp_path / "out", ignore)
    assert (copied.directory / copied.source).read_text() == "int f() { return 1; }\n"
    assert copied.directory == tmp_path / "out"
    local = c2.copy_scratch(dataclasses.replace(config, source="local.cpp"), tmp_path / "out2", ignore)
    assert local.source == "local.cpp"
