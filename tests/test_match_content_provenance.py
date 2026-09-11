from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from crimson.match import (
    LoadedImage,
    ObjectFunction,
    ObjectRelocationReference,
    ReferenceCatalog,
    _image_read_only_data,
    load_image,
    match_function,
)
from crimson.match_flow_graph import flow_graph_payload


def literal_candidate(kind: str) -> tuple[bytes, ObjectFunction]:
    literal = b"timer\0" if kind == "string" else bytes.fromhex("0000803f")
    opcode = b"\x68" if kind == "string" else bytes.fromhex("d905")
    symbol = {"string": "??_C@literal", "float": "__real@constant", "data": "_constant"}[kind]
    return literal, ObjectFunction(
        name="_foo", data=opcode + b"\0" * 4 + b"\xc3",
        relocation_offsets=frozenset({len(opcode)}),
        relocation_references=(ObjectRelocationReference(
            offset=len(opcode), symbol_name=symbol, key=None, explained=False,
            symbol_data=literal, read_only_data=True, relocation_type=6,
        ),),
    )


@pytest.mark.parametrize("kind", ["float", "data"])
@pytest.mark.parametrize("read_only", [False, True])
def test_literal_requires_read_only_native_content(kind: str, read_only: bool) -> None:
    literal, candidate = literal_candidate(kind)
    image = LoadedImage(
        b"\0" * 0x2000 + literal, 0x400000, 0x2000 + len(literal),
        read_only_ranges=((0x402000, 0x402000 + len(literal)),) if read_only else (),
    )
    offset = next(iter(candidate.relocation_offsets))
    target = candidate.data[:offset] + struct.pack("<I", 0x402000) + b"\xc3"
    result = match_function(
        target, candidate, image=image, target_va=0x401000,
        reference_catalog=ReferenceCatalog({0x402000: ("runtime_value",)}),
    )
    assert result.ratio == 1.0
    assert result.exact is read_only
    assert result.masked_operand_audit.mismatch_count == int(not read_only)
    assert flow_graph_payload(result)["status"] == ("matched" if read_only else "different")


def test_named_mutable_reference_still_requires_the_same_owner() -> None:
    literal, candidate = literal_candidate("data")
    reference = replace(
        candidate.relocation_references[0], symbol_name="_runtime_value",
        read_only_data=False, symbol_data=b"\xff" * 4,
    )
    image = LoadedImage(b"\0" * 0x2000 + literal, 0x400000, 0x2004)
    target = bytes.fromhex("d90500204000c3")
    for owner, exact in [("runtime_value", True), ("other_value", False)]:
        result = match_function(
            target, replace(candidate, relocation_references=(replace(reference, symbol_name=f"_{owner}"),)),
            image=image, target_va=0x401000,
            reference_catalog=ReferenceCatalog({0x402000: ("runtime_value",), 0x402004: ("other_value",)}),
        )
        assert result.exact is exact


@pytest.mark.parametrize("kind", ["float", "data"])
@pytest.mark.parametrize("boundary", ["section", "loader", "mapped"])
def test_content_evidence_cannot_cross_a_provenance_boundary(kind: str, boundary: str) -> None:
    literal, candidate = literal_candidate(kind)
    end = 0x402000 + len(literal)
    image = LoadedImage(
        b"\0" * 0x2000 + literal, 0x400000, 0x3000,
        read_only_ranges=((0x402000, end),),
    )
    if boundary == "section":
        image = replace(image, read_only_ranges=((0x402000, end - 1),))
    elif boundary == "loader":
        image = replace(image, content_exclusions=((end - 1, end + 3),))
    else:
        image = replace(image, mapped=image.mapped[:-1])
    offset = next(iter(candidate.relocation_offsets))
    target = candidate.data[:offset] + struct.pack("<I", 0x402000) + b"\xc3"
    result = match_function(
        target, candidate, image=image, target_va=0x401000, reference_catalog=ReferenceCatalog({}),
    )
    assert not result.exact
    assert result.masked_operand_audit.mismatch_count == 1


def test_compiler_string_pooling_remains_separate_from_scalar_content() -> None:
    literal, candidate = literal_candidate("string")
    image = LoadedImage(b"\0" * 0x2000 + literal, 0x400000, 0x2000 + len(literal))
    target = bytes.fromhex("6800204000c3")
    result = match_function(
        target, candidate, image=image, target_va=0x401000, reference_catalog=ReferenceCatalog({}),
    )
    assert result.exact
    assert result.target_disassembly[0].masked_references[0].keys[-1] == 'string:"timer"'
    assert not any(key.startswith("bytes") for key in result.target_disassembly[0].masked_references[0].keys)
    relocated = match_function(
        target, candidate, image=replace(image, content_exclusions=((0x402002, 0x402006),)),
        target_va=0x401000, reference_catalog=ReferenceCatalog({}),
    )
    assert not relocated.exact
    load_candidate = replace(candidate, data=bytes.fromhex("a100000000c3"))
    loaded = match_function(
        bytes.fromhex("a100204000c3"), load_candidate, image=image, target_va=0x401000,
        reference_catalog=ReferenceCatalog({}),
    )
    assert loaded.exact
    scalar_reference = replace(load_candidate.relocation_references[0], symbol_name="_ordinary_constant")
    scalar = match_function(
        bytes.fromhex("a100204000c3"),
        replace(load_candidate, relocation_references=(scalar_reference,)), image=image, target_va=0x401000,
        reference_catalog=ReferenceCatalog({}),
    )
    assert not scalar.exact


def minimal_pe(path: Path) -> None:
    """A real PE32 with writable data, read-only data, an IAT, and a base fixup."""
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 3, 0, 0, 0, 0xE0, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x4000, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 5 * 8, 0x2100, 12)
    struct.pack_into("<II", data, optional + 96 + 12 * 8, 0x2060, 4)
    for index, (name, flags) in enumerate(((b".text", 0x60000020), (b".rdata", 0x40000040), (b".data", 0xC0000040))):
        struct.pack_into(
            "<8sIIIIIIHHI", data, 0x178 + index * 40,
            name, 0x200, (index + 1) * 0x1000, 0x200, (index + 1) * 0x200, 0, 0, 0, 0, flags,
        )
    data[0x200] = 0xC3
    data[0x400:0x500] = b"A" * 0x100
    struct.pack_into("<IIHH", data, 0x500, 0x2000, 12, 0x3040, 0)
    path.write_bytes(data)


@pytest.mark.parametrize("image_base", [None, 0x500000])
def test_pe_loader_records_permissions_and_loader_writes(tmp_path: Path, image_base: int | None) -> None:
    path = tmp_path / "content.exe"
    minimal_pe(path)
    image = load_image(path, image_base=image_base)
    base = image_base or 0x400000
    assert image.image_base == base
    assert _image_read_only_data(image, base + 0x2000, 4) == b"AAAA"
    assert _image_read_only_data(image, base + 0x3000, 4) == b""
    assert _image_read_only_data(image, base + 0x2040, 4) == b""
    assert _image_read_only_data(image, base + 0x203E, 4) == b"AA"
    assert _image_read_only_data(image, base + 0x2044, 4) == b"AAAA"
    assert _image_read_only_data(image, base + 0x2060, 4) == b""
    assert _image_read_only_data(image, base + 0x205E, 4) == b"AA"
    assert _image_read_only_data(image, base + 0x2200, 4) == b""
    assert _image_read_only_data(image, base + 0x100, 4) == b""
