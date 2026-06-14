from __future__ import annotations

import struct
from pathlib import Path

import pytest

from crimson.match import (
    DEFAULT_FUNCTIONS_PATH,
    FunctionManifest,
    LoadedImage,
    ObjectFunction,
    ScratchConfig,
    ScratchStatus,
    common_prefix_length,
    diff_regions,
    disassemble_normalized_function,
    extract_object_function,
    load_function_manifest,
    match_function,
    normalize_function,
    parse_coff_object,
    render_status_rows,
    resolve_function,
    validate_scratch_source,
)


def build_object(code: bytes, symbols: list[tuple[str, int]], relocations: list[int]) -> bytes:
    section_count = 1
    symbol_records = b""
    for name, value in symbols:
        symbol_records += struct.pack("<8sIhHBB", name.encode(), value, 1, 0x20, 2, 0)

    header_size = 20
    section_header_size = 40
    code_offset = header_size + section_header_size
    reloc_offset = code_offset + len(code)
    symtab_offset = reloc_offset + len(relocations) * 10

    header = struct.pack("<HHIIIHH", 0x14C, section_count, 0, symtab_offset, len(symbols), 0, 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        0,
        0,
        len(code),
        code_offset,
        reloc_offset if relocations else 0,
        0,
        len(relocations),
        0,
        0x60000020,
    )
    reloc_records = b"".join(struct.pack("<IIH", address, 0, 6) for address in relocations)
    string_table = struct.pack("<I", 4)
    return header + section + code + reloc_records + symbol_records + string_table


def test_load_manifest_resolves_known_function() -> None:
    manifest = load_function_manifest(DEFAULT_FUNCTIONS_PATH)
    function, start, end = resolve_function(manifest, "player_update")
    assert function.address == 0x004136B0
    assert start == 0x004136B0
    assert end > start


def test_resolve_function_accepts_address() -> None:
    manifest = FunctionManifest(
        image_name="test.exe",
        image_base=0x400000,
        functions=(next(function for function in load_function_manifest(DEFAULT_FUNCTIONS_PATH).functions if function.name == "player_update"),),
    )
    function, _, _ = resolve_function(manifest, "0x004136b0")
    assert function.name == "player_update"


def test_parse_and_extract_object_function() -> None:
    code = bytes.fromhex("8b442404c3") + bytes.fromhex("31c0c3")
    obj = parse_coff_object(build_object(code, [("_foo", 0), ("_bar", 5)], []))
    assert extract_object_function(obj, "foo").data == bytes.fromhex("8b442404c3")
    assert extract_object_function(obj, "bar").data == bytes.fromhex("31c0c3")


def test_extract_object_function_collects_relocations() -> None:
    code = bytes.fromhex("a100000000c3")
    obj = parse_coff_object(build_object(code, [("_foo", 0)], [1]))
    function = extract_object_function(obj, "foo")
    assert function.relocation_offsets == frozenset({1})


def test_normalize_masks_relocated_and_absolute_operands() -> None:
    code = bytes.fromhex("a134124a00c3")
    assert normalize_function(code, relocation_offsets=frozenset({1}))[0] == "mov eax, dword [ADDR]"
    assert normalize_function(code, address_range=(0x400000, 0x500000))[0] == "mov eax, dword [ADDR]"
    assert normalize_function(code)[0] == "mov eax, dword [0x4a1234]"


def test_normalize_labels_intra_function_branches() -> None:
    code = bytes.fromhex("7402") + bytes.fromhex("31c0") + bytes.fromhex("c3")
    assert normalize_function(code)[0] == "je L4"
    assert normalize_function(code, base_address=0x445F00)[0] == "je L4"


def test_normalize_masks_relocated_call_targets() -> None:
    code = bytes.fromhex("e800000000") + bytes.fromhex("c3")
    relocated = normalize_function(code, relocation_offsets=frozenset({1}))
    assert relocated[0] == "call ADDR"
    relocated_dump = disassemble_normalized_function(code, relocation_offsets=frozenset({1}))
    assert relocated_dump[0].offset == 0
    assert relocated_dump[0].text == "call ADDR"
    assert normalize_function(code)[0] == "call L5"


def test_normalize_strips_untargeted_terminal_padding() -> None:
    code = bytes.fromhex("c3") + bytes.fromhex("8d4900") + (b"\x00" * 4) + (b"\x90" * 4)
    assert normalize_function(code) == ("ret",)


def test_common_prefix_length() -> None:
    assert common_prefix_length(("push ebp", "mov ebp, esp"), ("push ebp", "ret")) == 1
    assert common_prefix_length(("push ebp",), ("push ebp", "ret")) == 1
    assert common_prefix_length((), ("ret",)) == 0


def test_match_function_reports_prefix_and_first_mismatch() -> None:
    target = bytes.fromhex("558bec31c0c3")
    candidate = ObjectFunction(name="_foo", data=bytes.fromhex("558becb801000000c3"), relocation_offsets=frozenset())
    result = match_function(
        target,
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0),
        target_va=0x401000,
    )
    assert result.prefix_instructions == 2
    assert result.first_target_mismatch == "xor eax, eax"
    assert result.first_candidate_mismatch == "mov eax, 0x1"


def test_diff_regions_reports_localized_mismatch() -> None:
    target = bytes.fromhex("558bec31c040c3")
    candidate = ObjectFunction(name="_foo", data=bytes.fromhex("558becb80100000040c3"), relocation_offsets=frozenset())
    result = match_function(
        target,
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0),
        target_va=0x401000,
    )
    regions = diff_regions(result, context=1)
    assert len(regions) == 1
    assert regions[0].target_span == "1:4"
    assert regions[0].candidate_span == "1:4"


def test_validate_scratch_source_rejects_inline_asm(tmp_path: Path) -> None:
    clean = tmp_path / "clean.cpp"
    clean.write_text("void f() { int x = 1; }\n")
    validate_scratch_source(clean)

    for token in ("__asm { mov eax, 1 }", "_asm mov eax, 1", "__declspec(naked)"):
        dirty = tmp_path / "dirty.cpp"
        dirty.write_text(f"void f() {{ {token} }}\n")
        with pytest.raises(ValueError, match="fakematching"):
            validate_scratch_source(dirty)


def test_render_status_rows_includes_prefix() -> None:
    config = ScratchConfig(
        directory=Path("scratch"),
        function="foo",
        image="crimsonland.exe",
        compiler="msvc7.0",
        cflags="/O2 /G6 /W3 /GR-",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
    )
    status = ScratchStatus(
        config=config,
        address=0x401000,
        target_size=10,
        ratio=0.5,
        prefix_instructions=2,
        target_instructions=4,
        candidate_instructions=5,
        error=None,
    )
    assert render_status_rows([status])[0][7] == "2/4"
