from __future__ import annotations

import shutil
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from crimson_re import match as matchlib
from crimson_re import match_report, match_toolchain
from crimson_re.match import (
    CoffObject,
    CoffRelocation,
    CoffSection,
    CoffSymbol,
    LoadedImage,
    ReferenceCatalog,
    extract_object_function,
    match_function,
)


def code_object(code: bytes) -> CoffObject:
    return CoffObject(
        (CoffSection(".text", code, 0x20, ()),),
        (CoffSymbol(0, "_probe", 0, 1, 0x20, 2),),
    )


@pytest.mark.parametrize(
    ("target", "candidate"),
    [(b"\xcc", b"\x90"), (b"\x90" * 128 + b"\xeb\xcc", b"\x90" * 128 + b"\xeb\x90")],
)
def test_function_extraction_preserves_executable_terminal_bytes(target: bytes, candidate: bytes) -> None:
    image = LoadedImage(target, 0x401000, len(target))
    target_body = image.function_bytes(0x401000, 0x401000 + len(target))
    candidate_body = extract_object_function(code_object(candidate), "probe")
    assert target_body == target
    assert candidate_body.data == candidate
    result = match_function(target_body, candidate_body, image=image, target_va=0x401000)
    assert not result.exact
    assert result.body_byte_exact is False


def test_extracted_alignment_padding_is_recorded_after_decoding() -> None:
    target = bytes.fromhex("c3cc90")
    candidate = bytes.fromhex("c390cccc")
    image = LoadedImage(target, 0x401000, len(target))
    result = match_function(
        image.function_bytes(0x401000, 0x401000 + len(target)),
        extract_object_function(code_object(candidate), "probe"),
        image=image,
        target_va=0x401000,
    )
    assert result.exact
    assert result.body_byte_exact is True
    assert (result.target_padding_bytes, result.candidate_padding_bytes) == (2, 3)


@pytest.mark.parametrize(
    ("name", "imported", "prefix", "trimmed"),
    [
        ("longjmp", True, b"", True),
        ("returns", True, b"", False),
        ("longjmp", False, b"", False),
        ("longjmp", True, bytes.fromhex("eb06"), False),  # Branch into cleanup.
        ("longjmp", True, bytes.fromhex("eb07"), False),  # Branch into padding.
        ("longjmp", True, bytes.fromhex("ffe0"), False),  # Unknown indirect entry.
    ],
)
def test_padding_after_cleanup_requires_a_verified_nonreturn_import(
    name: str,
    imported: bool,
    prefix: bytes,
    trimmed: bool,
) -> None:
    import_address = 0x402000
    code = prefix + bytes.fromhex("ff15") + b"\0" * 4 + bytes.fromhex("5e909090")
    obj = CoffObject(
        (CoffSection(".text", code, 0x20, (CoffRelocation(len(prefix) + 2, 1, 6),)),),
        (
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, f"__imp__{name}" if imported else f"_{name}", 0, 0, 0, 2),
        ),
    )
    catalog = ReferenceCatalog(
        {import_address: (name,)},
        import_addresses=frozenset({import_address}) if imported else frozenset(),
    )
    candidate = extract_object_function(obj, "probe")
    lines = matchlib.disassemble_normalized_function(
        candidate.data,
        relocation_offsets=candidate.relocation_offsets,
        relocation_references=candidate.relocation_references,
        reference_catalog=catalog,
    )
    assert sum(line.text == "nop" for line in lines) == (0 if trimmed else 3)
    assert any(line.text == "pop esi" for line in lines)
    target = prefix + bytes.fromhex("ff15") + struct.pack("<I", import_address) + b"\x5e"
    result = match_function(
        target,
        candidate,
        image=LoadedImage(b"\0" * 0x3000, 0x400000, 0x3000),
        target_va=0x401000,
        reference_catalog=catalog,
    )
    assert result.exact is trimmed
    assert result.body_byte_exact is trimmed
    assert result.candidate_padding_bytes == (3 if trimmed else 0)


def test_report_inventory_excludes_decoded_padding_without_truncating_operands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = b"\xc3\x90\xcc" + b"\x90" * 128 + bytes.fromhex("ebcc")
    functions = (
        matchlib.FunctionSymbol("padded", 0x401000, 0x401003, 3),
        matchlib.FunctionSymbol("loop", 0x401003, 0x401000 + len(target), 130),
    )
    image = SimpleNamespace(
        name="crimsonland.exe",
        is_canonical=True,
        native_inventory=None,
        target=SimpleNamespace(
            functions_path=Path("functions.json"),
            metadata_path=Path("metadata.json"),
            image_name="crimsonland.exe",
            image_path=Path("image.exe"),
        ),
    )
    monkeypatch.setattr(match_report, "_images", lambda version: [image])
    monkeypatch.setattr(
        matchlib,
        "load_function_manifest",
        lambda *args, **kwargs: SimpleNamespace(
            functions=functions,
            image_base=0x401000,
        ),
    )
    monkeypatch.setattr(matchlib, "load_image", lambda *args: LoadedImage(target, 0x401000, len(target)))
    assert [row["size"] for row in match_report._inventory()] == [1, 130]


@pytest.mark.parametrize("opcode", ["8b048d", "8d05", "d905", "65a1"])
@pytest.mark.parametrize("named", [False, True])
def test_scalar_content_requires_a_direct_read_or_named_owner(opcode: str, named: bool) -> None:
    prefix = bytes.fromhex(opcode)
    suffix = struct.pack("<I", 1) if opcode == "c705" else b""
    obj = CoffObject(
        (
            CoffSection(".text", prefix + b"\0" * 4 + suffix + b"\xc3", 0x20, (CoffRelocation(len(prefix), 1, 6),)),
            CoffSection(".rdata", struct.pack("<II", 1, 3), 0x40000040, ()),
        ),
        (CoffSymbol(0, "_probe", 0, 1, 0x20, 2), CoffSymbol(1, "_table", 0, 2, 0, 3)),
    )
    image = LoadedImage(
        b"\0" * 0x2000 + struct.pack("<II", 1, 2),
        0x400000,
        0x3000,
        read_only_ranges=((0x402000, 0x402008),),
    )
    result = match_function(
        prefix + struct.pack("<I", 0x402000) + suffix + b"\xc3",
        extract_object_function(obj, "probe"),
        image=image,
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({0x402000: ("table",)} if named else {}),
    )
    assert result.ratio == 1.0
    assert result.exact is (named or opcode == "d905")
    assert result.body_byte_exact is result.exact


@pytest.mark.parametrize("write_owner", ["source", "destination"])
@pytest.mark.parametrize("write_offset", [-4, -1, 7, 8])
def test_copy_proof_accounts_for_the_entire_memory_access(write_owner: str, write_offset: int) -> None:
    source, destination = 0x402000, 0x402100
    owners = {"source": source, "destination": destination}
    load_offset = 4 if write_offset == 7 else 0
    setup = bytes.fromhex("b902000000be") + struct.pack("<I", source) + b"\xbf" + struct.pack("<I", destination)
    write = bytes.fromhex("f3a5c705") + struct.pack("<I", owners[write_owner] + write_offset) + b"\0" * 4
    target = setup + write + bytes.fromhex("d905") + struct.pack("<I", destination + load_offset) + b"\xc3"
    candidate = bytearray(setup + write + bytes.fromhex("d905") + struct.pack("<I", source + load_offset) + b"\xc3")
    relocations = []
    for offset, symbol_index, addend in (
        (6, 1, 0),
        (11, 2, 0),
        (19, 1 if write_owner == "source" else 2, write_offset),
        (29, 1, load_offset),
    ):
        candidate[offset : offset + 4] = struct.pack("<i", addend)
        relocations.append(CoffRelocation(offset, symbol_index, 6))
    obj = CoffObject(
        (CoffSection(".text", bytes(candidate), 0x20, tuple(relocations)),),
        (
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "_source", 0, 0, 0, 2),
            CoffSymbol(2, "_destination", 0, 0, 0, 2),
        ),
    )
    result = match_function(
        target,
        extract_object_function(obj, "probe"),
        image=LoadedImage(b"\0" * 0x3000, 0x400000, 0x3000),
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({source: ("source",), destination: ("destination",)}),
    )
    assert result.ratio == 1.0
    assert result.exact is (write_offset in (-4, 8))
    assert result.body_byte_exact is result.exact


@pytest.mark.parametrize("load_offset", [4, 7, 8])
@pytest.mark.parametrize("before_copy", [b"", b"\xfd", b"\xfd\xfc"])
def test_copy_load_requires_a_complete_forward_copied_value(load_offset: int, before_copy: bytes) -> None:
    source, destination = 0x402000, 0x402100
    setup = bytes.fromhex("b902000000be") + struct.pack("<I", source) + b"\xbf" + struct.pack("<I", destination)
    prefix = before_copy + setup + bytes.fromhex("f3a5d905")
    target = prefix + struct.pack("<I", destination + load_offset) + b"\xc3"
    candidate = bytearray(prefix + struct.pack("<I", source + load_offset) + b"\xc3")
    relocations = []
    for offset, symbol_index, addend in (
        (len(before_copy) + 6, 1, 0),
        (len(before_copy) + 11, 2, 0),
        (len(prefix), 1, load_offset),
    ):
        candidate[offset : offset + 4] = struct.pack("<i", addend)
        relocations.append(CoffRelocation(offset, symbol_index, 6))
    obj = CoffObject(
        (CoffSection(".text", bytes(candidate), 0x20, tuple(relocations)),),
        (
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "_source", 0, 0, 0, 2),
            CoffSymbol(2, "_destination", 0, 0, 0, 2),
        ),
    )
    result = match_function(
        target,
        extract_object_function(obj, "probe"),
        image=LoadedImage(b"\0" * 0x3000, 0x400000, 0x3000),
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({source: ("source",), destination: ("destination",)}),
    )
    assert result.ratio == 1.0
    assert result.exact is (load_offset == 4 and before_copy != b"\xfd")


def test_copy_proof_survives_an_independent_read_only_scalar_load() -> None:
    source, destination, constant = 0x402000, 0x402100, 0x402200
    literal = struct.pack("<f", 1.0)
    setup = bytes.fromhex("b902000000be") + struct.pack("<I", source) + b"\xbf" + struct.pack("<I", destination)
    target = setup + bytes.fromhex("f3a5d905") + struct.pack("<I", constant) + bytes.fromhex("ddd8d905")
    target += struct.pack("<I", destination + 4) + b"\xc3"
    candidate = bytearray(target)
    relocations = []
    for offset, symbol_index, addend in ((6, 1, 0), (11, 2, 0), (19, 3, 0), (27, 1, 4)):
        candidate[offset : offset + 4] = struct.pack("<i", addend)
        relocations.append(CoffRelocation(offset, symbol_index, 6))
    obj = CoffObject(
        (
            CoffSection(".text", bytes(candidate), 0x20, tuple(relocations)),
            CoffSection(".rdata", literal, 0x40000040, ()),
        ),
        (
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "_source", 0, 0, 0, 2),
            CoffSymbol(2, "_destination", 0, 0, 0, 2),
            CoffSymbol(3, "__real@constant", 0, 2, 0, 3),
        ),
    )
    image = LoadedImage(
        b"\0" * 0x2200 + literal,
        0x400000,
        0x3000,
        read_only_ranges=((constant, constant + len(literal)),),
    )
    result = match_function(
        target,
        extract_object_function(obj, "probe"),
        image=image,
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({source: ("source",), destination: ("destination",)}),
    )
    assert result.exact
    assert result.body_byte_exact is True


def test_angle_include_changes_rebuild_real_objects_and_experiment_fingerprints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiler = matchlib._compiler_executable_path(
        matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches/game_is_full_version"),
        matchlib.DEFAULT_MATCH_ROOT,
    )
    runner = match_toolchain.resolve_wibo_path(matchlib.DEFAULT_MATCH_ROOT, required=False)
    if not compiler.is_file() or runner is None:
        pytest.skip("pinned compiler and Wibo are unavailable")
    root = tmp_path / "match"
    scratch = root / "scratches/probe"
    scratch.mkdir(parents=True)
    include = root / "include"
    include.mkdir()
    (include / "outer.h").write_text("#include <value.h>\n")
    header = include / "value.h"
    header.write_text("#define VALUE 1\n")
    source = '#include "outer.h"\nextern "C" int probe(void) { return VALUE; }\n'
    (scratch / "scratch.cpp").write_text(source)
    (scratch / "scratch.conf").write_text("FUNCTION=game_is_full_version\n")
    shutil.copy(matchlib.DEFAULT_MATCH_ROOT / "cl.sh", root / "cl.sh")
    monkeypatch.setenv("CRIMSON_MSVC_ROOT", str(compiler.parent.parent))
    monkeypatch.setenv("WIBO", str(runner))
    config = matchlib.ScratchConfig(
        scratch,
        "game_is_full_version",
        "crimsonland.exe",
        "msvc6.5",
        "/O2 /GB /GR-",
        "scratch.cpp",
        None,
        "probe",
        "",
    )
    key = matchlib._scratch_build_key(config, root)
    epoch = matchlib.scratch_experiment_epoch(config, root)
    fingerprint = matchlib.source_probe_tree_fingerprint(config, source, root)
    initial = matchlib.compile_scratch(config, root).read_bytes()
    assert matchlib.normalize_function(extract_object_function(matchlib.parse_coff_object(initial), "probe").data) == (
        "mov eax, 0x1",
        "ret",
    )
    header.write_text("#define VALUE 2\n")
    assert matchlib._scratch_build_key(config, root) != key
    assert matchlib.scratch_experiment_epoch(config, root) != epoch
    assert matchlib.source_probe_tree_fingerprint(config, source, root) != fingerprint
    rebuilt = matchlib.compile_scratch(config, root).read_bytes()
    assert matchlib.normalize_function(extract_object_function(matchlib.parse_coff_object(rebuilt), "probe").data) == (
        "mov eax, 0x2",
        "ret",
    )


def test_angle_includes_use_search_paths_instead_of_the_including_directory(tmp_path: Path) -> None:
    including = tmp_path / "local"
    search = tmp_path / "search"
    including.mkdir()
    search.mkdir()
    header = including / "outer.h"
    header.write_text("#include <value.h>\n")
    (including / "value.h").write_text("wrong sibling\n")
    selected = search / "value.h"
    selected.write_text("correct search path\n")
    resolver = matchlib._ScratchIncludeResolver(tmp_path)
    assert resolver.direct_dependencies(header, source=False, include_dirs=(search,)) == (selected,)
