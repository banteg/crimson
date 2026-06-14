from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from crimson.match import (
    DEFAULT_FUNCTIONS_PATH,
    FunctionManifest,
    FunctionSymbol,
    ImageTotals,
    LoadedImage,
    ObjectFunction,
    ScratchConfig,
    ScratchStatus,
    collect_image_totals,
    collect_scratch_statuses,
    common_prefix_length,
    diff_regions,
    disassemble_normalized_function,
    extract_object_function,
    load_function_manifest,
    match_function,
    normalize_function,
    parse_coff_object,
    render_image_total_rows,
    render_status_markdown,
    render_status_rows,
    render_status_table,
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
        functions=(
            next(
                function
                for function in load_function_manifest(DEFAULT_FUNCTIONS_PATH).functions
                if function.name == "player_update"
            ),
        ),
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
        compiler="msvc6.5",
        cflags="/O2 /G6 /W3 /GR-",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="branch",
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
    assert render_status_rows([status])[0][9] == "branch"
    totals = [
        ImageTotals(
            image="crimsonland.exe",
            function_count=10,
            byte_total=1000,
            matched_functions=0,
            matched_bytes=0,
            scratch_count=1,
            matched_scratches=0,
        ),
        ImageTotals(
            image="grim.dll",
            function_count=20,
            byte_total=2000,
            matched_functions=0,
            matched_bytes=0,
            scratch_count=0,
            matched_scratches=0,
        ),
    ]
    assert render_image_total_rows(totals)[0] == ("crimsonland.exe", "0/10", "0/1000", "0.0%", "0/1")
    assert "all images: 0/30 functions, 0/3000 bytes (0.0%) matched; 0/1 scratches at 100%" in (
        render_status_table([status], totals)
    )
    markdown = render_status_markdown([status], totals)
    assert "| crimsonland.exe | 0/10 | 0/1000 | 0.0% | 0/1 |" in markdown
    assert "## crimsonland.exe" in markdown
    assert "## grim.dll" in markdown
    assert "| wip | foo | 0x00401000 | 10 | 5/4 | 50.00% | 2/4 |  | branch |" in markdown


def test_collect_image_totals_counts_manifest_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    manifests = {
        "crimsonland.exe": FunctionManifest(
            image_name="crimsonland.exe",
            image_base=0x401000,
            functions=(
                FunctionSymbol(name="foo", address=0x401000, end=0x401003, size=3),
                FunctionSymbol(name="bar", address=0x401010, end=0x401013, size=3),
            ),
        ),
        "grim.dll": FunctionManifest(
            image_name="grim.dll",
            image_base=0x1010,
            functions=(FunctionSymbol(name="baz", address=0x1010, end=0x1012, size=2),),
        ),
    }

    def fake_load_manifest(*args: object, **kwargs: object) -> FunctionManifest:
        return manifests[str(kwargs["image_name"])]

    def fake_load_image(*args: object, **kwargs: object) -> LoadedImage:
        image_base = args[1]
        assert isinstance(image_base, int)
        return LoadedImage(mapped=b"\xc3" * 0x20, image_base=image_base, size_of_image=0x20)

    config = ScratchConfig(
        directory=Path("scratch"),
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2 /G6 /W3 /GR-",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )
    statuses = [
        ScratchStatus(
            config=config,
            address=0x401000,
            target_size=3,
            ratio=1.0,
            prefix_instructions=1,
            target_instructions=1,
            candidate_instructions=1,
            error=None,
        ),
        ScratchStatus(
            config=replace(config, function="bar"),
            address=0x401010,
            target_size=3,
            ratio=0.5,
            prefix_instructions=0,
            target_instructions=1,
            candidate_instructions=1,
            error=None,
        ),
        ScratchStatus(
            config=replace(config, function="0x00401000"),
            address=0x401000,
            target_size=2,
            ratio=1.0,
            prefix_instructions=1,
            target_instructions=1,
            candidate_instructions=1,
            error=None,
        ),
    ]

    monkeypatch.setattr("crimson.match.load_function_manifest", fake_load_manifest)
    monkeypatch.setattr("crimson.match.load_image", fake_load_image)

    totals = collect_image_totals(statuses)

    assert totals == [
        ImageTotals(
            image="crimsonland.exe",
            function_count=2,
            byte_total=6,
            matched_functions=1,
            matched_bytes=3,
            scratch_count=3,
            matched_scratches=2,
        ),
        ImageTotals(
            image="grim.dll",
            function_count=1,
            byte_total=2,
            matched_functions=0,
            matched_bytes=0,
            scratch_count=0,
            matched_scratches=0,
        ),
    ]


def test_collect_status_overrides_compiler(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scratch = tmp_path / "scratches" / "foo"
    scratch.mkdir(parents=True)
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
    (scratch / "scratch.cpp").write_text('extern "C" void foo() {}\n', encoding="utf-8")

    observed = {}

    def fake_load_manifest(*args: object, **kwargs: object) -> FunctionManifest:
        return FunctionManifest(
            image_name="crimsonland.exe",
            image_base=0x400000,
            functions=(FunctionSymbol(name="foo", address=0x401000, end=0x401001, size=1),),
        )

    def fake_load_image(*args: object, **kwargs: object) -> LoadedImage:
        return LoadedImage(mapped=b"\xc3", image_base=0x401000, size_of_image=1)

    def fake_compile(config: ScratchConfig, match_root: Path) -> Path:
        observed["compiler"] = config.compiler
        observed["cflags"] = config.cflags
        return scratch / "scratch.obj"

    monkeypatch.setattr("crimson.match.load_function_manifest", fake_load_manifest)
    monkeypatch.setattr("crimson.match.load_image", fake_load_image)
    monkeypatch.setattr("crimson.match.compile_scratch", fake_compile)
    monkeypatch.setattr("crimson.match.parse_coff_object", lambda data: object())
    monkeypatch.setattr(
        "crimson.match.extract_object_function",
        lambda obj, symbol: ObjectFunction(name="foo", data=b"\xc3", relocation_offsets=frozenset()),
    )
    monkeypatch.setattr(Path, "read_bytes", lambda self: b"")

    statuses = collect_scratch_statuses(tmp_path, compiler="msvc6.5", cflags="/O2")

    assert statuses[0].state == "match"
    assert observed == {"compiler": "msvc6.5", "cflags": "/O2"}
