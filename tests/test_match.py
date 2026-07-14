from __future__ import annotations

import struct
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import (
    DEFAULT_FUNCTIONS_PATH,
    VC6_LOCAL_JUMP_TABLE_KEY,
    VC6_SINGLE_DELETE_UNWIND_KEY,
    CoffObject,
    CoffRelocation,
    CoffSection,
    CoffSymbol,
    FunctionManifest,
    FunctionSymbol,
    ImageTotals,
    LoadedImage,
    MaskedOperandAudit,
    MaskedOperandAuditEntry,
    MaskedReference,
    MatchResult,
    ObjectFunction,
    ObjectRelocationReference,
    ReferenceCatalog,
    ScratchConfig,
    ScratchStatus,
    _coff_local_jump_table_key,
    _coff_vc6_single_delete_unwind_key,
    _scratch_build_key,
    _ScratchIncludeResolver,
    collect_image_totals,
    collect_scratch_statuses,
    common_prefix_length,
    compile_scratch,
    diff_regions,
    disassemble_normalized_function,
    extract_object_function,
    load_function_manifest,
    load_reference_catalog,
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


def test_load_manifest_applies_curated_name_map(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1000A310","end":"0x1000A323","name":"sub_1000A310","size":19}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1000A310","name":"grim_joystick_button_down"}]\n',
        encoding="utf-8",
    )

    manifest = load_function_manifest(
        functions_path,
        metadata_path=None,
        image_name="grim.dll",
        name_map_path=name_map_path,
    )

    function, start, end = resolve_function(manifest, "grim_joystick_button_down")
    assert function.name == "grim_joystick_button_down"
    assert start == 0x1000A310
    assert end == 0x1000A323


def test_load_reference_catalog_includes_import_iat_names(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1000A8FA","name":"_ftol"}]\n',
        encoding="utf-8",
    )
    (tmp_path / "imports.json").write_text(
        '[{"module":"MSVCRT","entries":['
        '{"address":"0x1004C0B4","name":"vsprintf","ordinal":0},'
        '{"address":"0x1004C0FC","name":"_ftol","ordinal":0}'
        "]}]\n",
        encoding="utf-8",
    )
    manifest = FunctionManifest(image_name="grim.dll", image_base=0x10000000, functions=())

    catalog = load_reference_catalog(
        manifest,
        functions_path=functions_path,
        data_map_path=tmp_path / "missing-data-map.json",
    )

    assert catalog.keys_for_address(0x1004C0B4) == (
        "address:0x1004c0b4",
        "name:vsprintf",
    )
    assert catalog.knows_name("__imp__vsprintf")
    assert catalog.keys_for_object_reference("__imp__vsprintf", 0) == (
        "name:vsprintf",
        "address:0x1004c0b4",
    )
    assert catalog.keys_for_object_reference("__ftol", 0) == (
        "name:ftol",
        "address:0x1000a8fa",
    )
    assert catalog.keys_for_object_reference("__imp___ftol", 0) == (
        "name:ftol",
        "address:0x1004c0fc",
    )


def test_load_reference_catalog_includes_curated_decorated_aliases(tmp_path: Path) -> None:
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x10004AB0",'
        '"name":"grim_texture_release",'
        '"aliases":["??1GrimTexture@@QAE@XZ"]}]\n',
        encoding="utf-8",
    )
    manifest = FunctionManifest(image_name="grim.dll", image_base=0x10000000, functions=())

    catalog = load_reference_catalog(
        manifest,
        functions_path=tmp_path / "missing-functions.json",
        data_map_path=tmp_path / "missing-data-map.json",
        name_map_path=name_map_path,
    )

    assert catalog.keys_for_address(0x10004AB0) == (
        "address:0x10004ab0",
        "name:grim_texture_release",
        "name:??1GrimTexture@@QAE@XZ",
    )
    assert catalog.keys_for_object_reference("??1GrimTexture@@QAE@XZ", 0) == (
        "name:??1GrimTexture@@QAE@XZ",
        "name:?1GrimTexture",
        "address:0x10004ab0",
    )


def test_load_reference_catalog_preserves_scoped_data_aliases(tmp_path: Path) -> None:
    local_name = "?half_vector@?1??grim_draw_line@IGrim2D_cpp@@UAEXPAM0M@Z@4UVector@@A"
    data_map_path = tmp_path / "data_map.json"
    data_map_path.write_text(
        '{"entries":[{"program":"grim.dll","address":"0x1005A490",'
        f'"name":"grim_line_dx","aliases":["{local_name}"]}}]}}\n',
        encoding="utf-8",
    )
    manifest = FunctionManifest(image_name="grim.dll", image_base=0x10000000, functions=())

    catalog = load_reference_catalog(
        manifest,
        functions_path=tmp_path / "missing-functions.json",
        data_map_path=data_map_path,
        name_map_path=tmp_path / "missing-name-map.json",
    )

    assert catalog.knows_name(f"_{local_name}")
    assert catalog.keys_for_object_reference(f"_{local_name}", 4) == (
        f"name:{local_name}+0x4",
        "address:0x1005a494",
    )


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
    assert function.relocation_references[0].symbol_name == "_foo"
    assert function.relocation_references[0].key == "name:foo"


def test_normalize_masks_relocated_and_absolute_operands() -> None:
    code = bytes.fromhex("a134124a00c3")
    assert normalize_function(code, relocation_offsets=frozenset({1}))[0] == "mov eax, dword [ADDR]"
    assert normalize_function(code, address_range=(0x400000, 0x500000))[0] == "mov eax, dword [ADDR]"
    assert normalize_function(code)[0] == "mov eax, dword [0x4a1234]"


def test_normalize_resolves_vc_exception_chain_relocation_to_fs_zero() -> None:
    function = ObjectFunction(
        name="_probe",
        data=bytes.fromhex("64a100000000c3"),
        relocation_offsets=frozenset({2}),
        relocation_references=(
            ObjectRelocationReference(
                offset=2,
                symbol_name="__except_list",
                key="name:except_list",
                explained=True,
            ),
        ),
    )

    disassembly = disassemble_normalized_function(
        function.data,
        relocation_offsets=function.relocation_offsets,
        relocation_references=function.relocation_references,
    )

    assert disassembly[0].text == "mov eax, dword [0x0]"
    assert disassembly[0].masked_references == ()


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


@pytest.mark.parametrize(
    ("candidate_key", "catalog", "expected_status", "exact"),
    [
        ("name:expected", ReferenceCatalog({0x402000: ("expected",)}), "ok", True),
        (
            "name:other",
            ReferenceCatalog({0x402000: ("expected",), 0x403000: ("other",)}),
            "mismatch",
            False,
        ),
        ("name:expected", ReferenceCatalog({}), "unresolved", False),
    ],
)
def test_match_function_audits_masked_reference_identity(
    candidate_key: str,
    catalog: ReferenceCatalog,
    expected_status: str,
    exact: bool,
) -> None:
    target = bytes.fromhex("a100204000c3")
    candidate = ObjectFunction(
        name="_foo",
        data=bytes.fromhex("a100000000c3"),
        relocation_offsets=frozenset({1}),
        relocation_references=(
            ObjectRelocationReference(
                offset=1,
                symbol_name=candidate_key.removeprefix("name:"),
                key=candidate_key,
                explained=True,
            ),
        ),
    )
    result = match_function(
        target,
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0x10000),
        target_va=0x401000,
        reference_catalog=catalog,
    )
    assert result.ratio == 1.0
    assert result.masked_operand_audit.entries[0].status == expected_status
    assert result.exact is exact


def test_match_function_audits_compiler_string_by_content() -> None:
    mapped = bytearray(0x10000)
    mapped[0x2000:0x2003] = b"%s\x00"
    candidate = ObjectFunction(
        name="_foo",
        data=bytes.fromhex("6800000000c3"),
        relocation_offsets=frozenset({1}),
        relocation_references=(
            ObjectRelocationReference(
                offset=1,
                symbol_name="??_C@_02DILL@?$CFs?$AA@",
                key=None,
                explained=False,
                symbol_data=b"%s\x00",
            ),
        ),
    )
    result = match_function(
        bytes.fromhex("6800204000c3"),
        candidate,
        image=LoadedImage(mapped=bytes(mapped), image_base=0x400000, size_of_image=len(mapped)),
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({}),
    )
    assert result.exact
    assert result.masked_operand_audit.ok_count == 1


def test_match_function_audits_compiler_float_by_content() -> None:
    mapped = bytearray(0x10000)
    mapped[0x2000:0x2004] = bytes.fromhex("000000b4")
    candidate = ObjectFunction(
        name="_foo",
        data=bytes.fromhex("d90500000000c3"),
        relocation_offsets=frozenset({2}),
        relocation_references=(
            ObjectRelocationReference(
                offset=2,
                symbol_name="__real@b4000000",
                key=None,
                explained=False,
                symbol_data=bytes.fromhex("000000b4"),
            ),
        ),
    )
    result = match_function(
        bytes.fromhex("d90500204000c3"),
        candidate,
        image=LoadedImage(mapped=bytes(mapped), image_base=0x400000, size_of_image=len(mapped)),
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({}),
    )
    assert result.exact
    assert result.masked_operand_audit.ok_count == 1


def test_match_function_audits_complete_vc6_delete_unwind_graph() -> None:
    image_base = 0x400000
    handler_address = 0x400100
    func_info_address = 0x400200
    cleanup_address = 0x400300
    frame_handler_address = 0x400400
    delete_address = 0x400500
    unwind_key = f"{VC6_SINGLE_DELETE_UNWIND_KEY}:ebp+0x0c"
    mapped = bytearray(0x1000)

    handler = b"\xb8" + struct.pack("<I", func_info_address)
    handler += b"\xe9" + struct.pack("<i", frame_handler_address - (handler_address + 10))
    mapped[0x100:0x10A] = handler
    func_info = struct.pack("<II", 0x19930520, 1)
    func_info += struct.pack("<I", func_info_address + 32) + b"\x00" * 20
    func_info += struct.pack("<iI", -1, cleanup_address)
    mapped[0x200:0x228] = func_info
    cleanup = bytes.fromhex("8b450c50e8")
    cleanup += struct.pack("<i", delete_address - (cleanup_address + 9)) + bytes.fromhex("59c3")
    mapped[0x300:0x30B] = cleanup

    candidate = ObjectFunction(
        name="_probe",
        data=b"\x68\x00\x00\x00\x00\xc3",
        relocation_offsets=frozenset({1}),
        relocation_references=(
            ObjectRelocationReference(
                offset=1,
                symbol_name="$Lhandler",
                key=unwind_key,
                explained=True,
            ),
        ),
    )
    catalog = ReferenceCatalog(
        {
            frame_handler_address: ("__CxxFrameHandler",),
            delete_address: ("??3@YAXPAX@Z",),
        },
    )

    result = match_function(
        b"\x68" + struct.pack("<I", handler_address) + b"\xc3",
        candidate,
        image=LoadedImage(bytes(mapped), image_base, len(mapped)),
        target_va=0x400000,
        reference_catalog=catalog,
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 1


def test_recognizes_complete_vc6_delete_unwind_graph_in_coff() -> None:
    handler = b"\xb8\x00\x00\x00\x00\xe9\x00\x00\x00\x00"
    cleanup = bytes.fromhex("8b450c50e80000000059c3")
    func_info = struct.pack("<II", 0x19930520, 1) + b"\x00" * 24
    func_info += struct.pack("<iI", -1, 0)
    obj = CoffObject(
        sections=(
            CoffSection(
                name=".text$x",
                data=handler + cleanup,
                characteristics=0x20,
                relocations=(
                    CoffRelocation(1, 1, 6),
                    CoffRelocation(6, 3, 20),
                    CoffRelocation(15, 5, 20),
                ),
            ),
            CoffSection(
                name=".xdata$x",
                data=func_info,
                characteristics=0,
                relocations=(
                    CoffRelocation(8, 2, 6),
                    CoffRelocation(36, 4, 6),
                ),
            ),
        ),
        symbols=(
            CoffSymbol(0, "$Lhandler", 0, 1, 0, 6),
            CoffSymbol(1, "$Tinfo", 0, 2, 0, 3),
            CoffSymbol(2, "$Tunwind", 32, 2, 0, 3),
            CoffSymbol(3, "___CxxFrameHandler", 0, 0, 0x20, 2),
            CoffSymbol(4, "$Lcleanup", 10, 1, 0, 6),
            CoffSymbol(5, "??3@YAXPAX@Z", 0, 0, 0x20, 2),
        ),
    )

    assert _coff_vc6_single_delete_unwind_key(obj, obj.symbols[0]) == (f"{VC6_SINGLE_DELETE_UNWIND_KEY}:ebp+0x0c")


def test_recognizes_compiler_local_jump_table_in_coff() -> None:
    obj = CoffObject(
        sections=(
            CoffSection(
                name=".text",
                data=b"\x90" * 0x20 + b"\x00" * 12,
                characteristics=0x20,
                relocations=(
                    CoffRelocation(0x20, 2, 6),
                    CoffRelocation(0x24, 3, 6),
                    CoffRelocation(0x28, 4, 6),
                ),
            ),
        ),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "$Ltable", 0x20, 1, 0, 6),
            CoffSymbol(2, "$Lcase0", 0x08, 1, 0, 6),
            CoffSymbol(3, "$Lcase1", 0x10, 1, 0, 6),
            CoffSymbol(4, "$Lcase2", 0x18, 1, 0, 6),
        ),
    )

    assert _coff_local_jump_table_key(obj, obj.symbols[0], obj.symbols[1]) == (
        f"{VC6_LOCAL_JUMP_TABLE_KEY}:0x8,0x10,0x18"
    )


def test_match_function_audits_local_jump_table_destinations() -> None:
    image_base = 0x400000
    function_address = 0x401000
    table_address = 0x402000
    target = bytes.fromhex("ff2485") + struct.pack("<I", table_address) + b"\xc3" + b"\x90" * 16
    candidate = ObjectFunction(
        name="_probe",
        data=bytes.fromhex("ff2485") + b"\x00" * 4 + b"\xc3" + b"\x90" * 16,
        relocation_offsets=frozenset({3}),
        relocation_references=(
            ObjectRelocationReference(
                offset=3,
                symbol_name="$Ltable",
                key=f"{VC6_LOCAL_JUMP_TABLE_KEY}:0x8,0x10,0x14",
                explained=True,
            ),
        ),
    )
    mapped = bytearray(0x3000)
    mapped[0x2000:0x200C] = struct.pack(
        "<III",
        function_address + 0x08,
        function_address + 0x10,
        function_address + 0x14,
    )

    result = match_function(
        target,
        candidate,
        image=LoadedImage(bytes(mapped), image_base, len(mapped)),
        target_va=function_address,
        reference_catalog=ReferenceCatalog({}),
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 1


def test_diff_command_fails_on_masked_reference_debt(monkeypatch: pytest.MonkeyPatch) -> None:
    target_reference = MaskedReference(
        operand_index=0,
        kind="imm",
        source="image",
        value=0x402000,
        text="0x00402000",
        keys=("address:0x00402000",),
        explained=True,
    )
    candidate_reference = MaskedReference(
        operand_index=0,
        kind="imm",
        source="reloc",
        value=None,
        text="unknown",
        keys=(),
        explained=False,
    )
    audit = MaskedOperandAudit(
        (
            MaskedOperandAuditEntry(
                target_index=0,
                candidate_index=0,
                target_offset=0,
                candidate_offset=0,
                target_address=0x401000,
                candidate_address=0,
                instruction="push ADDR",
                target_references=(target_reference,),
                candidate_references=(candidate_reference,),
                status="unresolved",
            ),
        ),
    )
    result = MatchResult(
        ratio=1.0,
        prefix_instructions=1,
        target_lines=("push ADDR",),
        candidate_lines=("push ADDR",),
        masked_operand_audit=audit,
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: result)

    completed = CliRunner().invoke(match_app, ["diff", "candidate.obj", "foo"])

    assert completed.exit_code == 1
    assert "refs=0/1/0" in completed.output
    assert "unresolved target=0x00401000" in completed.output


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
        cflags="/O2 /GB /W3 /GR-",
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
    assert render_status_rows([status])[0][8] == "0/0/0"
    assert render_status_rows([status])[0][10] == "branch"
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
    assert "all images: 0/30 functions, 0/3000 bytes (0.0%) matched; 0/1 scratches verified" in (
        render_status_table([status], totals)
    )
    markdown = render_status_markdown([status], totals)
    assert "| crimsonland.exe | 0/10 | 0/1000 | 0.0% | 0/1 |" in markdown
    assert "## crimsonland.exe" in markdown
    assert "## grim.dll" in markdown
    assert "| wip | foo | 0x00401000 | 10 | 5/4 | 50.00% | 2/4 | 0/0/0 |  | branch |" in markdown


def test_exact_score_with_reference_debt_requires_audit() -> None:
    config = ScratchConfig(
        directory=Path("scratch"),
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )
    status = ScratchStatus(
        config=config,
        address=0x401000,
        target_size=6,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
        masked_unresolved=1,
        audit=MaskedOperandAudit(),
    )
    assert status.state == "audit"


def test_scratch_build_key_tracks_transitive_headers(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "foo"
    include = match_root / "include"
    third_party = tmp_path / "third_party" / "headers"
    compiler = match_root / "compilers" / "msvc6.5" / "Bin"
    scratch.mkdir(parents=True)
    include.mkdir()
    third_party.mkdir(parents=True)
    compiler.mkdir(parents=True)
    (scratch / "scratch.cpp").write_text('#include "outer.h"\n', encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
    (include / "outer.h").write_text('#include "inner.h"\n', encoding="utf-8")
    inner = third_party / "inner.h"
    inner.write_text("#define VALUE 1\n", encoding="utf-8")
    (match_root / "cl.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (compiler / "CL.EXE").write_bytes(b"compiler")
    config = ScratchConfig(
        directory=scratch,
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )
    resolver = _ScratchIncludeResolver(match_root, repo_root=tmp_path)
    before = _scratch_build_key(config, match_root, include_resolver=resolver)
    dependencies = {row[0] for row in before["dependencies"]}
    assert "include/outer.h" in dependencies
    assert str(inner) in dependencies
    inner.write_text("#define VALUE 2\n", encoding="utf-8")
    after = _scratch_build_key(config, match_root, include_resolver=resolver)
    assert after != before


def test_compile_scratch_isolates_profiles_and_resolves_match_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    match_root = tmp_path / "match"
    scratch = tmp_path / "scratch"
    compiler = match_root / "compilers" / "msvc6.5" / "Bin"
    scratch.mkdir()
    compiler.mkdir(parents=True)
    (scratch / "scratch.c").write_text("void foo(void) {}\n", encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
    (match_root / "cl.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (compiler / "CL.EXE").write_bytes(b"compiler")
    config = ScratchConfig(
        directory=scratch,
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2 /GB",
        source="scratch.c",
        end_va=None,
        symbol="foo",
        note="",
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        cwd = Path(str(kwargs["cwd"]))
        (cwd / "scratch.obj").write_bytes(" ".join(command).encode())
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)

    optimized = compile_scratch(config, Path("match"))
    unoptimized = compile_scratch(replace(config, cflags="/Od"), Path("match"))

    assert optimized != unoptimized
    assert optimized.parent != unoptimized.parent
    assert optimized.read_bytes() != unoptimized.read_bytes()
    assert Path(commands[0][0]).is_absolute()
    assert commands[0][0] == str((match_root / "cl.sh").resolve())


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
        cflags="/O2 /GB /W3 /GR-",
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

    def fake_compile(
        config: ScratchConfig,
        match_root: Path,
        *,
        include_resolver: _ScratchIncludeResolver | None = None,
    ) -> Path:
        observed["compiler"] = config.compiler
        observed["cflags"] = config.cflags
        observed["calls"] = observed.get("calls", 0) + 1
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

    statuses = collect_scratch_statuses(tmp_path, compiler="msvc6.5", cflags="/O2", jobs=1)
    cached_statuses = collect_scratch_statuses(tmp_path, compiler="msvc6.5", cflags="/O2", jobs=1)

    assert statuses[0].state == "match"
    assert cached_statuses[0].state == "match"
    assert observed == {"compiler": "msvc6.5", "cflags": "/O2", "calls": 1}
