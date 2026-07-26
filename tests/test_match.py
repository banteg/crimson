from __future__ import annotations

import json
import struct
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import (
    DEFAULT_FUNCTIONS_PATH,
    SHARD_PLAN_KIND,
    VC6_LOCAL_JUMP_TABLE_KEY,
    VC6_SINGLE_DELETE_UNWIND_KEY,
    WORKER_CLAIM_KIND,
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
    ProbeResult,
    ReferenceCatalog,
    ScratchConfig,
    ScratchStatus,
    TriageRow,
    _coff_local_jump_table_key,
    _coff_vc6_single_delete_unwind_key,
    _region_hints,
    _scratch_build_key,
    _ScratchIncludeResolver,
    build_match_shard_plan,
    claimed_scratch_paths,
    collect_image_totals,
    collect_scratch_statuses,
    collect_triage_rows,
    common_prefix_length,
    compile_scratch,
    diff_region_payload,
    diff_regions,
    disassemble_normalized_function,
    evaluate_profile_matrix,
    evaluate_source_probe,
    extract_object_function,
    inspect_match_function,
    load_function_manifest,
    load_reference_catalog,
    load_scratch_config,
    match_function,
    match_result_payload,
    normalize_function,
    parse_coff_object,
    render_image_total_rows,
    render_probe_result,
    render_profile_table,
    render_status_markdown,
    render_status_rows,
    render_status_summary,
    render_status_table,
    render_triage_rows,
    resolve_function,
    sort_profile_statuses,
    sort_triage_rows,
    triage_row_payload,
    validate_claimed_changes,
    validate_match_claim,
    validate_matching_workspace,
    validate_scratch_source,
    write_match_shard_plan,
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


def test_load_manifest_adds_explicit_disjoint_curated_function(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1001BC84","end":"0x1001BCA0","name":"sub_1001BC84","size":28}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1001BC68","end":"0x1001BC84",'
        '"name":"grim_pixel_format_scalar_deleting_destroy_yuv_base","create":true}]\n',
        encoding="utf-8",
    )

    manifest = load_function_manifest(
        functions_path,
        metadata_path=None,
        image_name="grim.dll",
        name_map_path=name_map_path,
    )

    function, start, end = resolve_function(manifest, "grim_pixel_format_scalar_deleting_destroy_yuv_base")
    assert function.size == 28
    assert start == 0x1001BC68
    assert end == 0x1001BC84


def test_load_manifest_rejects_overlapping_created_function(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1001BC70","end":"0x1001BC90","name":"sub_1001BC70","size":32}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1001BC68","end":"0x1001BC84",'
        '"name":"grim_pixel_format_scalar_deleting_destroy_yuv_base","create":true}]\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="overlaps the existing manifest"):
        load_function_manifest(
            functions_path,
            metadata_path=None,
            image_name="grim.dll",
            name_map_path=name_map_path,
        )


def test_load_manifest_can_include_curated_library_false_positive(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401170","end":"0x0040117A",'
        '"name":"console_global_init","size":10,"library":true}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"crimsonland.exe","address":"0x00401170",'
        '"name":"console_global_init","include_library":true}]\n',
        encoding="utf-8",
    )

    manifest = load_function_manifest(
        functions_path,
        metadata_path=None,
        image_name="crimsonland.exe",
        name_map_path=name_map_path,
    )

    function, start, end = resolve_function(manifest, "console_global_init")
    assert function.name == "console_global_init"
    assert start == 0x00401170
    assert end == 0x0040117A


def test_port_scope_uses_stable_ownership_boundary() -> None:
    manifest = load_function_manifest(DEFAULT_FUNCTIONS_PATH, scope="port")

    assert resolve_function(manifest, "game_is_full_version")[0].address == 0x0041DF40
    with pytest.raises(ValueError, match="not found"):
        resolve_function(manifest, "float_near_equal")

    grim_manifest = load_function_manifest(
        Path("analysis/ida/raw/grim.dll/functions.json"),
        metadata_path=Path("analysis/ida/raw/grim.dll/metadata.json"),
        image_name="grim.dll",
        scope="port",
    )
    assert resolve_function(grim_manifest, "grim_mouse_shutdown")[0].address == 0x1000A7D0
    assert resolve_function(grim_manifest, "FUN_1000a880")[0].address == 0x1000A880
    with pytest.raises(ValueError, match="not found"):
        resolve_function(grim_manifest, "sprintf")
    with pytest.raises(ValueError, match="not found"):
        resolve_function(grim_manifest, "grim_format_info_lookup")


def test_matching_workspace_stays_inside_port_scope() -> None:
    assert validate_matching_workspace(scope="port") == []


def test_scratch_config_parses_recovery_and_residuals(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo RECOVERY=semantic-complete RESIDUAL=compiler,references\n",
        encoding="utf-8",
    )

    config = load_scratch_config(tmp_path)

    assert config.recovery == "semantic-complete"
    assert config.residuals == ("compiler", "references")


def test_inspect_joins_scoped_tool_views() -> None:
    payload = inspect_match_function("game_is_full_version", statuses=[])

    assert payload["scope"] == "port"
    assert payload["address"] == 0x0041DF40
    assert payload["observed"]["ida"]["function"]["library"] is True
    assert payload["observed"]["ghidra"]["function"]["name"] == "game_is_full_version"
    assert payload["binary_ninja"]["commands"]["decompile"].startswith(
        "bn decompile 0x0041df40",
    )

    grim = inspect_match_function(
        "grim_is_key_down",
        image="grim.dll",
        scope="all",
        statuses=[],
    )
    assert grim["observed"]["ghidra"]["function"]["name"] == "grim_is_key_down"


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


def test_extract_object_function_prefers_exact_decorated_symbol() -> None:
    code = bytes.fromhex("31c0c3")
    obj = parse_coff_object(build_object(code, [("__foo", 0), ("_foo", 0)], []))

    assert extract_object_function(obj, "__foo").name == "__foo"
    assert extract_object_function(obj, "_foo").name == "_foo"


def test_extract_object_function_collects_relocations() -> None:
    code = bytes.fromhex("a100000000c3")
    obj = parse_coff_object(build_object(code, [("_foo", 0)], [1]))
    function = extract_object_function(obj, "foo")
    assert function.relocation_offsets == frozenset({1})
    assert function.relocation_references[0].symbol_name == "_foo"
    assert function.relocation_references[0].key == "name:foo"


def test_extract_object_function_excludes_appended_local_jump_table() -> None:
    code = bytes.fromhex("ff248500000000b801000000c3c38bff") + b"\x00" * 8
    obj = CoffObject(
        sections=(
            CoffSection(
                name=".text",
                data=code,
                characteristics=0x20,
                relocations=(
                    CoffRelocation(3, 1, 6),
                    CoffRelocation(0x10, 2, 6),
                    CoffRelocation(0x14, 3, 6),
                ),
            ),
        ),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "$Ltable", 0x10, 1, 0, 6),
            CoffSymbol(2, "$Lcase0", 0x07, 1, 0, 6),
            CoffSymbol(3, "$Lcase1", 0x0D, 1, 0, 6),
        ),
    )

    function = extract_object_function(obj, "probe")

    assert function.data == code[:0x10]
    assert function.relocation_offsets == frozenset({3})
    assert normalize_function(
        function.data,
        relocation_offsets=function.relocation_offsets,
    ) == ("jmp dword [eax*4+ADDR]", "mov eax, 0x1", "ret", "ret")


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


def test_normalize_resolves_coff_rel32_self_call_as_local_label() -> None:
    obj = CoffObject(
        sections=(
            CoffSection(
                name=".text",
                data=bytes.fromhex("e800000000c3"),
                characteristics=0x20,
                relocations=(CoffRelocation(1, 0, 0x14),),
            ),
        ),
        symbols=(CoffSymbol(0, "_foo", 0, 1, 0x20, 2),),
    )

    function = extract_object_function(obj, "foo")
    disassembly = disassemble_normalized_function(
        function.data,
        relocation_offsets=function.relocation_offsets,
        relocation_references=function.relocation_references,
    )

    assert function.relocation_references[0].local_target_offset == 0
    assert disassembly[0].text == "call L0"
    assert disassembly[0].masked_references == ()


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


def test_reference_catalog_scopes_ambiguous_object_alias() -> None:
    catalog = ReferenceCatalog(
        {
            0x402000: ("first_destroy", "$E2"),
            0x403000: ("second_destroy", "$E2"),
        },
        {"$E2": (0x402000, 0x403000), "second_destroy": (0x403000,)},
    )

    assert not catalog.knows_name("$E2")
    scoped = catalog.with_object_aliases((("$E2", "second_destroy"),))
    assert scoped.knows_name("$E2")
    assert "address:0x00403000" in scoped.keys_for_object_reference("$E2", 0)


def test_match_function_accepts_scoped_alias_for_compiler_string() -> None:
    address = 0x402000
    symbol = "??_C@_00A@?$AA@"
    catalog = ReferenceCatalog(
        {address: ("s_empty_string",)},
        {"s_empty_string": (address,)},
    ).with_object_aliases(((symbol, "s_empty_string"),))
    candidate = ObjectFunction(
        name="_foo",
        data=bytes.fromhex("6800000000c3"),
        relocation_offsets=frozenset({1}),
        relocation_references=(
            ObjectRelocationReference(
                offset=1,
                symbol_name=symbol,
                key=None,
                explained=False,
                symbol_data=b"\x00",
            ),
        ),
    )

    result = match_function(
        bytes.fromhex("6800204000c3"),
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0x10000),
        target_va=0x401000,
        reference_catalog=catalog,
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 1


@pytest.mark.parametrize("literal", [b"%s\x00", b"perk description " * 16 + b"\x00"])
def test_match_function_audits_compiler_string_by_content(literal: bytes) -> None:
    mapped = bytearray(0x10000)
    mapped[0x2000 : 0x2000 + len(literal)] = literal
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
                symbol_data=literal,
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
    assert regions[0].target_byte_span == "0x1:0x6"
    assert regions[0].candidate_byte_span == "0x1:0x9"
    assert regions[0].target_address_span == "0x00401001:0x00401006"
    assert regions[0].target_byte_count == 5
    assert regions[0].fuzzy_weighted_bytes == pytest.approx(5 * regions[0].ratio)
    assert regions[0].hints == ("instruction-shape-difference",)
    payload = diff_region_payload(regions[0])
    assert payload["target_bytes"]["count"] == 5
    assert payload["hints"] == ["instruction-shape-difference"]


def test_diff_command_json_includes_region_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    target = bytes.fromhex("558bec31c040c3")
    candidate = ObjectFunction(
        name="_foo",
        data=bytes.fromhex("558becb80100000040c3"),
        relocation_offsets=frozenset(),
    )
    result = match_function(
        target,
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0),
        target_va=0x401000,
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.run_match", lambda **kwargs: result)

    completed = CliRunner().invoke(
        match_app,
        ["diff", "candidate.obj", "foo", "--json", "--region-context", "1", "--max-regions", "1"],
    )

    assert completed.exit_code == 1
    payload = json.loads(completed.output)
    assert payload == match_result_payload(result, region_context=1, max_regions=1)
    assert payload["regions"][0]["target_bytes"]["address_start"] == 0x401001


def test_region_hints_are_cautious_and_composable() -> None:
    hints = _region_hints(
        ("fld dword [ebp-0x4]", "fstp dword [ebp-0x8]", "jne L10"),
        ("fstp dword [ebp-0x8]", "fld dword [ebp-0x4]", "je L10"),
        masked_unresolved=1,
        masked_mismatches=1,
    )

    assert hints == (
        "reference-mismatch",
        "unresolved-reference",
        "possible-control-flow-shape",
        "possible-x87-lifetime-or-ordering",
        "possible-stack-frame-or-lifetime",
    )


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
    status_row = render_status_rows([status])[0]
    assert status_row[5] == "5/10"
    assert status_row[6] == "5"
    assert status_row[9] == "2/4"
    assert status_row[10] == "0/0/0"
    assert status_row[12] == "branch"
    totals = [
        ImageTotals(
            image="crimsonland.exe",
            function_count=10,
            byte_total=1000,
            matched_functions=0,
            matched_bytes=0,
            fuzzy_weighted_bytes=5.0,
            candidate_functions=1,
            candidate_bytes=10,
            scratch_count=1,
            matched_scratches=0,
        ),
        ImageTotals(
            image="grim.dll",
            function_count=20,
            byte_total=2000,
            matched_functions=0,
            matched_bytes=0,
            fuzzy_weighted_bytes=0.0,
            candidate_functions=0,
            candidate_bytes=0,
            scratch_count=0,
            matched_scratches=0,
        ),
    ]
    assert render_image_total_rows(totals)[0] == (
        "crimsonland.exe",
        "0/10",
        "0/1000",
        "0.0%",
        "5/1000",
        "0.5%",
        "1/10",
        "10/1000",
        "1.0%",
        "0/1",
    )
    assert (
        "all images: 0/30 functions, 0/3000 bytes (0.0%) matched; "
        "5/3000 fuzzy-weighted bytes (0.2%); "
        "1/30 source candidates covering 10/3000 bytes (0.3%); "
        "0/1 scratches verified"
    ) in render_status_table([status], totals)
    assert render_status_summary(totals).startswith(
        "all images: 0/30 functions, 0/3000 bytes (0.0%) matched",
    )
    markdown = render_status_markdown([status], totals)
    assert (
        "| crimsonland.exe | 0/10 | 0/1000 | 0.0% | 5/1000 | 0.5% | "
        "1/10 | 10/1000 | 1.0% | 0/1 |"
    ) in markdown
    assert "Fuzzy-weighted alignment is **5/3000** code bytes (**0.2%**)." in markdown
    assert "Candidate coverage includes exact matches and WIPs" in markdown
    assert "## crimsonland.exe" in markdown
    assert "## grim.dll" in markdown
    assert (
        "| wip | foo | 0x00401000 | 10 | 5/10 | 5 | 5/4 | 50.00% | "
        "2/4 | 0/0/0 |  | branch |"
    ) in markdown


def test_collect_triage_rows_joins_scratches_by_address(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = FunctionManifest(
        image_name="crimsonland.exe",
        image_base=0x401000,
        functions=(
            FunctionSymbol(name="recovered_foo", address=0x401000, end=0x401003, size=3),
            FunctionSymbol(name="bar", address=0x401010, end=0x401013, size=3),
        ),
    )
    config = ScratchConfig(
        directory=Path("scratches/address_probe"),
        function="0x00401000",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2 /GB /W3 /GR-",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="address identity",
    )
    statuses = [
        ScratchStatus(
            config=config,
            address=0x401000,
            target_size=3,
            ratio=0.5,
            prefix_instructions=1,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        ),
        ScratchStatus(
            config=replace(config, directory=Path("scratches/stale_name"), function="old_foo"),
            address=0x401000,
            target_size=3,
            ratio=0.8,
            prefix_instructions=1,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        ),
    ]

    monkeypatch.setattr("crimson.match.load_function_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr(
        "crimson.match.load_image",
        lambda *args, **kwargs: LoadedImage(mapped=b"\xc3" * 0x20, image_base=0x401000, size_of_image=0x20),
    )

    rows = collect_triage_rows(statuses, images=("crimsonland.exe",))

    assert [(row.function, row.state) for row in rows] == [
        ("recovered_foo", "wip"),
        ("bar", "missing"),
    ]
    assert rows[0].scratch_count == 2
    assert rows[0].best_status is statuses[1]
    assert rows[0].fuzzy_weighted_bytes == pytest.approx(2.4)
    assert rows[0].fuzzy_gap_bytes == pytest.approx(0.6)
    assert triage_row_payload(rows[0])["best_scratch"]["function"] == "old_foo"
    assert render_triage_rows(rows)[0][2] == "recovered_foo"
    assert sort_triage_rows(rows, sort_by="fuzzy-gap")[0].function == "bar"


def test_triage_command_filters_and_emits_json(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        TriageRow(
            image="crimsonland.exe",
            function="large_missing",
            address=0x401000,
            target_size=100,
            state="missing",
            exact_bytes=0,
            fuzzy_weighted_bytes=0.0,
            candidate_bytes=0,
            scratch_count=0,
        ),
        TriageRow(
            image="crimsonland.exe",
            function="small_missing",
            address=0x401100,
            target_size=5,
            state="missing",
            exact_bytes=0,
            fuzzy_weighted_bytes=0.0,
            candidate_bytes=0,
            scratch_count=0,
        ),
    ]
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_scratch_statuses", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_triage_rows", lambda *args, **kwargs: rows)

    completed = CliRunner().invoke(
        match_app,
        ["triage", "--state", "missing", "--min-bytes", "10", "--limit", "1", "--json"],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    assert payload["summary"]["row_count"] == 1
    assert payload["rows"][0]["function"] == "large_missing"


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


def test_source_probe_uses_temporary_shadow_without_touching_scratch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = scratch / "scratch.cpp"
    source.write_text("baseline\n", encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
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
    observed_directories: list[Path] = []

    def fake_evaluate(probe_config: ScratchConfig, match_root: Path) -> ScratchStatus:
        del match_root
        observed_directories.append(probe_config.directory)
        text = (probe_config.directory / probe_config.source).read_text(encoding="utf-8")
        ratio = 0.75 if text == "variant\n" else 0.5
        return ScratchStatus(
            config=probe_config,
            address=0x401000,
            target_size=100,
            ratio=ratio,
            prefix_instructions=2,
            target_instructions=10,
            candidate_instructions=10,
            error=None,
        )

    monkeypatch.setattr("crimson.match.evaluate_scratch", fake_evaluate)

    result = evaluate_source_probe(config, "variant\n", match_root=tmp_path, label="scalar-copy")

    assert source.read_text(encoding="utf-8") == "baseline\n"
    assert result.fuzzy_delta_bytes == 25
    assert result.ratio_delta == pytest.approx(0.25)
    assert result.label == "scalar-copy"
    assert observed_directories[0] == scratch
    assert observed_directories[1] != scratch
    assert not observed_directories[1].exists()
    assert "delta: match=+25.00% fuzzy=+25" in render_probe_result(result)


def test_probe_command_records_jsonl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "scratch.cpp").write_text("baseline\n", encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=foo\n", encoding="utf-8")
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
    baseline = ScratchStatus(
        config=config,
        address=0x401000,
        target_size=10,
        ratio=0.5,
        prefix_instructions=1,
        target_instructions=4,
        candidate_instructions=4,
        error=None,
    )
    probe = replace(baseline, config=replace(config, directory=Path("/tmp/shadow")), ratio=0.75)
    result = ProbeResult(baseline=baseline, probe=probe, source_sha256="abc", label="trial")
    monkeypatch.setattr("crimson.cli.match.matchlib.evaluate_source_probe", lambda *args, **kwargs: result)

    completed = CliRunner().invoke(
        match_app,
        ["probe", str(scratch), "--stdin", "--label", "trial", "--record", "--json"],
        input="variant\n",
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    assert payload["delta"]["fuzzy_weighted_bytes"] == 2.5
    assert payload["recorded_to"] == str(scratch / "experiments.jsonl")
    recorded = json.loads((scratch / "experiments.jsonl").read_text(encoding="utf-8"))
    assert recorded["recorded_at"].endswith("+00:00")
    assert recorded["label"] == "trial"
    assert (scratch / "scratch.cpp").read_text(encoding="utf-8") == "baseline\n"


def test_profile_matrix_deduplicates_and_ranks_honest_matches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = ScratchConfig(
        directory=tmp_path,
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )

    def fake_evaluate(profile: ScratchConfig, match_root: Path) -> ScratchStatus:
        del match_root
        exact = profile.compiler == "msvc6.5pp" and profile.cflags == "/O1"
        return ScratchStatus(
            config=profile,
            address=0x401000,
            target_size=20,
            ratio=1.0 if exact else 0.75,
            prefix_instructions=5 if exact else 2,
            target_instructions=5,
            candidate_instructions=5,
            error=None,
            masked_ok=2 if exact else 1,
        )

    monkeypatch.setattr("crimson.match.evaluate_scratch", fake_evaluate)

    statuses = evaluate_profile_matrix(
        config,
        compilers=("msvc6.5", "msvc6.5pp", "msvc6.5"),
        cflags=("/O2", "/O1", "/O2"),
        match_root=tmp_path,
    )

    assert len(statuses) == 4
    ranked = sort_profile_statuses(statuses)
    assert (ranked[0].config.compiler, ranked[0].config.cflags, ranked[0].state) == (
        "msvc6.5pp",
        "/O1",
        "match",
    )
    assert "msvc6.5pp" in render_profile_table(statuses)


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
            fuzzy_weighted_bytes=4.5,
            candidate_functions=2,
            candidate_bytes=6,
            scratch_count=3,
            matched_scratches=2,
        ),
        ImageTotals(
            image="grim.dll",
            function_count=1,
            byte_total=2,
            matched_functions=0,
            matched_bytes=0,
            fuzzy_weighted_bytes=0.0,
            candidate_functions=0,
            candidate_bytes=0,
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


def test_collect_status_can_limit_evaluation_to_selected_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    selected = tmp_path / "scratches" / "selected"
    ignored = tmp_path / "scratches" / "ignored"
    for scratch, function in ((selected, "selected"), (ignored, "ignored")):
        scratch.mkdir(parents=True)
        (scratch / "scratch.conf").write_text(f"FUNCTION={function}\n", encoding="utf-8")
        (scratch / "scratch.cpp").write_text(
            f'extern "C" void {function}() {{}}\n',
            encoding="utf-8",
        )

    manifest = FunctionManifest(
        image_name="crimsonland.exe",
        image_base=0x401000,
        functions=(
            FunctionSymbol(name="selected", address=0x401000, end=0x401001, size=1),
            FunctionSymbol(name="ignored", address=0x401001, end=0x401002, size=1),
        ),
    )
    compiled: list[str] = []

    monkeypatch.setattr("crimson.match.load_function_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr(
        "crimson.match.load_image",
        lambda *args, **kwargs: LoadedImage(
            mapped=b"\xc3\xc3",
            image_base=0x401000,
            size_of_image=2,
        ),
    )

    def fake_compile(
        config: ScratchConfig,
        match_root: Path,
        *,
        include_resolver: _ScratchIncludeResolver | None = None,
    ) -> Path:
        compiled.append(config.function)
        return config.directory / "scratch.obj"

    monkeypatch.setattr("crimson.match.compile_scratch", fake_compile)
    monkeypatch.setattr("crimson.match.parse_coff_object", lambda data: object())
    monkeypatch.setattr(
        "crimson.match.extract_object_function",
        lambda obj, symbol: ObjectFunction(name="selected", data=b"\xc3", relocation_offsets=frozenset()),
    )
    monkeypatch.setattr(Path, "read_bytes", lambda self: b"")

    statuses = collect_scratch_statuses(
        tmp_path,
        jobs=1,
        directories=[selected],
    )

    assert [status.config.function for status in statuses] == ["selected"]
    assert compiled == ["selected"]


def test_inspect_command_evaluates_only_target_scratches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratches" / "target"
    config = ScratchConfig(
        directory=scratch,
        function="game_is_full_version",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )
    observed_directories: list[Path] = []

    def fake_inspect(*args: object, **kwargs: object) -> dict[str, object]:
        return {
            "image": "crimsonland.exe",
            "address": 0x0041DF40,
            "scratches": [],
        }

    def fake_collect(*args: object, **kwargs: object) -> list[ScratchStatus]:
        directories = kwargs["directories"]
        assert isinstance(directories, list)
        observed_directories.extend(
            directory
            for directory in directories
            if isinstance(directory, Path)
        )
        return []

    monkeypatch.setattr("crimson.cli.match.matchlib.inspect_match_function", fake_inspect)
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.find_scratch_configs_for_target",
        lambda *args, **kwargs: [config],
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_scratch_statuses", fake_collect)

    completed = CliRunner().invoke(
        match_app,
        ["inspect", "game_is_full_version", "--match-root", str(tmp_path), "--max-regions", "0", "--json"],
    )

    assert completed.exit_code == 0
    assert observed_directories == [scratch]


def test_match_shard_plan_is_deterministic_balanced_and_disjoint(tmp_path: Path) -> None:
    rows = [
        TriageRow(
            image="crimsonland.exe",
            function=f"target_{index}",
            address=0x401000 + index * 0x10,
            target_size=size,
            state="missing",
            exact_bytes=0,
            fuzzy_weighted_bytes=0.0,
            candidate_bytes=0,
            scratch_count=0,
        )
        for index, size in enumerate((100, 80, 30, 20))
    ]

    plan = build_match_shard_plan(
        rows,
        workers=2,
        scope="port",
        base_commit="a" * 40,
        match_root=tmp_path,
    )
    repeated = build_match_shard_plan(
        list(reversed(rows)),
        workers=2,
        scope="port",
        base_commit="a" * 40,
        match_root=tmp_path,
    )
    targets = [
        target
        for assignment in plan["assignments"]
        for target in assignment["targets"]
    ]

    assert plan == repeated
    assert [assignment["estimated_gap_bytes"] for assignment in plan["assignments"]] == [120.0, 110.0]
    assert len({(target["image"], target["address"]) for target in targets}) == 4
    assert len({target["scratch"] for target in targets}) == 4


def test_match_shard_plan_writes_worker_claims(tmp_path: Path) -> None:
    row = TriageRow(
        image="crimsonland.exe",
        function="game_is_full_version",
        address=0x0041DF40,
        target_size=6,
        state="missing",
        exact_bytes=0,
        fuzzy_weighted_bytes=0.0,
        candidate_bytes=0,
        scratch_count=0,
    )
    plan = build_match_shard_plan(
        [row],
        workers=2,
        scope="port",
        base_commit="a" * 40,
        match_root=tmp_path,
    )

    output_directory = tmp_path / ".cache" / "shards"
    output_directory.mkdir(parents=True)
    stale_claim = output_directory / "worker-99.json"
    stale_claim.write_text("{}\n", encoding="utf-8")
    unrelated = output_directory / "notes.json"
    unrelated.write_text("{}\n", encoding="utf-8")

    plan_path, claim_paths = write_match_shard_plan(plan, output_directory)

    assert json.loads(plan_path.read_text(encoding="utf-8")) == plan
    assert len(claim_paths) == 2
    assert json.loads(claim_paths[0].read_text(encoding="utf-8"))["kind"] == WORKER_CLAIM_KIND
    assert json.loads(claim_paths[1].read_text(encoding="utf-8"))["targets"] == []
    assert not stale_claim.exists()
    assert unrelated.exists()
    assert validate_match_claim(plan, match_root=tmp_path, scope="port") == []


def test_match_claim_rejects_duplicate_targets(tmp_path: Path) -> None:
    target = {
        "image": "crimsonland.exe",
        "function": "game_is_full_version",
        "address": 0x0041DF40,
        "target_bytes": 6,
        "state": "missing",
        "fuzzy_gap_bytes": 6.0,
    }
    plan = {
        "schema": 1,
        "kind": SHARD_PLAN_KIND,
        "scope": "port",
        "base_commit": "a" * 40,
        "workers": 2,
        "target_count": 2,
        "filters": {},
        "assignments": [
            {
                "worker": "worker-01",
                "claim": "worker-01.json",
                "estimated_gap_bytes": 6.0,
                "targets": [{**target, "scratch": "scratches/one"}],
            },
            {
                "worker": "worker-02",
                "claim": "worker-02.json",
                "estimated_gap_bytes": 6.0,
                "targets": [{**target, "scratch": "scratches/two"}],
            },
        ],
    }

    errors = validate_match_claim(plan, match_root=tmp_path, scope="port")

    assert errors == [
        "duplicate claim crimsonland.exe:0x0041df40: worker-01, worker-02",
    ]


def test_claimed_scratch_changes_reject_out_of_claim_edits(tmp_path: Path) -> None:
    claim = {
        "schema": 1,
        "kind": WORKER_CLAIM_KIND,
        "scope": "port",
        "base_commit": "a" * 40,
        "worker": "worker-01",
        "targets": [
            {
                "image": "crimsonland.exe",
                "function": "game_is_full_version",
                "address": 0x0041DF40,
                "scratch": "scratches/allowed",
            },
        ],
    }

    assert claimed_scratch_paths(claim) == {"scratches/allowed"}
    assert validate_claimed_changes(
        claim,
        [
            "scratches/allowed/scratch.cpp",
            "scratches/not-allowed/scratch.cpp",
            "src/crimson/match.py",
        ],
        match_root=tmp_path,
    ) == [
        "scratch change outside claims: scratches/not-allowed",
        "change outside claims: src/crimson/match.py",
    ]
    assert validate_claimed_changes(
        claim,
        ["STATUS.md"],
        match_root=tmp_path,
        allowed_paths=["STATUS.md"],
    ) == []


def test_matching_workspace_rejects_duplicate_target_directories(tmp_path: Path) -> None:
    for name in ("one", "two"):
        scratch = tmp_path / "scratches" / name
        scratch.mkdir(parents=True)
        (scratch / "scratch.conf").write_text(
            "FUNCTION=game_is_full_version\n",
            encoding="utf-8",
        )

    assert validate_matching_workspace(tmp_path, scope="port") == [
        "duplicate target crimsonland.exe:0x0041df40: one, two",
    ]


def test_matching_workspace_rejects_scratch_files_without_config(tmp_path: Path) -> None:
    scratch = tmp_path / "scratches" / "orphan"
    scratch.mkdir(parents=True)
    (scratch / "scratch.cpp").write_text("void orphan() {}\n", encoding="utf-8")

    assert validate_matching_workspace(tmp_path, scope="port") == [
        "orphan: scratch files require scratch.conf",
    ]


def test_worker_check_writes_ignored_report_without_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    claim_path = tmp_path / "worker-01.json"
    claim_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": WORKER_CLAIM_KIND,
                "scope": "port",
                "base_commit": "a" * 40,
                "worker": "worker-01",
                "targets": [
                    {
                        "image": "crimsonland.exe",
                        "function": "game_is_full_version",
                        "address": 0x0041DF40,
                        "target_bytes": 6,
                        "state": "missing",
                        "fuzzy_gap_bytes": 6.0,
                        "scratch": "scratches/game_is_full_version",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "crimson.cli.match._batch_changed_paths",
        lambda base_commit=None: [],
    )

    completed = CliRunner().invoke(
        match_app,
        ["worker-check", str(claim_path), "--match-root", str(tmp_path), "--json"],
    )

    assert completed.exit_code == 0
    report = json.loads(completed.output)
    assert report["summary"]["unhandled"] == 1
    assert report["targets"][0]["handled"] is False
    assert not (tmp_path / "STATUS.md").exists()
    assert (tmp_path / ".cache" / "reports" / "worker-01.json").exists()
