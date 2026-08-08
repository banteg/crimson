from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import (
    DEFAULT_FUNCTIONS_PATH,
    SHARD_PLAN_KIND,
    VC6_LOCAL_JUMP_TABLE_KEY,
    VC6_LOCAL_SWITCH_PARTITION_KEY,
    VC6_PROVEN_COPY_LOAD_KEY,
    VC6_SINGLE_DELETE_UNWIND_KEY,
    VC6_UNWIND_ONLY_KEY,
    WORKER_CLAIM_KIND,
    WORKER_OUTCOME_FILE,
    WORKER_OUTCOME_KIND,
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
    NativeLinkStatus,
    ObjectFunction,
    ObjectRelocationReference,
    ProbeResult,
    ReferenceCatalog,
    ScratchConfig,
    ScratchStatus,
    TriageRow,
    _coff_local_jump_table_key,
    _coff_vc6_single_delete_unwind_key,
    _coff_vc6_unwind_only_key,
    _exception_summary,
    _image_vc6_unwind_only_key,
    _import_thunk_object_bytes,
    _local_switch_partition_key,
    _region_hints,
    _scratch_build_key,
    _ScratchIncludeResolver,
    address_in_matching_scope,
    apply_naming_suggestions,
    build_compiler_scan_rows,
    build_match_shard_plan,
    claimed_scratch_paths,
    collect_image_totals,
    collect_naming_debt,
    collect_native_link_statuses,
    collect_scratch_statuses,
    collect_triage_rows,
    common_prefix_length,
    compile_scratch,
    compiler_scan_row_payload,
    compiler_scan_summary,
    diff_region_payload,
    diff_regions,
    disassemble_normalized_function,
    evaluate_profile_matrix,
    evaluate_source_overlay,
    evaluate_source_probe,
    extract_object_function,
    inspect_match_function,
    is_analyzer_placeholder,
    load_function_manifest,
    load_matching_scope,
    load_matching_scope_function_dispositions,
    load_name_map_rows,
    load_naming_hints,
    load_reference_catalog,
    load_scratch_config,
    match_function,
    match_result_payload,
    matching_scope_function_disposition_payloads,
    naming_debt_payload,
    native_json_program_sha256,
    normalize_function,
    parse_coff_object,
    prune_placeholder_aliases,
    render_compiler_scan_rows,
    render_image_total_rows,
    render_naming_debt_summary,
    render_naming_debt_table,
    render_native_link_status_markdown,
    render_probe_result,
    render_profile_table,
    render_status_markdown,
    render_status_rows,
    render_status_summary,
    render_status_table,
    render_triage_rows,
    repair_provider_comments,
    resolve_function,
    resolve_function_with_scope_hint,
    rewrite_placeholder_references,
    run_match,
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


def build_archive_members(members: list[tuple[str, bytes]]) -> bytes:
    def member(name: bytes, data: bytes) -> bytes:
        header = (
            name.ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"100644".ljust(8)
            + str(len(data)).encode().ljust(10)
            + b"`\n"
        )
        return header + data + (b"\n" if len(data) & 1 else b"")

    long_names = b""
    encoded_members: list[bytes] = []
    for member_name, payload in members:
        offset = len(long_names)
        long_names += f"{member_name}/\n".encode()
        encoded_members.append(member(f"/{offset}".encode(), payload))
    return b"!<arch>\n" + member(b"//", long_names) + b"".join(encoded_members)


def build_archive(member_name: str, payload: bytes) -> bytes:
    return build_archive_members([(member_name, payload)])


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


def test_resolve_function_reports_scope_exclusion() -> None:
    function = FunctionSymbol(name="codec_helper", address=0x10025AEC, end=0x10025BF5, size=265)
    scoped = FunctionManifest(image_name="grim.dll", image_base=0x10000000, functions=())
    unscoped = FunctionManifest(
        image_name="grim.dll",
        image_base=0x10000000,
        functions=(function,),
    )

    with pytest.raises(
        ValueError,
        match=r"outside matching scope 'port'.*retry with --scope all",
    ):
        resolve_function_with_scope_hint(
            scoped,
            "0x10025aec",
            scope="port",
            unscoped_manifest=unscoped,
        )


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


def test_load_manifest_excludes_curated_false_function(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1003A4F4","end":"0x1003A4F7","name":"nullsub_7","size":3},'
        '{"address":"0x1003A500","end":"0x1003A501","name":"real_function","size":1}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1003A4F4",'
        '"name":"nullsub_7","exclude":true}]\n',
        encoding="utf-8",
    )

    manifest = load_function_manifest(
        functions_path,
        metadata_path=None,
        image_name="grim.dll",
        name_map_path=name_map_path,
    )

    assert [function.name for function in manifest.functions] == ["real_function"]


def test_load_manifest_rejects_stale_curated_exclusion(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text("[]\n", encoding="utf-8")
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1003A4F4",'
        '"name":"nullsub_7","exclude":true}]\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exclusions are absent.*0x1003a4f4"):
        load_function_manifest(
            functions_path,
            metadata_path=None,
            image_name="grim.dll",
            name_map_path=name_map_path,
        )


def test_load_manifest_rejects_duplicate_curated_address(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1000A310","end":"0x1000A323",'
        '"name":"sub_1000A310","size":19}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1000A310","name":"recovered_name"},'
        '{"program":"grim.dll","address":"0x1000A310","name":"stale_name"}]\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate name-map entry.*grim.dll:0x1000a310"):
        load_function_manifest(
            functions_path,
            metadata_path=None,
            image_name="grim.dll",
            name_map_path=name_map_path,
        )


def test_load_manifest_applies_curated_end_override(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1002047C","end":"0x100204A1",'
        '"name":"png_read_data","size":37},'
        '{"address":"0x100204A4","end":"0x100204E3",'
        '"name":"sub_100204A4","size":63}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1002047C",'
        '"end":"0x100204A4","name":"png_read_data"}]\n',
        encoding="utf-8",
    )

    manifest = load_function_manifest(
        functions_path,
        metadata_path=None,
        image_name="grim.dll",
        name_map_path=name_map_path,
    )

    function, start, end = resolve_function(manifest, "png_read_data")
    assert function.size == 40
    assert start == 0x1002047C
    assert end == 0x100204A4


def test_load_manifest_rejects_overlapping_curated_end_override(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x1002047C","end":"0x100204A1",'
        '"name":"png_read_data","size":37},'
        '{"address":"0x100204A4","end":"0x100204E3",'
        '"name":"sub_100204A4","size":63}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"grim.dll","address":"0x1002047C",'
        '"end":"0x100204A5","name":"png_read_data"}]\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="curated function.*overlaps"):
        load_function_manifest(
            functions_path,
            metadata_path=None,
            image_name="grim.dll",
            name_map_path=name_map_path,
        )


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
        resolve_function(manifest, "dx_get_version_fallback_from_files")
    with pytest.raises(ValueError, match="not found"):
        resolve_function(manifest, "reg_read_dword_default")
    with pytest.raises(ValueError, match="not found"):
        resolve_function(manifest, "float_near_equal")

    grim_manifest = load_function_manifest(
        Path("analysis/ida/raw/grim.dll/functions.json"),
        metadata_path=Path("analysis/ida/raw/grim.dll/metadata.json"),
        image_name="grim.dll",
        scope="port",
    )
    assert resolve_function(grim_manifest, "grim_config_defaults_init")[0].address == 0x10001710
    assert resolve_function(grim_manifest, "grim_apply_render_state")[0].address == 0x10004520
    assert resolve_function(grim_manifest, "grim_jaz_decompress_payload")[0].address == 0x1000A880
    with pytest.raises(ValueError, match="not found"):
        resolve_function(grim_manifest, "grim_window_proc")
    with pytest.raises(ValueError, match="not found"):
        resolve_function(grim_manifest, "grim_keyboard_poll")
    with pytest.raises(ValueError, match="not found"):
        resolve_function(grim_manifest, "sprintf")
    with pytest.raises(ValueError, match="not found"):
        resolve_function(grim_manifest, "grim_format_info_lookup")

    all_manifest = load_function_manifest(DEFAULT_FUNCTIONS_PATH, scope="all")
    assert resolve_function(all_manifest, "dx_get_version_fallback_from_files")[0].address == 0x0041CFE0
    all_grim_manifest = load_function_manifest(
        Path("analysis/ida/raw/grim.dll/functions.json"),
        metadata_path=Path("analysis/ida/raw/grim.dll/metadata.json"),
        image_name="grim.dll",
        scope="all",
    )
    assert resolve_function(all_grim_manifest, "grim_window_proc")[0].address == 0x100033B0


def test_port_scope_has_audited_function_dispositions() -> None:
    dispositions = matching_scope_function_disposition_payloads("port")
    image_counts = {
        image: sum(row["image"] == image for row in dispositions)
        for image in ("crimsonland.exe", "grim.dll")
    }

    assert image_counts == {"crimsonland.exe": 8, "grim.dll": 49}
    assert not address_in_matching_scope(
        "crimsonland.exe",
        0x0041CFE0,
        scope="port",
    )
    assert not address_in_matching_scope("grim.dll", 0x100033B0, scope="port")
    assert not address_in_matching_scope("grim.dll", 0x10009A50, scope="port")
    assert address_in_matching_scope("grim.dll", 0x10001710, scope="port")
    assert address_in_matching_scope("grim.dll", 0x10004520, scope="port")
    assert address_in_matching_scope("grim.dll", 0x100033B0, scope="all")
    assert {
        (row["image"], row["function"], row["disposition"])
        for row in dispositions
        if row["address"] in {0x0041CFE0, 0x100033B0, 0x10009A50}
    } == {
        (
            "crimsonland.exe",
            "dx_get_version_fallback_from_files",
            "platform-replaced",
        ),
        ("grim.dll", "grim_window_proc", "platform-replaced"),
        ("grim.dll", "grim_jaz_jpeg_create_decompress", "third-party"),
    }


def test_matching_scope_function_dispositions_are_validated(tmp_path: Path) -> None:
    scope_path = tmp_path / "matching_scope.json"

    def write_scope(rows: list[dict[str, str]]) -> None:
        scope_path.write_text(
            json.dumps(
                {
                    "schema": 2,
                    "default": "port",
                    "scopes": {
                        "port": {
                            "programs": {
                                "test.exe": [
                                    {
                                        "start": "0x00401000",
                                        "end": "0x00402000",
                                        "owner": "game",
                                    },
                                ],
                            },
                            "function_dispositions": {"test.exe": rows},
                        },
                    },
                },
            ),
            encoding="utf-8",
        )

    valid: dict[str, str] = {
        "address": "0x00401100",
        "name": "platform_probe",
        "disposition": "platform-replaced",
        "reason": "host backend",
    }
    write_scope([valid])
    assert load_matching_scope("port", path=scope_path)["test.exe"][0].owner == "game"
    assert load_matching_scope_function_dispositions(
        "port",
        path=scope_path,
    )["test.exe"][0].name == "platform_probe"

    write_scope([{**valid, "disposition": "third-party"}])
    assert (
        load_matching_scope_function_dispositions(
            "port",
            path=scope_path,
        )["test.exe"][0].disposition
        == "third-party"
    )

    write_scope([valid, valid])
    with pytest.raises(ValueError, match="duplicate .* function disposition"):
        load_matching_scope_function_dispositions("port", path=scope_path)

    write_scope([{**valid, "address": "0x00403000"}])
    with pytest.raises(ValueError, match="outside owned ranges"):
        load_matching_scope_function_dispositions("port", path=scope_path)

    write_scope([{**valid, "disposition": "guess"}])
    with pytest.raises(ValueError, match="unknown function disposition"):
        load_matching_scope_function_dispositions("port", path=scope_path)

    write_scope([{**valid, "reason": ""}])
    with pytest.raises(ValueError, match="needs a reason"):
        load_matching_scope_function_dispositions("port", path=scope_path)


def test_matching_scope_disposition_name_must_match_manifest(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401100","end":"0x00401110",'
        '"name":"observed_name","size":16,"external":false}]\n',
        encoding="utf-8",
    )
    scope_path = tmp_path / "matching_scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "schema": 2,
                "default": "port",
                "scopes": {
                    "port": {
                        "programs": {
                            "test.exe": [
                                {
                                    "start": "0x00401000",
                                    "end": "0x00402000",
                                    "owner": "game",
                                },
                            ],
                        },
                        "function_dispositions": {
                            "test.exe": [
                                {
                                    "address": "0x00401100",
                                    "name": "stale_name",
                                    "disposition": "platform-replaced",
                                    "reason": "host backend",
                                },
                            ],
                        },
                    },
                },
            },
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not match manifest name"):
        load_function_manifest(
            functions_path,
            metadata_path=None,
            image_name="test.exe",
            name_map_path=None,
            scope="port",
            scope_path=scope_path,
        )


def test_matching_workspace_stays_inside_port_scope() -> None:
    assert validate_matching_workspace(scope="port") == []


def test_scratch_config_parses_recovery_and_residuals(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo RECOVERY=semantic-complete RESIDUAL=compiler,references "
        "AUTO_INLINE_OFF=select_colors,create_index\n",
        encoding="utf-8",
    )

    config = load_scratch_config(tmp_path)

    assert config.recovery == "semantic-complete"
    assert config.residuals == ("compiler", "references")
    assert config.auto_inline_off == ("select_colors", "create_index")


def test_scratch_config_rejects_invalid_auto_inline_identifier(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo AUTO_INLINE_OFF='valid,bad-name'\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid AUTO_INLINE_OFF identifiers 'bad-name'"):
        load_scratch_config(tmp_path)


def test_scratch_config_parses_pinned_archive_member(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo ARCHIVE=provider.lib "
        "ARCHIVE_MEMBER='obj\\i386\\foo.obj' "
        f"ARCHIVE_SHA256={'a' * 64} SYMBOL=_foo ARCHIVE_EXTENT=section-tail\n",
        encoding="utf-8",
    )

    config = load_scratch_config(tmp_path)

    assert config.source == ""
    assert config.archive == "provider.lib"
    assert config.archive_member == r"obj\i386\foo.obj"
    assert config.archive_sha256 == "a" * 64
    assert config.archive_extent == "section-tail"


def test_scratch_config_parses_archive_end_symbol(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo ARCHIVE=provider.lib "
        "ARCHIVE_MEMBER='obj\\i386\\foo.obj' "
        f"ARCHIVE_SHA256={'a' * 64} SYMBOL=_foo ARCHIVE_END_SYMBOL=_foo_end\n",
        encoding="utf-8",
    )

    config = load_scratch_config(tmp_path)

    assert config.archive_end_symbol == "_foo_end"


def test_scratch_config_parses_archive_symbol_size(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo ARCHIVE=provider.lib "
        "ARCHIVE_MEMBER='obj\\i386\\foo.obj' "
        f"ARCHIVE_SHA256={'a' * 64} SYMBOL='$L123' ARCHIVE_SIZE=9\n",
        encoding="utf-8",
    )

    config = load_scratch_config(tmp_path)

    assert config.archive_size == 9


def test_scratch_config_parses_structural_import_thunk(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=sprintf IMPORT_THUNK=sprintf\n",
        encoding="utf-8",
    )

    config = load_scratch_config(tmp_path)

    assert config.import_thunk == "sprintf"
    assert config.compiler == "linker-import"
    assert config.cflags == ""
    assert config.source == ""


def test_scratch_config_rejects_import_thunk_source(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=sprintf IMPORT_THUNK=sprintf SOURCE=scratch.cpp\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cannot combine IMPORT_THUNK and SOURCE"):
        load_scratch_config(tmp_path)


@pytest.mark.parametrize(
    "config, message",
    (
        ("FUNCTION=foo ARCHIVE_MEMBER=foo.obj", "without ARCHIVE"),
        ("FUNCTION=foo ARCHIVE_END_SYMBOL=_foo_end", "without ARCHIVE"),
        ("FUNCTION=foo ARCHIVE_SIZE=9", "without ARCHIVE"),
        ("FUNCTION=foo ARCHIVE_EXTENT=section-tail", "without ARCHIVE"),
        ("FUNCTION=foo ARCHIVE=provider.lib", "must set ARCHIVE_MEMBER, ARCHIVE_SHA256, SYMBOL"),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo SOURCE=foo.c",
            "cannot combine ARCHIVE and SOURCE",
        ),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo AUTO_INLINE_OFF=foo",
            "cannot combine ARCHIVE and AUTO_INLINE_OFF",
        ),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo ARCHIVE_EXTENT=bogus",
            "invalid ARCHIVE_EXTENT",
        ),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo "
            "ARCHIVE_EXTENT=section-tail ARCHIVE_END_SYMBOL=_foo_end",
            "cannot combine ARCHIVE_END_SYMBOL",
        ),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo "
            "ARCHIVE_EXTENT=section-tail ARCHIVE_SIZE=9",
            "cannot combine ARCHIVE_SIZE",
        ),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo "
            "ARCHIVE_END_SYMBOL=_foo_end ARCHIVE_SIZE=9",
            "cannot combine ARCHIVE_SIZE",
        ),
        (
            "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
            + f"ARCHIVE_SHA256={'a' * 64} SYMBOL=foo ARCHIVE_SIZE=0",
            "ARCHIVE_SIZE must be positive",
        ),
    ),
)
def test_scratch_config_rejects_invalid_archive_mode(
    tmp_path: Path,
    config: str,
    message: str,
) -> None:
    (tmp_path / "scratch.conf").write_text(config, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_scratch_config(tmp_path)


def test_scratch_config_rejects_unknown_fields(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text(
        "FUNCTION=foo MSVC_VER=msvc6.5pp\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown field 'MSVC_VER'.*COMPILER"):
        load_scratch_config(tmp_path)


def test_scratch_config_rejects_malformed_assignments(tmp_path: Path) -> None:
    (tmp_path / "scratch.conf").write_text("FUNCTION=foo typo\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid assignment 'typo'"):
        load_scratch_config(tmp_path)


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


def test_load_reference_catalog_drops_superseded_raw_function_names(tmp_path: Path) -> None:
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x0046150a","name":"crt_flushall"},'
        '{"address":"0x00461501","name":"sub_00461501"}]\n',
        encoding="utf-8",
    )
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        '[{"program":"crimsonland.exe","address":"0x00461501",'
        '"name":"crt_flushall","aliases":["__flushall"]},'
        '{"program":"crimsonland.exe","address":"0x0046150a",'
        '"name":"crt_flsall","aliases":["_flsall"]}]\n',
        encoding="utf-8",
    )
    manifest = FunctionManifest(
        image_name="crimsonland.exe",
        image_base=0x00400000,
        functions=(
            FunctionSymbol("crt_flushall", 0x00461501, 0x0046150A, 9),
            FunctionSymbol("crt_flsall", 0x0046150A, 0x00461520, 0x16),
        ),
    )

    catalog = load_reference_catalog(
        manifest,
        functions_path=functions_path,
        data_map_path=tmp_path / "missing-data-map.json",
        name_map_path=name_map_path,
    )

    assert "name:crt_flushall" not in catalog.keys_for_address(0x0046150A)
    assert catalog.keys_for_object_reference("crt_flushall", 0) == (
        "name:crt_flushall",
        "address:0x00461501",
    )


def test_reference_catalog_prefers_decorated_member_scope(tmp_path: Path) -> None:
    surface = "?Lock@CD3DXLockSurface@@QAEJXZ"
    volume = "?Lock@CD3DXLockVolume@@QAEJXZ"
    name_map_path = tmp_path / "name_map.json"
    name_map_path.write_text(
        "["
        '{"program":"grim.dll","address":"0x100161BB",'
        f'"name":"surface_lock","aliases":["{surface}"]}},'
        '{"program":"grim.dll","address":"0x100165D3",'
        f'"name":"volume_lock","aliases":["{volume}"]}}'
        "]\n",
        encoding="utf-8",
    )
    manifest = FunctionManifest(image_name="grim.dll", image_base=0x10000000, functions=())

    catalog = load_reference_catalog(
        manifest,
        functions_path=tmp_path / "missing-functions.json",
        data_map_path=tmp_path / "missing-data-map.json",
        name_map_path=name_map_path,
    )

    assert catalog.knows_name(surface)
    assert catalog.knows_name(volume)
    assert not catalog.knows_name("Lock")
    assert "address:0x100161bb" in catalog.keys_for_object_reference(surface, 0)
    assert "address:0x100165d3" in catalog.keys_for_object_reference(volume, 0)


def test_reference_catalog_scoped_alias_overrides_decorated_local_variant() -> None:
    configured = "?$S1@?P@??ui_render@@9@4EA"
    emitted = "?$S1@?4??ui_render@@9@4EA"
    wrong_address = 0x4912B0
    target_address = 0x480340
    catalog = ReferenceCatalog(
        {
            wrong_address: (emitted,),
            target_address: ("ui_init_flags",),
        },
        {
            emitted: (wrong_address,),
            "$S1": (wrong_address,),
            "ui_init_flags": (target_address,),
        },
    ).with_object_aliases(((configured, "ui_init_flags"),))

    assert "address:0x00480340" in catalog.keys_for_object_reference(emitted, 0)


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


def test_extract_object_function_keeps_vc_code_packets_in_extent() -> None:
    code = bytes.fromhex("31c0c3b801000000c3")
    obj = CoffObject(
        sections=(CoffSection(".text", code, 0x20, ()),),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "TAG_PACKET_0", 3, 1, 0x20, 3),
            CoffSymbol(2, "TAG_PACKET_1", 8, 1, 0x20, 3),
        ),
    )

    assert extract_object_function(obj, "probe").data == code


def test_extract_object_function_accepts_explicit_code_label() -> None:
    code = bytes.fromhex("31c0c3b800000000c3")
    obj = CoffObject(
        sections=(CoffSection(".text", code, 0x20, ()),),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "$Lhandler", 3, 1, 0, 6),
        ),
    )

    assert extract_object_function(obj, "$Lhandler").data == code[3:]


def test_extract_object_function_collects_relocations() -> None:
    code = bytes.fromhex("a100000000c3")
    obj = parse_coff_object(build_object(code, [("_foo", 0)], [1]))
    function = extract_object_function(obj, "foo")
    assert function.relocation_offsets == frozenset({1})
    assert function.relocation_references[0].symbol_name == "_foo"
    assert function.relocation_references[0].key == "name:foo"


def test_extract_object_function_recovers_implicit_same_section_branch() -> None:
    code = bytes.fromhex("e801000000c3") + bytes.fromhex("31c0c3")
    obj = parse_coff_object(
        build_object(code, [("_caller", 0), ("_callee", 6)], []),
    )

    function = extract_object_function(obj, "caller")

    assert function.data == bytes.fromhex("e801000000c3")
    assert function.relocation_offsets == frozenset({1})
    assert len(function.relocation_references) == 1
    assert function.relocation_references[0].symbol_name == "_callee"
    assert function.relocation_references[0].key == "name:callee"
    disassembly = disassemble_normalized_function(
        function.data,
        relocation_offsets=function.relocation_offsets,
        relocation_references=function.relocation_references,
    )
    assert disassembly[0].text == "call ADDR"
    assert disassembly[0].masked_references[0].keys == ("local:+0x6",)


def test_extract_object_function_recovers_implicit_branch_to_function_tail() -> None:
    code = bytes.fromhex("e804000000c3") + bytes.fromhex("909090c3")
    obj = parse_coff_object(
        build_object(code, [("_caller", 0), ("_callee", 6)], []),
    )

    function = extract_object_function(obj, "caller")

    assert len(function.relocation_references) == 1
    reference = function.relocation_references[0]
    assert reference.symbol_name == "_callee"
    assert reference.addend == 3
    assert reference.key == "name:callee+0x3"


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


def test_extract_object_function_can_include_external_symbol_section_tail() -> None:
    code = bytes.fromhex("31c0c390c3")
    obj = CoffObject(
        sections=(CoffSection(name=".text", data=code, characteristics=0x20, relocations=()),),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "_helper", 3, 1, 0x20, 3),
        ),
    )

    symbol = extract_object_function(obj, "probe")
    section_tail = extract_object_function(obj, "probe", extent="section-tail")

    assert symbol.data == code[:3]
    assert section_tail.data == code


def test_extract_object_function_can_end_at_explicit_code_symbol() -> None:
    code = bytes.fromhex("31c0c390c3c3")
    obj = CoffObject(
        sections=(CoffSection(name=".text", data=code, characteristics=0x20, relocations=()),),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "_local_entry", 3, 1, 0x20, 3),
            CoffSymbol(2, "_probe_end", 5, 1, 0x20, 2),
        ),
    )

    function = extract_object_function(obj, "probe", end_symbol="_probe_end")

    assert function.data == code[:5]
    with pytest.raises(ValueError, match="cannot be combined"):
        extract_object_function(
            obj,
            "probe",
            extent="section-tail",
            end_symbol="_probe_end",
        )


def test_extract_object_function_can_use_explicit_code_label_size() -> None:
    code = bytes.fromhex("31c0c390c3c3")
    obj = CoffObject(
        sections=(CoffSection(name=".text", data=code, characteristics=0x20, relocations=()),),
        symbols=(
            CoffSymbol(0, "$Lhandler", 3, 1, 0, 6),
            CoffSymbol(1, "$Lret", 4, 1, 0, 6),
        ),
    )

    function = extract_object_function(obj, "$Lhandler", size=2)

    assert function.data == code[3:5]
    with pytest.raises(ValueError, match="cannot be combined"):
        extract_object_function(obj, "$Lhandler", end_symbol="$Lret", size=2)
    with pytest.raises(ValueError, match="exceeds section"):
        extract_object_function(obj, "$Lhandler", size=4)


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


def test_normalize_keeps_out_of_image_branch_entry_relative() -> None:
    code = bytes.fromhex("e978563412")

    assert normalize_function(code)[0] == normalize_function(code, base_address=0x445F00)[0]
    assert normalize_function(code)[0] == "jmp R+0x1234567d"


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
    code = (
        bytes.fromhex("c3")
        + bytes.fromhex("8d4900")
        + bytes.fromhex("8db600000000")
        + bytes.fromhex("8dbf00000000")
        + bytes.fromhex("8bf6")
        + (b"\x00" * 4)
        + (b"\x90" * 4)
    )
    assert normalize_function(code) == ("ret",)


def test_normalize_strips_untargeted_padding_after_tail_jump() -> None:
    code = bytes.fromhex("e9000000008da424000000008bff")

    assert normalize_function(
        code,
        relocation_offsets=frozenset({1}),
    ) == ("jmp ADDR",)


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


def test_match_function_materializes_local_dir32_relocation() -> None:
    function_address = 0x401000
    local_target_offset = 6
    target = (
        b"\xb8"
        + struct.pack("<I", function_address + local_target_offset)
        + bytes.fromhex("c3c3")
    )
    candidate = ObjectFunction(
        name="_probe",
        data=bytes.fromhex("b800000000c3c3"),
        relocation_offsets=frozenset({1}),
        relocation_references=(
            ObjectRelocationReference(
                offset=1,
                symbol_name="_helper",
                key="name:helper",
                explained=True,
                local_target_offset=local_target_offset,
                relocation_type=0x06,
            ),
        ),
    )

    result = match_function(
        target,
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0x10000),
        target_va=function_address,
        reference_catalog=ReferenceCatalog({}),
    )
    wrong = match_function(
        b"\xb8" + struct.pack("<I", function_address + local_target_offset + 1) + bytes.fromhex("c3c3"),
        candidate,
        image=LoadedImage(mapped=b"", image_base=0x400000, size_of_image=0x10000),
        target_va=function_address,
        reference_catalog=ReferenceCatalog({}),
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 1
    assert not wrong.exact
    assert wrong.masked_operand_audit.mismatch_count == 1


def test_run_match_forwards_object_boundaries(monkeypatch, tmp_path: Path) -> None:
    observed: list[tuple[str, str | None, int | None]] = []
    manifest = FunctionManifest(
        image_name="game.exe",
        image_base=0x401000,
        functions=(FunctionSymbol(name="probe", address=0x401000, end=0x401001, size=1),),
    )
    obj_path = tmp_path / "probe.obj"
    obj_path.write_bytes(b"object")
    image_path = tmp_path / "game.exe"
    image_path.write_bytes(b"image")

    monkeypatch.setattr("crimson.match.load_function_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr(
        "crimson.match.load_image",
        lambda *args, **kwargs: LoadedImage(b"\xc3", 0x401000, 1),
    )
    monkeypatch.setattr("crimson.match.load_reference_catalog", lambda *args, **kwargs: ReferenceCatalog({}))
    monkeypatch.setattr("crimson.match.parse_coff_object", lambda data: object())

    def fake_extract(
        obj,
        name,
        *,
        extent: str = "symbol",
        end_symbol: str | None = None,
        size: int | None = None,
    ) -> ObjectFunction:
        observed.append((extent, end_symbol, size))
        return ObjectFunction("_probe", b"\xc3", frozenset())

    monkeypatch.setattr("crimson.match.extract_object_function", fake_extract)

    result = run_match(
        obj_path=obj_path,
        function="probe",
        image_path=image_path,
        functions_path=tmp_path / "functions.json",
        metadata_path=tmp_path / "metadata.json",
        symbol_name="_probe",
        object_extent="section-tail",
        scope="all",
    )

    assert result.exact
    assert observed == [("section-tail", None, None)]

    result = run_match(
        obj_path=obj_path,
        function="probe",
        image_path=image_path,
        functions_path=tmp_path / "functions.json",
        metadata_path=tmp_path / "metadata.json",
        symbol_name="_probe",
        object_end_symbol="_probe_end",
        scope="all",
    )

    assert result.exact
    assert observed[-1] == ("symbol", "_probe_end", None)

    result = run_match(
        obj_path=obj_path,
        function="probe",
        image_path=image_path,
        functions_path=tmp_path / "functions.json",
        metadata_path=tmp_path / "metadata.json",
        symbol_name="_probe",
        object_size=9,
        scope="all",
    )

    assert result.exact
    assert observed[-1] == ("symbol", None, 9)


def test_match_function_accepts_first_load_from_proven_vc6_copy_range() -> None:
    image_base = 0x400000
    function_address = 0x401000
    source_address = 0x402000
    destination_address = 0x402100
    target = (
        bytes.fromhex("b902000000be")
        + struct.pack("<I", source_address)
        + b"\xbf"
        + struct.pack("<I", destination_address)
        + bytes.fromhex("f3a5d905")
        + struct.pack("<I", destination_address + 4)
        + b"\xc3"
    )
    candidate = ObjectFunction(
        name="_probe",
        data=(
            bytes.fromhex("b902000000be")
            + b"\x00" * 4
            + b"\xbf"
            + b"\x00" * 4
            + bytes.fromhex("f3a5d905")
            + struct.pack("<I", 4)
            + b"\xc3"
        ),
        relocation_offsets=frozenset({6, 11, 19}),
        relocation_references=(
            ObjectRelocationReference(6, "copy_source", "name:copy_source", True, addend=0),
            ObjectRelocationReference(11, "copy_destination", "name:copy_destination", True, addend=0),
            ObjectRelocationReference(19, "copy_source", "name:copy_source+0x4", True, addend=4),
        ),
    )
    result = match_function(
        target,
        candidate,
        image=LoadedImage(b"\x00" * 0x3000, image_base, 0x3000),
        target_va=function_address,
        reference_catalog=ReferenceCatalog(
            {
                source_address: ("copy_source",),
                destination_address: ("copy_destination",),
            },
        ),
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 3
    assert (
        f"{VC6_PROVEN_COPY_LOAD_KEY}:0x{source_address + 4:08x}"
        in result.masked_operand_audit.entries[-1].target_references[0].keys
    )


def test_proven_vc6_copy_load_expires_on_first_direct_access() -> None:
    image_base = 0x400000
    function_address = 0x401000
    source_address = 0x402000
    destination_address = 0x402100
    target = (
        bytes.fromhex("b902000000be")
        + struct.pack("<I", source_address)
        + b"\xbf"
        + struct.pack("<I", destination_address)
        + bytes.fromhex("f3a5c705")
        + struct.pack("<I", destination_address + 4)
        + b"\x00" * 4
        + bytes.fromhex("d905")
        + struct.pack("<I", destination_address + 4)
        + b"\xc3"
    )
    candidate = ObjectFunction(
        name="_probe",
        data=(
            bytes.fromhex("b902000000be")
            + b"\x00" * 4
            + b"\xbf"
            + b"\x00" * 4
            + bytes.fromhex("f3a5c705")
            + struct.pack("<I", 4)
            + b"\x00" * 4
            + bytes.fromhex("d905")
            + struct.pack("<I", 4)
            + b"\xc3"
        ),
        relocation_offsets=frozenset({6, 11, 19, 29}),
        relocation_references=(
            ObjectRelocationReference(6, "copy_source", "name:copy_source", True, addend=0),
            ObjectRelocationReference(11, "copy_destination", "name:copy_destination", True, addend=0),
            ObjectRelocationReference(
                19,
                "copy_destination",
                "name:copy_destination+0x4",
                True,
                addend=4,
            ),
            ObjectRelocationReference(29, "copy_source", "name:copy_source+0x4", True, addend=4),
        ),
    )
    result = match_function(
        target,
        candidate,
        image=LoadedImage(b"\x00" * 0x3000, image_base, 0x3000),
        target_va=function_address,
        reference_catalog=ReferenceCatalog(
            {
                source_address: ("copy_source",),
                destination_address: ("copy_destination",),
            },
        ),
    )

    assert result.ratio == 1.0
    assert result.masked_operand_audit.mismatch_count == 1
    assert not result.exact


def test_proven_vc6_copy_load_does_not_cross_control_flow() -> None:
    image_base = 0x400000
    function_address = 0x401000
    source_address = 0x402000
    destination_address = 0x402100
    target = (
        bytes.fromhex("b902000000be")
        + struct.pack("<I", source_address)
        + b"\xbf"
        + struct.pack("<I", destination_address)
        + bytes.fromhex("f3a5eb00d905")
        + struct.pack("<I", destination_address + 4)
        + b"\xc3"
    )
    candidate = ObjectFunction(
        name="_probe",
        data=(
            bytes.fromhex("b902000000be")
            + b"\x00" * 4
            + b"\xbf"
            + b"\x00" * 4
            + bytes.fromhex("f3a5eb00d905")
            + struct.pack("<I", 4)
            + b"\xc3"
        ),
        relocation_offsets=frozenset({6, 11, 21}),
        relocation_references=(
            ObjectRelocationReference(6, "copy_source", "name:copy_source", True, addend=0),
            ObjectRelocationReference(11, "copy_destination", "name:copy_destination", True, addend=0),
            ObjectRelocationReference(21, "copy_source", "name:copy_source+0x4", True, addend=4),
        ),
    )
    result = match_function(
        target,
        candidate,
        image=LoadedImage(b"\x00" * 0x3000, image_base, 0x3000),
        target_va=function_address,
        reference_catalog=ReferenceCatalog(
            {
                source_address: ("copy_source",),
                destination_address: ("copy_destination",),
            },
        ),
    )

    assert result.ratio == 1.0
    assert result.masked_operand_audit.mismatch_count == 1
    assert not result.exact


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


def test_match_function_audits_read_only_local_data_by_content() -> None:
    literal = bytes.fromhex("5a825a82")
    mapped = bytearray(0x10000)
    mapped[0x2000:0x2004] = literal
    reference = ObjectRelocationReference(
        offset=2,
        symbol_name="_const_mask",
        key="name:const_mask",
        explained=True,
        symbol_data=literal,
        read_only_data=True,
    )
    candidate = ObjectFunction(
        name="_foo",
        data=bytes.fromhex("d90500000000c3"),
        relocation_offsets=frozenset({2}),
        relocation_references=(reference,),
    )
    target = bytes.fromhex("d90500204000c3")
    image = LoadedImage(mapped=bytes(mapped), image_base=0x400000, size_of_image=len(mapped))

    result = match_function(
        target,
        candidate,
        image=image,
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({}),
    )
    assert result.exact
    assert result.masked_operand_audit.ok_count == 1

    named_candidate = replace(
        candidate,
        relocation_references=(replace(reference, symbol_data=b"\x00" * 4),),
    )
    named = match_function(
        target,
        named_candidate,
        image=image,
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({0x402000: ("const_mask",)}),
    )
    assert named.exact
    assert named.masked_operand_audit.ok_count == 1

    writable_candidate = replace(
        candidate,
        relocation_references=(replace(reference, read_only_data=False),),
    )
    unresolved = match_function(
        target,
        writable_candidate,
        image=image,
        target_va=0x401000,
        reference_catalog=ReferenceCatalog({}),
    )
    assert not unresolved.exact
    assert unresolved.masked_operand_audit.unresolved_count == 1


def test_extract_object_function_marks_static_rdata_references_read_only() -> None:
    obj = CoffObject(
        sections=(
            CoffSection(
                name=".text",
                data=bytes.fromhex("d90500000000c3"),
                characteristics=0x20,
                relocations=(CoffRelocation(2, 1, 6),),
            ),
            CoffSection(
                name=".rdata",
                data=bytes.fromhex("5a825a82"),
                characteristics=0x40,
                relocations=(),
            ),
        ),
        symbols=(
            CoffSymbol(0, "_foo", 0, 1, 0x20, 2),
            CoffSymbol(1, "_const_mask", 0, 2, 0, 3),
        ),
    )

    function = extract_object_function(obj, "_foo")

    assert function.relocation_references[0].read_only_data
    assert function.relocation_references[0].symbol_data == bytes.fromhex("5a825a82")


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


def _build_vc6_unwind_only_object() -> CoffObject:
    function = bytes.fromhex("b800000000e800000000c3")
    cleanup = bytes.fromhex("8b4dece900000000")
    handler = bytes.fromhex("b800000000e900000000")
    func_info = struct.pack("<II", 0x19930520, 1) + b"\x00" * 24
    unwind_entry = struct.pack("<iI", -1, 0)
    return CoffObject(
        sections=(
            CoffSection(
                name=".text",
                data=function,
                characteristics=0x20,
                relocations=(
                    CoffRelocation(1, 2, 6),
                    CoffRelocation(6, 6, 20),
                ),
            ),
            CoffSection(
                name=".text$x",
                data=cleanup + handler,
                characteristics=0x20,
                relocations=(
                    CoffRelocation(4, 6, 20),
                    CoffRelocation(9, 3, 6),
                    CoffRelocation(14, 5, 20),
                ),
            ),
            CoffSection(
                name=".xdata$x",
                data=func_info + unwind_entry,
                characteristics=0,
                relocations=(
                    CoffRelocation(8, 4, 6),
                    CoffRelocation(36, 1, 6),
                ),
            ),
        ),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "$Lcleanup", 0, 2, 0, 6),
            CoffSymbol(2, "$Lhandler", 8, 2, 0, 6),
            CoffSymbol(3, "$Tinfo", 0, 3, 0, 3),
            CoffSymbol(4, "$Tunwind", 32, 3, 0, 3),
            CoffSymbol(5, "___CxxFrameHandler", 0, 0, 0x20, 2),
            CoffSymbol(6, "??1base@@UAE@XZ", 0, 0, 0x20, 2),
        ),
    )


def test_match_function_audits_complete_vc6_unwind_only_graph() -> None:
    image_base = 0x400000
    handler_address = 0x400100
    unwind_map_address = 0x400180
    func_info_address = 0x400200
    cleanup_address = 0x400300
    frame_handler_address = 0x400400
    base_destructor_address = 0x400500
    mapped = bytearray(0x1000)

    handler = b"\xb8" + struct.pack("<I", func_info_address)
    handler += b"\xe9" + struct.pack("<i", frame_handler_address - (handler_address + 10))
    mapped[0x100:0x10A] = handler
    func_info = struct.pack("<II", 0x19930520, 1)
    func_info += struct.pack("<I", unwind_map_address) + b"\x00" * 20
    mapped[0x200:0x220] = func_info
    mapped[0x180:0x188] = struct.pack("<iI", -1, cleanup_address)
    cleanup = bytes.fromhex("8b4dece9")
    cleanup += struct.pack("<i", base_destructor_address - (cleanup_address + 8))
    mapped[0x300:0x308] = cleanup

    function = b"\xb8" + struct.pack("<I", handler_address)
    function += b"\xe8" + struct.pack("<i", base_destructor_address - (image_base + 10)) + b"\xc3"
    catalog = ReferenceCatalog(
        {
            frame_handler_address: ("__CxxFrameHandler",),
            base_destructor_address: ("base_destroy",),
        },
    ).with_object_aliases((("??1base@@UAE@XZ", "base_destroy"),))

    loaded_image = LoadedImage(bytes(mapped), image_base, len(mapped))
    key = f"{VC6_UNWIND_ONLY_KEY}:ecx=[ebp-0x14]"
    assert _image_vc6_unwind_only_key(
        loaded_image,
        catalog,
        handler_address,
        {base_destructor_address},
    ) == key
    assert _image_vc6_unwind_only_key(loaded_image, catalog, handler_address, set()) is None

    result = match_function(
        function,
        extract_object_function(_build_vc6_unwind_only_object(), "_probe"),
        image=loaded_image,
        target_va=image_base,
        reference_catalog=catalog,
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 2


def test_recognizes_complete_vc6_unwind_only_graph_in_coff() -> None:
    obj = _build_vc6_unwind_only_object()
    key = f"{VC6_UNWIND_ONLY_KEY}:ecx=[ebp-0x14]"

    assert _coff_vc6_unwind_only_key(obj, obj.symbols[0], 11, obj.symbols[2]) == key

    missing_direct_cleanup = replace(
        obj,
        sections=(replace(obj.sections[0], relocations=obj.sections[0].relocations[:1]), *obj.sections[1:]),
    )
    assert _coff_vc6_unwind_only_key(
        missing_direct_cleanup,
        missing_direct_cleanup.symbols[0],
        11,
        missing_direct_cleanup.symbols[2],
    ) is None


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


def test_canonicalizes_vc6_sparse_switch_destination_partition() -> None:
    candidate_key = _local_switch_partition_key(
        bytes((0, 1, 2, 2)),
        (0x08, 0x10, 0x18),
    )
    target_key = _local_switch_partition_key(
        bytes((0, 1, 3, 2)),
        (0x08, 0x10, 0x18, 0x18),
    )

    assert candidate_key == target_key
    assert candidate_key == f"{VC6_LOCAL_SWITCH_PARTITION_KEY}:00010202"


def test_extract_object_function_keys_vc6_sparse_switch_table_pair() -> None:
    code = (
        bytes.fromhex("0fb680")
        + b"\x00" * 4
        + bytes.fromhex("ff2485")
        + b"\x00" * 4
        + b"\xc3"
    )
    obj = CoffObject(
        sections=(
            CoffSection(
                name=".text",
                data=(
                    code
                    + b"\x90" * (0x20 - len(code))
                    + b"\x00" * 12
                    + bytes((0, 1, 2, 2))
                    + b"\x90"
                ),
                characteristics=0x20,
                relocations=(
                    CoffRelocation(3, 2, 6),
                    CoffRelocation(10, 1, 6),
                    CoffRelocation(0x20, 3, 6),
                    CoffRelocation(0x24, 4, 6),
                    CoffRelocation(0x28, 5, 6),
                ),
            ),
        ),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "$Ltable", 0x20, 1, 0, 6),
            CoffSymbol(2, "$Llookup", 0x2C, 1, 0, 6),
            CoffSymbol(3, "$Lcase0", 0x10, 1, 0, 6),
            CoffSymbol(4, "$Lcase1", 0x18, 1, 0, 6),
            CoffSymbol(5, "$Lcase2", 0x1C, 1, 0, 6),
        ),
    )

    function = extract_object_function(obj, "_probe")

    assert [reference.key for reference in function.relocation_references] == [
        f"{VC6_LOCAL_SWITCH_PARTITION_KEY}:00010202",
        f"{VC6_LOCAL_JUMP_TABLE_KEY}:0x10,0x18,0x1c",
    ]
    assert [reference.alternate_keys for reference in function.relocation_references] == [
        (),
        (f"{VC6_LOCAL_SWITCH_PARTITION_KEY}:00010202",),
    ]
    assert all(reference.explained for reference in function.relocation_references)


def test_match_function_audits_vc6_sparse_switch_destination_partition() -> None:
    image_base = 0x400000
    function_address = 0x401000
    table_address = 0x402000
    lookup_address = table_address + 16
    target = (
        bytes.fromhex("0fb680")
        + struct.pack("<I", lookup_address)
        + bytes.fromhex("ff2485")
        + struct.pack("<I", table_address)
        + b"\xc3"
        + b"\x90" * 16
    )
    partition_key = _local_switch_partition_key(
        bytes((0, 1, 2, 2)),
        (0x08, 0x10, 0x18),
    )
    assert partition_key is not None
    candidate = ObjectFunction(
        name="_probe",
        data=(
            bytes.fromhex("0fb680")
            + b"\x00" * 4
            + bytes.fromhex("ff2485")
            + b"\x00" * 4
            + b"\xc3"
            + b"\x90" * 16
        ),
        relocation_offsets=frozenset({3, 10}),
        relocation_references=(
            ObjectRelocationReference(
                offset=3,
                symbol_name="$Llookup",
                key=partition_key,
                explained=True,
            ),
            ObjectRelocationReference(
                offset=10,
                symbol_name="$Ltable",
                key=f"{VC6_LOCAL_JUMP_TABLE_KEY}:0x8,0x10,0x18",
                explained=True,
                alternate_keys=(partition_key,),
            ),
        ),
    )
    mapped = bytearray(0x3000)
    mapped[0x2000:0x2010] = struct.pack(
        "<IIII",
        function_address + 0x08,
        function_address + 0x10,
        function_address + 0x18,
        function_address + 0x18,
    )
    mapped[0x2010:0x2018] = bytes((0, 1, 3, 2, 0, 1, 2, 3))

    result = match_function(
        target,
        candidate,
        image=LoadedImage(bytes(mapped), image_base, len(mapped)),
        target_va=function_address,
        reference_catalog=ReferenceCatalog({lookup_address + 4: ("next_symbol",)}),
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 2


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


def test_validate_command_accepts_scratch_directory(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "scratch.conf").write_text(
        "FUNCTION=example SOURCE=source.cpp\n",
        encoding="utf-8",
    )
    (scratch / "source.cpp").write_text("void example() {}\n", encoding="utf-8")

    completed = CliRunner().invoke(match_app, ["validate", str(scratch)])

    assert completed.exit_code == 0
    assert completed.output == "ok\n"


def test_validate_command_reports_directory_errors_without_traceback(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "scratch.conf").write_text(
        "FUNCTION=example SOURCE=missing.cpp\n",
        encoding="utf-8",
    )

    completed = CliRunner().invoke(match_app, ["validate", str(scratch)])

    assert completed.exit_code == 1
    assert "missing.cpp" in completed.output
    assert "Traceback" not in completed.output


def test_is_analyzer_placeholder_rejects_only_weak_generated_names() -> None:
    assert is_analyzer_placeholder("FUN_00401000")
    assert is_analyzer_placeholder("sub_1000ABCD")
    assert is_analyzer_placeholder("unknown_libname_7")
    assert is_analyzer_placeholder("j_nullsub_11")
    assert is_analyzer_placeholder("DAT_10050550")
    assert is_analyzer_placeholder("LAB_10001000")
    assert is_analyzer_placeholder("lookup_table_4044b0")
    assert not is_analyzer_placeholder("crt_array_unwind_filter")
    assert not is_analyzer_placeholder("j_config_init_defaults")
    assert not is_analyzer_placeholder("?ArrayUnwindFilter@@YAHPAU_EXCEPTION_POINTERS@@@Z")


def test_collect_naming_debt_covers_curated_maps_without_exact_scratches(tmp_path: Path) -> None:
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        '[{"program":"grim.dll","address":"0x10001000",'
        '"name":"known_function","aliases":["sub_10001000","?Known@@YAXXZ"],'
        '"comment":"formerly FUN_10001000"}]\n',
        encoding="utf-8",
    )
    data_map = tmp_path / "data_map.json"
    data_map.write_text(
        '{"entries":[{"program":"grim.dll","address":"0x10050000",'
        '"name":"known_table","aliases":["DAT_10050000","provider_table"],'
        '"comment":"switchD_10050000 loads PTR_10050004"}]}\n',
        encoding="utf-8",
    )

    rows = collect_naming_debt(
        [],
        name_map_path=name_map,
        data_map_path=data_map,
    )

    assert [
        (row.map_kind, row.function, row.issues, row.placeholder_aliases)
        for row in rows
    ] == [
        (
            "function",
            "known_function",
            ("placeholder-alias", "placeholder-comment"),
            ("sub_10001000",),
        ),
        (
            "data",
            "known_table",
            ("placeholder-alias", "placeholder-comment"),
            ("DAT_10050000",),
        ),
    ]
    assert rows[0].placeholder_comment_tokens == ("FUN_10001000",)
    assert rows[1].placeholder_comment_tokens == ("switchD_10050000", "PTR_10050004")
    assert naming_debt_payload(rows[1])["map_kind"] == "data"

    pruned = prune_placeholder_aliases(
        rows,
        name_map_path=name_map,
        data_map_path=data_map,
    )

    assert pruned == {"aliases_removed": 2, "rows_pruned": 2}
    assert load_name_map_rows(name_map)[0]["aliases"] == ["?Known@@YAXXZ"]
    data_payload = json.loads(data_map.read_text(encoding="utf-8"))
    assert data_payload["entries"][0]["aliases"] == ["provider_table"]


def test_collect_naming_debt_suggests_unique_exact_provider_peer(tmp_path: Path) -> None:
    archive_hash = "a" * 64
    placeholder_config = ScratchConfig(
        directory=tmp_path / "FUN_00401000",
        function="FUN_00401000",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2 /GB /W3 /GR-",
        source="",
        end_va=None,
        symbol="?KnownProvider@@YAXXZ",
        note="unknown provider name",
        reference_aliases=(("object_target", "sub_00402000"),),
        archive="provider.lib",
        archive_member="known.obj",
        archive_sha256=archive_hash,
    )
    peer_config = replace(
        placeholder_config,
        directory=tmp_path / "known_provider",
        function="known_provider",
        image="grim.dll",
        note="exact provider",
        reference_aliases=(),
    )
    statuses = [
        ScratchStatus(
            config=placeholder_config,
            address=0x00401000,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        ),
        ScratchStatus(
            config=peer_config,
            address=0x10002000,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        ),
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "FUN_00401000",
                    "aliases": ["sub_00401000", "?KnownProvider@@YAXXZ"],
                },
                {
                    "program": "grim.dll",
                    "address": "0x10002000",
                    "name": "known_provider",
                    "aliases": ["sub_10001000", "?KnownProvider@@YAXXZ"],
                },
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)

    assert len(rows) == 2
    row = next(candidate for candidate in rows if candidate.image == "crimsonland.exe")
    assert row.function == "FUN_00401000"
    assert row.suggestion == "known_provider"
    assert row.suggestion_sources == ("grim.dll:0x10002000",)
    assert row.issues == (
        "placeholder-function",
        "placeholder-directory",
        "placeholder-alias",
        "placeholder-reference",
        "placeholder-note",
    )
    assert row.placeholder_aliases == ("sub_00401000",)
    assert row.placeholder_references == ("sub_00402000",)
    assert naming_debt_payload(row)["provider_symbol"] == "?KnownProvider@@YAXXZ"
    rendered = render_naming_debt_table(rows)
    assert "FUN_00401000" in rendered
    assert "known_provider" in rendered
    assert "suggested=1" in rendered
    peer_row = next(candidate for candidate in rows if candidate.image == "grim.dll")
    assert peer_row.issues == ("placeholder-alias",)
    assert peer_row.suggestion is None

    pruned = prune_placeholder_aliases(rows, name_map_path=name_map)

    assert pruned == {"aliases_removed": 2, "rows_pruned": 2}
    mapped_rows = load_name_map_rows(name_map)
    assert mapped_rows[0]["aliases"] == ["?KnownProvider@@YAXXZ"]
    assert mapped_rows[1]["aliases"] == ["?KnownProvider@@YAXXZ"]


def test_render_naming_debt_table_handles_clean_result() -> None:
    assert render_naming_debt_table([]) == (
        "image  address  function  suggestion  issues  symbol  scratch\n\n"
        "rows=0; suggested=0; issues="
    )
    assert render_naming_debt_summary([]) == "rows=0; suggested=0; issues="


def test_collect_naming_debt_suggests_exact_d3dx_decorated_symbol(tmp_path: Path) -> None:
    config = ScratchConfig(
        directory=tmp_path / "FUN_00401000",
        function="FUN_00401000",
        image="crimsonland.exe",
        compiler="msvc7.0",
        cflags="",
        source="",
        end_va=None,
        symbol=(
            "?init_D3DXQuaternionSquadSetup@@YGXPAUD3DXQUATERNION@@00PBU1@111@Z"
        ),
        note="directx-8.1-archive-helper",
        archive="d3dx8.lib",
        archive_member=r"obj\i386\d3dxmath.obj",
        archive_sha256="a" * 64,
    )
    status = ScratchStatus(
        config=config,
        address=0x00401000,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    optimized_config = replace(
        config,
        directory=tmp_path / "FUN_00401020",
        function="FUN_00401020",
        symbol=(
            "?sse2_D3DXVec3TransformNormal$$1@@"
            "YGPAUD3DXVECTOR3@@PAU1@PBU1@PBUD3DXMATRIX@@@Z"
        ),
        archive_member=r"objf\i386\d3dxmathsse2.obj",
    )
    optimized_status = replace(status, config=optimized_config, address=0x00401020)
    codec_config = replace(
        config,
        directory=tmp_path / "FUN_00401040",
        function="FUN_00401040",
        symbol="?Encode@CD3DXCodec_D3DX_A16L16@@UAEXIIPAUD3DXCOLOR@@@Z",
        archive_member=r"obj\i386\cd3dxcodec.obj",
    )
    codec_status = replace(status, config=codec_config, address=0x00401040)
    codec_dtor_config = replace(
        codec_config,
        directory=tmp_path / "FUN_00401060",
        function="FUN_00401060",
        symbol="??_GCD3DXCodec@@UAEPAXI@Z",
    )
    codec_dtor_status = replace(status, config=codec_dtor_config, address=0x00401060)
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "FUN_00401000",
                },
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401020",
                    "name": "FUN_00401020",
                },
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401040",
                    "name": "FUN_00401040",
                },
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401060",
                    "name": "FUN_00401060",
                },
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(
        [status, optimized_status, codec_status, codec_dtor_status],
        name_map_path=name_map,
    )
    row = next(candidate for candidate in rows if candidate.address == status.address)
    optimized_row = next(
        candidate for candidate in rows if candidate.address == optimized_status.address
    )

    assert row.suggestion == "d3dx_init_quaternion_squad_setup"
    assert row.suggestion_sources == (f"provider-symbol:{config.symbol}",)
    assert optimized_row.suggestion == "d3dx_sse2_vec3_transform_normal_impl"
    assert optimized_row.suggestion_sources == (
        f"provider-symbol:{optimized_config.symbol}",
    )
    codec_row = next(candidate for candidate in rows if candidate.address == codec_status.address)
    codec_dtor_row = next(
        candidate for candidate in rows if candidate.address == codec_dtor_status.address
    )
    assert codec_row.suggestion == "d3dx_pixel_encode_a16l16"
    assert codec_row.suggestion_sources == (f"provider-symbol:{codec_config.symbol}",)
    assert codec_dtor_row.suggestion == "d3dx_codec_scalar_deleting_dtor"


def test_collect_naming_debt_suggests_exact_d3dx_image_and_jpeg_symbols(
    tmp_path: Path,
) -> None:
    image_config = ScratchConfig(
        directory=tmp_path / "grim_load_image_jpg",
        function="grim_load_image_jpg",
        image="grim.dll",
        compiler="msvc7.0",
        cflags="",
        source="",
        end_va=None,
        symbol="?LoadJPG@CD3DXImage@@AAEJPBXK@Z",
        note="directx-8.1-archive-load-jpg",
        archive="d3dx8.lib",
        archive_member=r"obj\i386\cd3dximage.obj",
        archive_sha256="a" * 64,
    )
    jpeg_config = replace(
        image_config,
        directory=tmp_path / "d3dx_jpeg_create_decompress",
        function="sub_1001C265",
        symbol="?jpeg_CreateDecompress@D3DX@@YAXPAUjpeg_decompress_struct@1@HI@Z",
        archive_member=r"obj\i386\jdapimin.obj",
    )
    statuses = [
        ScratchStatus(
            config=config,
            address=address,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )
        for config, address in ((image_config, 0x10010000), (jpeg_config, 0x1001C265))
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "grim.dll",
                    "address": "0x10010000",
                    "name": "grim_load_image_jpg",
                },
                {
                    "program": "grim.dll",
                    "address": "0x1001c265",
                    "name": "sub_1001C265",
                },
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)
    image_row = next(row for row in rows if row.address == 0x10010000)
    jpeg_row = next(row for row in rows if row.address == 0x1001C265)

    assert image_row.suggestion == "d3dx_image_load_jpg"
    assert image_row.issues == ("provider-directory-conflict", "provider-name-conflict")
    assert jpeg_row.suggestion == "d3dx_jpeg_create_decompress"
    assert jpeg_row.issues == ("placeholder-function",)


def test_collect_naming_debt_namespaces_exact_d3dx_codec_helpers(tmp_path: Path) -> None:
    base_config = ScratchConfig(
        directory=tmp_path / "d3dx_jpeg_output_pass_setup",
        function="sub_1001C641",
        image="grim.dll",
        compiler="msvc7.0",
        cflags="",
        source="",
        end_va=None,
        symbol="?output_pass_setup@D3DX@@YAEPAUjpeg_decompress_struct@1@@Z",
        note="directx-8.1-archive-jpeg-output-pass-setup",
        archive="d3dx8.lib",
        archive_member=r"obj\i386\jdapistd.obj",
        archive_sha256="a" * 64,
    )
    configs = [
        base_config,
        replace(
            base_config,
            directory=tmp_path / "d3dx_default_decompress_parms",
            function="d3dx_default_decompress_parms",
            symbol="?default_decompress_parms@D3DX@@YAXPAUjpeg_decompress_struct@1@@Z",
            archive_member=r"obj\i386\jdapimin.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "png_error",
            function="png_error",
            symbol="?png_error@D3DX@@YAXPAUpng_struct_def@1@PBD@Z",
            archive_member=r"obj\i386\pngerror.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "png_get_trns",
            function="png_get_tRNS",
            symbol=(
                "?png_get_tRNS@D3DX@@YAKPAUpng_struct_def@1@"
                "PAUpng_info_struct@1@PAPAEPAHPAPAUpng_color_16_struct@1@@Z"
            ),
            archive_member=r"obj\i386\pngget.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "d3dx_file_close",
            function="FUN_1001BE91",
            symbol="?Close@CD3DXFile@@QAEJXZ",
            archive_member=r"obj\i386\cd3dxfile.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "d3dx_jpeg_is_mmx",
            function="FUN_10022C2F",
            symbol="?IsMMX@D3DX@@YAHXZ",
            archive_member=r"obj\i386\jutils.obj",
        ),
    ]
    statuses = [
        ScratchStatus(
            config=config,
            address=0x1001C641 + index * 0x20,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )
        for index, config in enumerate(configs)
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "grim.dll",
                    "address": f"0x{status.address:08x}",
                    "name": status.config.function,
                }
                for status in statuses
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)

    assert [row.suggestion for row in rows] == [
        "d3dx_jpeg_output_pass_setup",
        "d3dx_jpeg_default_decompress_parms",
        "d3dx_png_error",
        "d3dx_png_get_trns",
        "d3dx_file_close",
        "d3dx_jpeg_is_mmx",
    ]


def test_collect_naming_debt_namespaces_exact_stock_codec_helpers(tmp_path: Path) -> None:
    jaz_config = ScratchConfig(
        directory=tmp_path / "grim_jaz_jpeg_output_pass_setup",
        function="output_pass_setup",
        image="grim.dll",
        compiler="msvc7.0",
        cflags="",
        source="../../third_party/sources/ijg-libjpeg-6a/jdapistd.c",
        end_va=None,
        symbol="output_pass_setup",
        note="ijg-6a-stock-output-pass-setup",
    )
    zlib_config = replace(
        jaz_config,
        directory=tmp_path / "d3dx_zlib_static_tree_init",
        function="nullsub_8",
        source="",
        symbol="_tr_static_init",
        note="zlib-1.1.3-empty-static-tree-init",
        archive="zlib.lib",
        archive_member="trees.obj",
        archive_sha256="a" * 64,
    )
    callback_config = replace(
        jaz_config,
        directory=tmp_path / "grim_png_error_longjmp",
        function="sub_100117F3",
        source="../../shared/grim_png_callbacks.cpp",
        symbol="grim_png_error_longjmp",
        note="png-error-longjmp-callback",
    )
    vertex_config = replace(
        jaz_config,
        directory=tmp_path / "nullsub_6",
        function="nullsub_6",
        source="../../shared/grim_vertex_space_converter.cpp",
        symbol="?noop@grim_vertex_space_converter_t@@QAEXIII@Z",
        note="d3dx-vertex-space-converter-noop-leaf",
    )
    statuses = [
        ScratchStatus(
            config=config,
            address=address,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )
        for config, address in (
            (jaz_config, 0x10009FA0),
            (callback_config, 0x100117F3),
            (vertex_config, 0x10018000),
            (zlib_config, 0x1003A604),
        )
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "grim.dll",
                    "address": f"0x{status.address:08x}",
                    "name": status.config.function,
                }
                for status in statuses
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)

    assert [row.suggestion for row in rows] == [
        "grim_jaz_jpeg_output_pass_setup",
        "grim_png_error_longjmp",
        "grim_vertex_space_converter_noop",
        "zlib_tr_static_init",
    ]


def test_collect_naming_debt_accepts_official_unknown_chunk_note(tmp_path: Path) -> None:
    config = ScratchConfig(
        directory=tmp_path / "png_handle_unknown",
        function="png_handle_unknown",
        image="grim.dll",
        compiler="msvc7.0",
        cflags="",
        source="../../third_party/sources/libpng-1.0.5/pngrutil.c",
        end_va=None,
        symbol="png_handle_unknown",
        note="libpng-1.0.5-unknown-chunk-handler",
    )
    status = ScratchStatus(
        config=config,
        address=0x10025000,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "grim.dll",
                    "address": "0x10025000",
                    "name": "png_handle_unknown",
                },
            ],
        ),
        encoding="utf-8",
    )

    assert collect_naming_debt([status], name_map_path=name_map) == []


def test_collect_naming_debt_suggests_exact_vc6_converter_symbols(tmp_path: Path) -> None:
    base_config = ScratchConfig(
        directory=tmp_path / "FUN_00401000",
        function="FUN_00401000",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="",
        source="",
        end_va=None,
        symbol="__FillZeroMan",
        note="vc6-crt-internal-converter",
        archive="libcmt.lib",
        archive_member=r"build\intel\mt_obj\intrncvt.obj",
        archive_sha256="a" * 64,
    )
    ld12_config = replace(
        base_config,
        directory=tmp_path / "FUN_00401020",
        function="FUN_00401020",
        symbol="__ld12cvt",
    )
    sbh_config = replace(
        base_config,
        directory=tmp_path / "FUN_00401040",
        function="FUN_00401040",
        symbol="___old_sbh_alloc_block_from_page",
        archive_member=r"build\intel\mt_obj\sbheap.obj",
    )
    printf_config = replace(
        base_config,
        directory=tmp_path / "FUN_00401060",
        function="FUN_00401060",
        symbol="_get_int64_arg",
        archive_member=r"build\intel\mt_obj\cprintf.obj",
    )
    statuses = [
        ScratchStatus(
            config=config,
            address=address,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )
        for config, address in (
            (base_config, 0x00401000),
            (ld12_config, 0x00401020),
            (sbh_config, 0x00401040),
            (printf_config, 0x00401060),
        )
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": f"0x{status.address:08x}",
                    "name": status.config.function,
                }
                for status in statuses
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)

    assert [row.suggestion for row in rows] == [
        "crt_fill_zero_man",
        "crt_ld12cvt",
        "crt_old_sbh_alloc_block_from_page",
        "crt_printf_get_int64_arg",
    ]
    assert all(row.suggestion_sources == (f"provider-symbol:{row.provider_symbol}",) for row in rows)


def test_collect_naming_debt_canonicalizes_weak_exact_vc6_symbols(tmp_path: Path) -> None:
    base_config = ScratchConfig(
        directory=tmp_path / "FUN_00401000",
        function="FUN_00401000",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="",
        source="",
        end_va=None,
        symbol="__GetLinkerVersion",
        note="vc6-crt-linker-version",
        archive="libcmt.lib",
        archive_member=r"build\intel\mt_obj\heapinit.obj",
        archive_sha256="a" * 64,
    )
    configs = [
        base_config,
        replace(
            base_config,
            directory=tmp_path / "CPtoLCID",
            function="_CPtoLCID",
            symbol="_CPtoLCID",
            archive_member=r"build\intel\mt_obj\mbctype.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "input",
            function="__input",
            symbol="__input",
            archive_member=r"build\intel\mt_obj\input.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "crt_flushall",
            function="crt_flushall",
            symbol="_flsall",
            archive_member=r"build\intel\mt_obj\fflush.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "FUN_00401080",
            function="FUN_00401080",
            symbol="$L17371",
            archive_member=r"build\intel\mt_obj\free.obj",
        ),
        replace(
            base_config,
            directory=tmp_path / "FUN_004010a0",
            function="FUN_004010a0",
            symbol="__fptrap",
            archive_member=r"build\intel\mt_obj\crt0fp.obj",
        ),
    ]
    statuses = [
        ScratchStatus(
            config=config,
            address=0x00401000 + index * 0x20,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )
        for index, config in enumerate(configs)
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": f"0x{status.address:08x}",
                    "name": status.config.function,
                }
                for status in statuses
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)

    assert [row.suggestion for row in rows] == [
        "crt_get_linker_version",
        "crt_cp_to_lcid",
        "crt_scan_input",
        "crt_flsall",
        "crt_free_sbh_unlock_cleanup",
        "crt_fptrap",
    ]
    assert rows[3].issues == (
        "provider-directory-conflict",
        "provider-name-conflict",
    )


def test_curated_naming_hint_renames_exact_placeholder_and_records_evidence(
    tmp_path: Path,
) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "nullsub_13"
    scratch.mkdir(parents=True)
    scratch.joinpath("scratch.conf").write_text(
        "IMAGE=crimsonland.exe\n"
        "FUNCTION=nullsub_13\n"
        "SYMBOL=nullsub_13\n"
        "SOURCE=scratch.cpp\n"
        "NOTE=empty-nullsub\n",
        encoding="utf-8",
    )
    scratch.joinpath("scratch.cpp").write_text(
        'extern "C" void nullsub_13() {}\n',
        encoding="utf-8",
    )
    status = ScratchStatus(
        config=load_scratch_config(scratch),
        address=0x00408970,
        target_size=1,
        ratio=1.0,
        prefix_instructions=1,
        target_instructions=1,
        candidate_instructions=1,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00408970",
                    "name": "nullsub_13",
                    "aliases": ["sub_408970"],
                    "comment": "analyzer placeholder",
                },
            ],
        ),
        encoding="utf-8",
    )
    hints = tmp_path / "naming_hints.json"
    hints.write_text(
        json.dumps(
            {
                "schema": 1,
                "entries": [
                    {
                        "program": "crimsonland.exe",
                        "address": "0x00408970",
                        "name": "tutorial_primary_button_destroy",
                        "comment": "Exact empty destructor for the tutorial primary button.",
                        "evidence": "tutorial static-object initialization order",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    loaded_hint = load_naming_hints(hints)[("crimsonland.exe", 0x00408970)]
    rows = collect_naming_debt(
        [status],
        name_map_path=name_map,
        naming_hints_path=hints,
    )
    row = rows[0]
    result = apply_naming_suggestions(
        rows,
        match_root=match_root,
        name_map_path=name_map,
    )

    renamed = match_root / "scratches" / "tutorial_primary_button_destroy"
    assert loaded_hint.name == "tutorial_primary_button_destroy"
    assert row.suggestion == "tutorial_primary_button_destroy"
    assert row.suggestion_sources == (
        "curated-hint:tutorial static-object initialization order",
    )
    assert row.suggestion_comment == loaded_hint.comment
    renamed_config = load_scratch_config(renamed)
    assert renamed_config.function == row.suggestion
    assert renamed_config.note == "evidence-backed-tutorial-primary-button-destroy"
    assert renamed.joinpath("scratch.cpp").read_text(encoding="utf-8") == (
        'extern "C" void tutorial_primary_button_destroy() {}\n'
    )
    mapped = load_name_map_rows(name_map)[0]
    assert mapped["name"] == row.suggestion
    assert mapped["comment"] == loaded_hint.comment
    assert "aliases" not in mapped
    assert result["directories_renamed"] == 1


def test_collect_naming_debt_suggests_exact_vc6_eh_decorated_symbol(tmp_path: Path) -> None:
    symbol = (
        "?_CallSETranslator@@YAHPAUEHExceptionRecord@@PAUEHRegistrationNode@@"
        "PAX2PBU_s_FuncInfo@@H1@Z"
    )
    config = ScratchConfig(
        directory=tmp_path / "CallSETranslator_YAHPAUEHExceptionRecord",
        function=symbol,
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="",
        source="",
        end_va=None,
        symbol=symbol,
        note="vc6-crt-eh-translator",
        archive="libcmt.lib",
        archive_member=r"build\intel\mt_obj\trnsctrl.obj",
        archive_sha256="a" * 64,
    )
    status = ScratchStatus(
        config=config,
        address=0x00401000,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": symbol,
                },
            ],
        ),
        encoding="utf-8",
    )

    row = collect_naming_debt([status], name_map_path=name_map)[0]

    assert row.suggestion == "crt_call_se_translator"
    assert row.issues == ("provider-directory-conflict", "provider-name-conflict")
    assert row.suggestion_sources == (f"provider-symbol:{symbol}",)


def test_apply_naming_suggestions_namespaces_exact_source_provider_symbol(
    tmp_path: Path,
) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "grim_jaz_jpeg_consume_input"
    scratch.mkdir(parents=True)
    scratch.joinpath("scratch.conf").write_text(
        "IMAGE=grim.dll\n"
        "FUNCTION=jpeg_consume_input\n"
        "SYMBOL=jpeg_consume_input\n"
        "SOURCE=../../third_party/sources/ijg-libjpeg-6a/jdapimin.c\n"
        "NOTE=ijg-6a-stock-consume-input\n",
        encoding="utf-8",
    )
    status = ScratchStatus(
        config=load_scratch_config(scratch),
        address=0x10009BA0,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "grim.dll",
                    "address": "0x10009ba0",
                    "name": "jpeg_consume_input",
                },
            ],
        ),
        encoding="utf-8",
    )
    matching_scope = tmp_path / "matching_scope.json"
    matching_scope.write_text(
        json.dumps(
            {
                "schema": 2,
                "scopes": {
                    "port": {
                        "programs": {},
                        "function_dispositions": {
                            "grim.dll": [
                                {
                                    "address": "0x10009ba0",
                                    "name": "jpeg_consume_input",
                                    "disposition": "third-party",
                                    "reason": "IJG libjpeg 6a",
                                },
                            ],
                        },
                    },
                },
            },
        ),
        encoding="utf-8",
    )

    row = collect_naming_debt([status], name_map_path=name_map)[0]
    result = apply_naming_suggestions(
        [row],
        match_root=match_root,
        name_map_path=name_map,
        matching_scope_path=matching_scope,
    )

    assert row.suggestion == "grim_jaz_jpeg_consume_input"
    assert row.suggestion_sources == ("source-symbol:jpeg_consume_input",)
    assert load_scratch_config(scratch).function == "grim_jaz_jpeg_consume_input"
    mapped = load_name_map_rows(name_map)[0]
    assert mapped["name"] == "grim_jaz_jpeg_consume_input"
    assert "aliases" not in mapped
    assert result["map_rows_updated"] == 1
    scope_payload = json.loads(matching_scope.read_text(encoding="utf-8"))
    disposition = scope_payload["scopes"]["port"]["function_dispositions"]["grim.dll"][0]
    assert disposition["name"] == "grim_jaz_jpeg_consume_input"
    assert result["scope_dispositions_updated"] == 1


def test_apply_naming_suggestions_replaces_weaker_d3dx_semantic_identity(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "vec2_normalize_dispatch_init_00401000"
    scratch.mkdir(parents=True)
    symbol = "?init_D3DXVec2Normalize@@YGPAUD3DXVECTOR2@@PAU1@PBU1@@Z"
    scratch.joinpath("scratch.conf").write_text(
        "\n".join(
            (
                "IMAGE=crimsonland.exe",
                "FUNCTION=vec2_normalize_dispatch_init",
                "ARCHIVE=d3dx8.lib",
                r"ARCHIVE_MEMBER='obj\i386\d3dxmath.obj'",
                f"ARCHIVE_SHA256={'a' * 64}",
                f"SYMBOL='{symbol}'",
                "NOTE=directx-8.1-archive-vec2-normalize-dispatch-init",
                "",
            ),
        ),
        encoding="utf-8",
    )
    config = load_scratch_config(scratch)
    status = ScratchStatus(
        config=config,
        address=0x00401000,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "vec2_normalize_dispatch_init",
                    "signature": "void vec2_normalize_dispatch_init(void)",
                },
            ],
        ),
        encoding="utf-8",
    )

    row = collect_naming_debt([status], name_map_path=name_map)[0]
    result = apply_naming_suggestions(
        [row],
        match_root=match_root,
        name_map_path=name_map,
    )

    renamed = match_root / "scratches" / "d3dx_init_vec2_normalize"
    assert row.issues == ("provider-directory-conflict", "provider-name-conflict")
    assert row.suggestion == "d3dx_init_vec2_normalize"
    assert not scratch.exists()
    assert load_scratch_config(renamed).function == "d3dx_init_vec2_normalize"
    assert load_name_map_rows(name_map)[0]["name"] == "d3dx_init_vec2_normalize"
    assert result["directories_renamed"] == 1


def test_apply_naming_suggestions_updates_map_configs_and_colliding_directory(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratches = match_root / "scratches"
    placeholder = scratches / "FUN_00401000"
    jump = scratches / "j_FUN_00401000"
    peer = scratches / "known_provider"
    consumer = scratches / "consumer"
    placeholder.mkdir(parents=True)
    jump.mkdir()
    peer.mkdir()
    consumer.mkdir()
    archive_hash = "a" * 64
    placeholder.joinpath("scratch.conf").write_text(
        "\n".join(
            (
                "IMAGE=crimsonland.exe",
                "FUNCTION=FUN_00401000",
                "ARCHIVE=provider.lib",
                "ARCHIVE_MEMBER=known.obj",
                f"ARCHIVE_SHA256={archive_hash}",
                "SYMBOL=?KnownProvider@@YAXXZ",
                "NOTE=unknown-provider-name",
                "",
            ),
        ),
        encoding="utf-8",
    )
    peer.joinpath("scratch.conf").write_text(
        "\n".join(
            (
                "IMAGE=grim.dll",
                "FUNCTION=known_provider",
                "ARCHIVE=provider.lib",
                "ARCHIVE_MEMBER=known.obj",
                f"ARCHIVE_SHA256={archive_hash}",
                "SYMBOL=?KnownProvider@@YAXXZ",
                "NOTE=exact-provider",
                "",
            ),
        ),
        encoding="utf-8",
    )
    jump.joinpath("scratch.conf").write_text(
        "\n".join(
            (
                "IMAGE=crimsonland.exe",
                "FUNCTION=j_FUN_00401000",
                "ARCHIVE=provider.lib",
                "ARCHIVE_MEMBER=known.obj",
                f"ARCHIVE_SHA256={archive_hash}",
                "SYMBOL=_PublicProvider@0",
                "NOTE=exact-provider-jump",
                "",
            ),
        ),
        encoding="utf-8",
    )
    consumer.joinpath("scratch.conf").write_text(
        "\n".join(
            (
                "IMAGE=crimsonland.exe",
                "FUNCTION=consumer",
                "ARCHIVE=consumer.lib",
                "ARCHIVE_MEMBER=consumer.obj",
                f"ARCHIVE_SHA256={'b' * 64}",
                "SYMBOL=_consumer",
                "REFERENCE_ALIASES=_provider:FUN_00401000",
                "NOTE=consumer",
                "",
            ),
        ),
        encoding="utf-8",
    )
    consumer.joinpath("source.cpp").write_text(
        "void consumer() { FUN_00401000(); }\n",
        encoding="utf-8",
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "FUN_00401000",
                    "aliases": ["sub_00401000", "?KnownProvider@@YAXXZ"],
                    "signature": "void FUN_00401000(void)",
                    "comment": "[binja] void sub_401000()",
                },
                {
                    "program": "grim.dll",
                    "address": "0x10001000",
                    "name": "known_provider",
                },
            ],
        ),
        encoding="utf-8",
    )
    placeholder_config = load_scratch_config(placeholder)
    peer_config = load_scratch_config(peer)
    statuses = [
        ScratchStatus(
            config=placeholder_config,
            address=0x00401000,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        ),
        ScratchStatus(
            config=peer_config,
            address=0x10001000,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        ),
    ]
    suggestion = next(
        row
        for row in collect_naming_debt(statuses, name_map_path=name_map)
        if row.suggestion is not None
    )
    jump_suggestion = replace(
        suggestion,
        address=0x00401020,
        function="j_FUN_00401000",
        configured_function="j_FUN_00401000",
        scratch=jump.as_posix(),
        placeholder_aliases=(),
        provider_symbol="_PublicProvider@0",
        suggestion="public_provider",
        suggestion_sources=("grim.dll:0x10001020",),
    )

    result = apply_naming_suggestions(
        [suggestion, jump_suggestion],
        match_root=match_root,
        name_map_path=name_map,
    )

    renamed = scratches / "crimson_known_provider"
    assert not placeholder.exists()
    assert not jump.exists()
    assert load_scratch_config(renamed).function == "known_provider"
    assert load_scratch_config(scratches / "public_provider").function == "public_provider"
    assert load_scratch_config(renamed).note == "exact-archive-known-provider"
    assert load_scratch_config(consumer).reference_aliases == (("_provider", "known_provider"),)
    assert consumer.joinpath("source.cpp").read_text(encoding="utf-8") == (
        "void consumer() { known_provider(); }\n"
    )
    rows = load_name_map_rows(name_map)
    mapped = next(row for row in rows if row["program"] == "crimsonland.exe")
    assert mapped["name"] == "known_provider"
    assert mapped["aliases"] == ["?KnownProvider@@YAXXZ"]
    assert mapped["signature"] == "void known_provider(void)"
    assert mapped["comment"] == "[binja] void known_provider()"
    assert result == {
        "applied": 2,
        "aliases_removed": 1,
        "config_references_updated": 1,
        "directories_renamed": 2,
        "map_rows_added": 1,
        "map_rows_updated": 1,
        "scope_dispositions_updated": 0,
        "text_references_updated": 3,
        "renames": [
            {
                "from": placeholder.as_posix(),
                "to": renamed.as_posix(),
            },
            {
                "from": jump.as_posix(),
                "to": (scratches / "public_provider").as_posix(),
            },
        ],
    }


def test_apply_naming_suggestions_reuses_vacated_canonical_directory(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratches = match_root / "scratches"
    internal = scratches / "crt_flushall"
    public = scratches / "sub_00401020"
    internal.mkdir(parents=True)
    public.mkdir()
    archive_hash = "a" * 64
    for scratch, function, symbol in (
        (internal, "crt_flushall", "_flsall"),
        (public, "sub_00401020", "__flushall"),
    ):
        scratch.joinpath("scratch.conf").write_text(
            "\n".join(
                (
                    "IMAGE=crimsonland.exe",
                    f"FUNCTION={function}",
                    "ARCHIVE=libcmt.lib",
                    r"ARCHIVE_MEMBER='build\intel\mt_obj\fflush.obj'",
                    f"ARCHIVE_SHA256={archive_hash}",
                    f"SYMBOL={symbol}",
                    "NOTE=vc6-sp6-libcmt-flush",
                    "",
                ),
            ),
            encoding="utf-8",
        )
    statuses = [
        ScratchStatus(
            config=load_scratch_config(scratch),
            address=address,
            target_size=8,
            ratio=1.0,
            prefix_instructions=2,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )
        for scratch, address in ((internal, 0x00401000), (public, 0x00401020))
    ]
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": f"0x{status.address:08x}",
                    "name": status.config.function,
                    "comment": (
                        "Exact archive recovery from "
                        rf"build\intel\mt_obj\fflush.obj symbol {status.config.symbol}."
                    ),
                }
                for status in statuses
            ],
        ),
        encoding="utf-8",
    )

    rows = collect_naming_debt(statuses, name_map_path=name_map)
    result = apply_naming_suggestions(
        rows,
        match_root=match_root,
        name_map_path=name_map,
    )

    assert not public.exists()
    assert load_scratch_config(scratches / "crt_flsall").function == "crt_flsall"
    assert load_scratch_config(scratches / "crt_flushall").function == "crt_flushall"
    assert result["directories_renamed"] == 2
    assert [row["comment"] for row in load_name_map_rows(name_map)] == [
        r"Exact archive recovery from build\intel\mt_obj\fflush.obj symbol _flsall.",
        r"Exact archive recovery from build\intel\mt_obj\fflush.obj symbol __flushall.",
    ]


def test_repair_provider_comments_restores_exact_linkage_symbol(tmp_path: Path) -> None:
    config = ScratchConfig(
        directory=tmp_path / "crt_scan_input",
        function="crt_scan_input",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="",
        source="",
        end_va=None,
        symbol="__input",
        note="vc6-sp6-libcmt-input",
        archive="libcmt.lib",
        archive_member=r"build\intel\mt_obj\input.obj",
        archive_sha256="a" * 64,
    )
    status = ScratchStatus(
        config=config,
        address=0x00401000,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "crt_scan_input",
                    "aliases": ["__input"],
                    "comment": (
                        "Exact archive recovery from "
                        r"build\intel\mt_obj\crt_scan_input.obj symbol crt_scan_input."
                    ),
                },
            ],
        ),
        encoding="utf-8",
    )

    result = repair_provider_comments([status], name_map_path=name_map)

    assert result["comments_repaired"] == 1
    assert load_name_map_rows(name_map)[0]["comment"] == (
        r"Exact archive recovery from build\intel\mt_obj\input.obj symbol __input."
    )


def test_rewrite_placeholder_references_uses_unique_canonical_map_name(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    consumer = match_root / "scratches" / "consumer"
    consumer.mkdir(parents=True)
    consumer.joinpath("scratch.conf").write_text(
        "IMAGE=crimsonland.exe\n"
        "FUNCTION=consumer\n"
        "REFERENCE_ALIASES=_target:FUN_00401000,_provider:?KnownTarget@@YAXXZ\n"
        "NOTE=exact-consumer\n",
        encoding="utf-8",
    )
    status = ScratchStatus(
        config=load_scratch_config(consumer),
        address=0x00402000,
        target_size=8,
        ratio=1.0,
        prefix_instructions=2,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "known_target",
                },
                {
                    "program": "crimsonland.exe",
                    "address": "0x00402000",
                    "name": "consumer",
                },
            ],
        ),
        encoding="utf-8",
    )

    row = collect_naming_debt([status], name_map_path=name_map)[0]

    assert row.reference_suggestions == (("_target", "FUN_00401000", "known_target"),)
    assert naming_debt_payload(row)["reference_suggestions"] == [
        {
            "object_symbol": "_target",
            "from": "FUN_00401000",
            "to": "known_target",
        },
    ]

    result = rewrite_placeholder_references([row], match_root=match_root)

    assert load_scratch_config(consumer).reference_aliases == (
        ("_target", "known_target"),
        ("_provider", "?KnownTarget@@YAXXZ"),
    )
    assert result == {
        "configs_updated": 1,
        "references_updated": 1,
        "mappings": [
            {
                "image": "crimsonland.exe",
                "from": "FUN_00401000",
                "to": "known_target",
            },
        ],
        "updated_files": [consumer.joinpath("scratch.conf").as_posix()],
    }


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
        "1/30 reproducible candidates covering 10/3000 bytes (0.3%); "
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


def _write_native_link_fixture(
    repo_root: Path,
    *,
    image: str = "grim.dll",
) -> tuple[Path, Path]:
    evidence = repo_root / "evidence.bin"
    evidence.write_bytes(b"native audit input")
    evidence_sha256 = hashlib.sha256(evidence.read_bytes()).hexdigest()
    definitions = repo_root / "definitions.json"
    definitions.write_bytes(b'{"schema":1}')
    definitions_sha256 = hashlib.sha256(definitions.read_bytes()).hexdigest()
    canonical = repo_root / "canonical.cpp"
    canonical.write_bytes(b"void recovered() {}")
    canonical_sha256 = hashlib.sha256(canonical.read_bytes()).hexdigest()
    object_list = "canonical.obj\n"
    export_definition = "EXPORTS\n"
    input_row = {
        "path": "evidence.bin",
        "repository_relative": True,
        "sha256": evidence_sha256,
    }
    artifact_dir = repo_root / "analysis" / "native" / image
    artifact_dir.mkdir(parents=True)
    objects = {
        "schema": 2,
        "kind": "crimson-native-object-manifest",
        "image": image,
        "scope": "port",
        "reference_image": "evidence.bin",
        "reference_image_sha256": evidence_sha256,
        "function_count": 3,
        "object_count": 2,
        "object_list_sha256": hashlib.sha256(object_list.encode()).hexdigest(),
        "translation_units": {
            "cluster_count": 1,
            "isolated_count": 1,
        },
        "abi_assertions": {
            "status": "passed",
            "compile_inputs": [input_row],
        },
        "objects": [
            {
                "source": "canonical.cpp",
                "source_sha256": canonical_sha256,
                "config": "canonical.cpp",
                "config_sha256": canonical_sha256,
                "compile_inputs": [input_row],
                "functions": [
                    {
                        "canonical_source": "canonical.cpp",
                        "canonical_source_sha256": canonical_sha256,
                        "canonical_config": "canonical.cpp",
                        "canonical_config_sha256": canonical_sha256,
                    },
                ],
            },
        ],
        "provenance": {
            "selection_inputs": [input_row],
            "toolchain": {
                "cl_wrapper": input_row,
                "wibo": input_row,
                "compiler_bundles": [],
            },
        },
    }
    closure = {
        "schema": 2,
        "kind": "crimson-native-symbol-closure",
        "image": image,
        "scope": "port",
        "export_definition_sha256": hashlib.sha256(export_definition.encode()).hexdigest(),
        "source": {
            "catalog_inputs": [input_row],
        },
        "summary": {
            "function_count": 3,
            "object_count": 2,
            "function_closure": True,
            "game_owned_closure": False,
            "all_references_closed": False,
            "hard_duplicate_symbols": 0,
            "resolved_symbols": 7,
            "unresolved_symbols": 5,
            "unresolved_by_category": {
                "import": 2,
                "game_data": 3,
            },
        },
    }
    data = {
        "schema": 1,
        "kind": "crimson-native-data-manifest",
        "image": image,
        "source": {
            "data_map": "evidence.bin",
            "data_map_sha256": evidence_sha256,
            "definitions": "definitions.json",
            "definitions_sha256": definitions_sha256,
            "segments": "evidence.bin",
            "segments_sha256": evidence_sha256,
        },
        "summary": {
            "entry_count": 11,
            "typed_entries": 8,
            "explicit_size_entries": 2,
            "explicit_alignment_entries": 1,
            "explicit_initializer_entries": 4,
        },
    }
    audit_digest = hashlib.sha256(
        json.dumps(
            {
                "data_manifest": data,
                "object_manifest": objects,
                "symbol_closure": closure,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    ).hexdigest()
    for payload in (objects, closure, data):
        payload["audit_digest"] = audit_digest
    for name, payload in (
        ("objects.json", objects),
        ("closure.json", closure),
        ("data.json", data),
    ):
        (artifact_dir / name).write_text(
            json.dumps(payload, sort_keys=True),
            encoding="utf-8",
        )
    (artifact_dir / "objects.txt").write_text(object_list, encoding="utf-8")
    (artifact_dir / "exports.def").write_text(export_definition, encoding="utf-8")
    return artifact_dir, canonical


def test_native_link_status_reads_current_audit_and_renders_debt(tmp_path: Path) -> None:
    analysis_dir, _ = _write_native_link_fixture(tmp_path)

    statuses = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )

    assert statuses == [
        NativeLinkStatus(
            image="grim.dll",
            artifact_state="current",
            artifact_note="audited inputs and artifact digest agree",
            function_count=3,
            object_count=2,
            translation_unit_clusters=1,
            abi_status="passed",
            function_closure=True,
            game_owned_closure=False,
            all_references_closed=False,
            hard_duplicate_symbols=0,
            resolved_symbols=7,
            unresolved_symbols=5,
            unresolved_by_category=(("game_data", 3), ("import", 2)),
            data_entries=11,
            typed_data_entries=8,
            explicit_size_entries=2,
            explicit_alignment_entries=1,
            explicit_initializer_entries=4,
        ),
    ]
    markdown = "\n".join(render_native_link_status_markdown(statuses))
    assert (
        "| grim.dll | current | 3 | 2 | 1 | passed | yes | no | no | 0 | 7 | 5 |"
    ) in markdown
    assert (
        "| grim.dll | game_data=3, import=2 | 3 | 11 | 8 | 2 | 1 | 4 |"
    ) in markdown
    assert "Artifact freshness issues:" not in markdown


def test_native_link_status_labels_changed_or_mixed_artifacts_stale(tmp_path: Path) -> None:
    analysis_dir, canonical_source = _write_native_link_fixture(tmp_path)
    canonical_source.write_bytes(b"changed after audit")
    data_path = analysis_dir / "data.json"
    data = json.loads(data_path.read_text(encoding="utf-8"))
    data["audit_digest"] = "b" * 64
    data_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    status = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]

    assert status.artifact_state == "stale"
    assert "artifact audit digests disagree" in status.artifact_note
    assert "1 recorded file inputs changed or missing" in status.artifact_note
    markdown = "\n".join(render_native_link_status_markdown([status]))
    assert "Gate values in `stale` rows are historical snapshots" in markdown
    assert "`grim.dll`: **stale**" in markdown


def test_native_link_status_projects_shared_json_inputs_by_image(
    tmp_path: Path,
) -> None:
    artifact_dir, _ = _write_native_link_fixture(tmp_path)
    shared_map = tmp_path / "shared-map.json"
    shared_map.write_text(
        json.dumps(
            [
                {"program": "crimsonland.exe", "name": "other"},
                {"program": "grim.dll", "name": "target"},
            ],
        ),
        encoding="utf-8",
    )
    paths = {
        name: artifact_dir / name
        for name in ("objects.json", "closure.json", "data.json")
    }
    payloads = {
        name: json.loads(path.read_text(encoding="utf-8"))
        for name, path in paths.items()
    }
    payloads["objects.json"]["provenance"]["selection_inputs"].append(
        {
            "path": "shared-map.json",
            "projection": {
                "kind": "json-program-v1",
                "program": "grim.dll",
            },
            "repository_relative": True,
            "sha256": native_json_program_sha256(shared_map, "grim.dll"),
        },
    )
    digest_payload = {
        "data_manifest": {
            key: value
            for key, value in payloads["data.json"].items()
            if key != "audit_digest"
        },
        "object_manifest": {
            key: value
            for key, value in payloads["objects.json"].items()
            if key != "audit_digest"
        },
        "symbol_closure": {
            key: value
            for key, value in payloads["closure.json"].items()
            if key != "audit_digest"
        },
    }
    audit_digest = hashlib.sha256(
        json.dumps(
            digest_payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    ).hexdigest()
    for name, payload in payloads.items():
        payload["audit_digest"] = audit_digest
        paths[name].write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    shared_map.write_text(
        json.dumps(
            [
                {"program": "crimsonland.exe", "name": "changed-other"},
                {"program": "grim.dll", "name": "target"},
            ],
        ),
        encoding="utf-8",
    )
    unrelated = collect_native_link_statuses(
        analysis_root=artifact_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]
    assert unrelated.artifact_state == "current"

    shared_map.write_text(
        json.dumps(
            [
                {"program": "crimsonland.exe", "name": "changed-other"},
                {"program": "grim.dll", "name": "changed-target"},
            ],
        ),
        encoding="utf-8",
    )
    relevant = collect_native_link_statuses(
        analysis_root=artifact_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]
    assert relevant.artifact_state == "stale"
    assert "1 recorded file inputs changed or missing" in relevant.artifact_note


def test_native_link_status_detects_report_content_changed_without_digest(
    tmp_path: Path,
) -> None:
    analysis_dir, _ = _write_native_link_fixture(tmp_path)
    closure_path = analysis_dir / "closure.json"
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["summary"]["resolved_symbols"] = 99
    closure_path.write_text(json.dumps(closure, sort_keys=True), encoding="utf-8")

    status = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]

    assert status.artifact_state == "stale"
    assert "artifact content does not match audit digest" in status.artifact_note


def test_native_link_status_detects_changed_data_definitions(tmp_path: Path) -> None:
    analysis_dir, _ = _write_native_link_fixture(tmp_path)
    (tmp_path / "definitions.json").write_text('{"schema":2}', encoding="utf-8")

    status = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]

    assert status.artifact_state == "stale"
    assert "1 recorded file inputs changed or missing" in status.artifact_note


def test_native_link_status_detects_changed_companion_artifact(tmp_path: Path) -> None:
    analysis_dir, _ = _write_native_link_fixture(tmp_path)
    (analysis_dir / "objects.txt").write_text("different.obj\n", encoding="utf-8")

    status = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]

    assert status.artifact_state == "stale"
    assert "1 generated linker artifacts changed or missing" in status.artifact_note


def test_native_link_status_can_allow_absent_ignored_toolchain(tmp_path: Path) -> None:
    analysis_dir, _ = _write_native_link_fixture(tmp_path)
    paths = {
        name: analysis_dir / name
        for name in ("objects.json", "closure.json", "data.json")
    }
    payloads = {
        name: json.loads(path.read_text(encoding="utf-8"))
        for name, path in paths.items()
    }
    objects = payloads["objects.json"]
    objects["provenance"]["toolchain"]["wibo"] = {
        "path": "tools/match/bin/wibo",
        "repository_relative": True,
        "sha256": "1" * 64,
    }
    objects["provenance"]["toolchain"]["compiler_bundles"] = [
        {
            "bundle_sha256": "2" * 64,
            "compiler": "msvc6.5",
            "included_trees": ["Bin", "Include"],
            "root": "tools/match/compilers/msvc6.5",
        },
    ]
    digest_payload = {
        "data_manifest": {
            key: value
            for key, value in payloads["data.json"].items()
            if key != "audit_digest"
        },
        "object_manifest": {
            key: value
            for key, value in objects.items()
            if key != "audit_digest"
        },
        "symbol_closure": {
            key: value
            for key, value in payloads["closure.json"].items()
            if key != "audit_digest"
        },
    }
    audit_digest = hashlib.sha256(
        json.dumps(
            digest_payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    ).hexdigest()
    for name, payload in payloads.items():
        payload["audit_digest"] = audit_digest
        paths[name].write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    strict = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]
    portable = collect_native_link_statuses(
        analysis_root=analysis_dir.parent,
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
        allow_absent_toolchain=True,
    )[0]

    assert strict.artifact_state == "stale"
    assert "1 recorded file inputs changed or missing" in strict.artifact_note
    assert "1 compiler bundles changed or missing" in strict.artifact_note
    assert portable.artifact_state == "current"
    assert portable.artifact_note == (
        "artifact digest and required repository inputs agree; "
        "toolchain availability not required"
    )


def test_native_link_status_reports_missing_artifacts_without_claiming_metrics(
    tmp_path: Path,
) -> None:
    status = collect_native_link_statuses(
        analysis_root=tmp_path / "analysis" / "native",
        repo_root=tmp_path,
        scope="port",
        images=("grim.dll",),
    )[0]

    assert status.artifact_state == "missing"
    assert status.artifact_note == "missing objects.json, closure.json, data.json"
    markdown = "\n".join(render_native_link_status_markdown([status]))
    assert (
        "| grim.dll | missing | unknown | unknown | unknown | unknown | unknown | "
        "unknown | unknown | unknown | unknown | unknown |"
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


def test_match_shard_excludes_semantic_complete_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def make_status(function: str, recovery: str | None) -> ScratchStatus:
        return ScratchStatus(
            config=ScratchConfig(
                directory=tmp_path / "scratches" / function,
                function=function,
                image="crimsonland.exe",
                compiler="msvc6.5",
                cflags="/O2",
                source="scratch.cpp",
                end_va=None,
                symbol=None,
                note="",
                recovery=recovery,
            ),
            address=0x401000,
            target_size=100,
            ratio=0.5,
            prefix_instructions=1,
            target_instructions=2,
            candidate_instructions=2,
            error=None,
        )

    unspecified = make_status("unspecified_target", None)
    semantic_complete = make_status("semantic_complete_target", "semantic-complete")
    rows = [
        TriageRow(
            image="crimsonland.exe",
            function="missing_target",
            address=0x401100,
            target_size=100,
            state="missing",
            exact_bytes=0,
            fuzzy_weighted_bytes=0.0,
            candidate_bytes=0,
            scratch_count=0,
        ),
        TriageRow(
            image="crimsonland.exe",
            function=unspecified.config.function,
            address=unspecified.address,
            target_size=unspecified.target_size,
            state="wip",
            exact_bytes=0,
            fuzzy_weighted_bytes=unspecified.fuzzy_weighted_bytes,
            candidate_bytes=unspecified.target_size,
            scratch_count=1,
            best_status=unspecified,
        ),
        TriageRow(
            image="crimsonland.exe",
            function=semantic_complete.config.function,
            address=0x401200,
            target_size=semantic_complete.target_size,
            state="wip",
            exact_bytes=0,
            fuzzy_weighted_bytes=semantic_complete.fuzzy_weighted_bytes,
            candidate_bytes=semantic_complete.target_size,
            scratch_count=1,
            best_status=semantic_complete,
        ),
    ]
    monkeypatch.setattr("crimson.cli.match.matchlib.validate_matching_workspace", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match._batch_changed_paths", list)
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_scratch_statuses", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_triage_rows", lambda *args, **kwargs: rows)
    monkeypatch.setattr("crimson.cli.match.matchlib.validate_match_claim", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match._git_head", lambda: "a" * 40)

    completed = CliRunner().invoke(
        match_app,
        [
            "shard",
            "--workers",
            "1",
            "--match-root",
            str(tmp_path),
            "--out",
            str(tmp_path / "default"),
            "--json",
        ],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    default_targets = payload["assignments"][0]["targets"]
    assert {target["function"] for target in default_targets} == {
        "missing_target",
        "unspecified_target",
    }
    assert payload["filters"]["recoveries"] == ["incomplete", "unspecified"]

    completed = CliRunner().invoke(
        match_app,
        [
            "shard",
            "--workers",
            "1",
            "--match-root",
            str(tmp_path),
            "--recovery",
            "semantic-complete",
            "--out",
            str(tmp_path / "explicit"),
            "--json",
        ],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    explicit_targets = payload["assignments"][0]["targets"]
    assert {target["function"] for target in explicit_targets} == {
        "missing_target",
        "semantic_complete_target",
    }
    assert payload["filters"]["recoveries"] == ["semantic-complete"]

    completed = CliRunner().invoke(
        match_app,
        [
            "shard",
            "--workers",
            "1",
            "--match-root",
            str(tmp_path),
            "--mode",
            "residual-audit",
            "--out",
            str(tmp_path / "residual"),
            "--json",
        ],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    residual_targets = payload["assignments"][0]["targets"]
    assert {target["function"] for target in residual_targets} == {
        "semantic_complete_target",
    }
    assert payload["filters"]["mode"] == "residual-audit"
    assert payload["filters"]["states"] == ["audit", "wip"]
    assert payload["filters"]["recoveries"] == ["semantic-complete"]


def test_match_shard_empty_recovery_queue_points_to_residual_audit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    status = ScratchStatus(
        config=ScratchConfig(
            directory=tmp_path / "scratches" / "residual",
            function="residual",
            image="crimsonland.exe",
            compiler="msvc6.5",
            cflags="/O2",
            source="scratch.cpp",
            end_va=None,
            symbol=None,
            note="",
            recovery="semantic-complete",
        ),
        address=0x401000,
        target_size=100,
        ratio=0.5,
        prefix_instructions=1,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    rows = [
        TriageRow(
            image="crimsonland.exe",
            function="residual",
            address=status.address,
            target_size=status.target_size,
            state="wip",
            exact_bytes=0,
            fuzzy_weighted_bytes=status.fuzzy_weighted_bytes,
            candidate_bytes=status.target_size,
            scratch_count=1,
            best_status=status,
        ),
    ]
    monkeypatch.setattr("crimson.cli.match.matchlib.validate_matching_workspace", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match._batch_changed_paths", list)
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_scratch_statuses", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match.matchlib.collect_triage_rows", lambda *args, **kwargs: rows)

    completed = CliRunner().invoke(
        match_app,
        ["shard", "--workers", "1", "--match-root", str(tmp_path), "--json"],
    )

    assert completed.exit_code == 1
    payload = json.loads(completed.output)
    assert payload["error"] == "empty-shard"
    assert payload["semantic_complete_residual_targets"] == 1
    assert payload["suggested_command"] == (
        "crimson match shard --mode residual-audit --workers <N>"
    )
    assert not (tmp_path / ".cache" / "shards" / "plan.json").exists()


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
    environments: list[dict[str, str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        environments.append(cast(dict[str, str], kwargs["env"]))
        cwd = Path(str(kwargs["cwd"]))
        (cwd / "scratch.obj").write_bytes(" ".join(command).encode())
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)

    overlay = tmp_path / "overlay"
    overlay.mkdir()
    optimized = compile_scratch(
        replace(config, include_overlay=overlay),
        Path("match"),
    )
    unoptimized = compile_scratch(replace(config, cflags="/Od"), Path("match"))
    cached = compile_scratch(replace(config, include_overlay=overlay), Path("match"))
    forced = compile_scratch(
        replace(config, include_overlay=overlay),
        Path("match"),
        force=True,
    )

    assert optimized != unoptimized
    assert optimized.parent != unoptimized.parent
    assert optimized.read_bytes() != unoptimized.read_bytes()
    assert cached == optimized
    assert forced == optimized
    assert len(commands) == 3
    assert Path(commands[0][0]).is_absolute()
    assert commands[0][0] == str((match_root / "cl.sh").resolve())
    assert environments[0]["CRIMSON_MATCH_INCLUDE_OVERLAY"] == str(overlay)
    assert "CRIMSON_MATCH_INCLUDE_OVERLAY" not in environments[1]


def test_compile_scratch_stages_auto_inline_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    match_root = tmp_path / "match"
    scratch = tmp_path / "scratch"
    compiler = match_root / "compilers" / "msvc6.5" / "Bin"
    scratch.mkdir()
    compiler.mkdir(parents=True)
    source = scratch / "scratch.c"
    original = (
        "#define LOCAL(type) static type\n"
        "LOCAL(void)\n"
        "helper(void)\n"
        "/* a comment with { braces } */\n"
        "{\n"
        "  const char *brace = \"}\";\n"
        "}\n"
    )
    source.write_text(original, encoding="utf-8")
    (scratch / "scratch.conf").write_text(
        "FUNCTION=helper SOURCE=scratch.c AUTO_INLINE_OFF=helper\n",
        encoding="utf-8",
    )
    (match_root / "cl.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (compiler / "CL.EXE").write_bytes(b"compiler")
    config = load_scratch_config(scratch)
    staged_sources: list[str] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cwd = Path(str(kwargs["cwd"]))
        staged_sources.append((cwd / "scratch.c").read_text(encoding="utf-8"))
        (cwd / "scratch.obj").write_bytes(b"object")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    obj = compile_scratch(config, match_root)

    assert obj.read_bytes() == b"object"
    assert source.read_text(encoding="utf-8") == original
    assert staged_sources == [
        original.replace(
            "LOCAL(void)\nhelper(void)\n/* a comment with { braces } */\n{\n"
            "  const char *brace = \"}\";\n}\n",
            "#pragma auto_inline(off)\n"
            "LOCAL(void)\nhelper(void)\n/* a comment with { braces } */\n{\n"
            "  const char *brace = \"}\";\n}\n"
            "#pragma auto_inline(on)\n",
        ),
    ]

    with pytest.raises(ValueError, match="AUTO_INLINE_OFF=missing.*found 0"):
        compile_scratch(replace(config, auto_inline_off=("missing",)), match_root)


def test_compile_scratch_extracts_hash_pinned_archive_member(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "foo"
    scratch.mkdir(parents=True)
    obj_data = build_object(b"\xc3", [("_foo", 0)], [])
    archive_data = build_archive(r"obj\i386\foo.obj", obj_data)
    archive = scratch / "provider.lib"
    archive.write_bytes(archive_data)
    digest = hashlib.sha256(archive_data).hexdigest()
    (scratch / "scratch.conf").write_text(
        "FUNCTION=foo ARCHIVE=provider.lib "
        "ARCHIVE_MEMBER='obj\\i386\\foo.obj' "
        f"ARCHIVE_SHA256={digest} SYMBOL=_foo\n",
        encoding="utf-8",
    )
    config = load_scratch_config(scratch)

    extracted = compile_scratch(config, match_root)
    cached = compile_scratch(config, match_root)

    assert extracted == cached
    assert extracted.name == "foo.obj"
    assert extracted.read_bytes() == obj_data
    assert _scratch_build_key(config, match_root)["archive_member"] == r"obj\i386\foo.obj"

    with pytest.raises(ValueError, match="archive SHA-256 mismatch"):
        compile_scratch(replace(config, archive_sha256="0" * 64), match_root)
    with pytest.raises(ValueError, match="expected exactly one archive member"):
        compile_scratch(replace(config, archive_member="missing.obj"), match_root)


def test_compile_scratch_materializes_structural_import_thunk(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "sprintf"
    scratch.mkdir(parents=True)
    (scratch / "scratch.conf").write_text(
        "FUNCTION=sprintf IMPORT_THUNK=sprintf\n",
        encoding="utf-8",
    )
    config = load_scratch_config(scratch)

    obj_path = compile_scratch(config, match_root)
    function = extract_object_function(parse_coff_object(obj_path.read_bytes()))

    assert function.data == bytes.fromhex("ff2500000000")
    assert function.relocation_offsets == frozenset({2})
    assert function.relocation_references[0].symbol_name == "__imp_sprintf"
    assert _scratch_build_key(config, match_root)["import_thunk"] == "sprintf"


def test_structural_import_thunk_audits_exact_iat_target() -> None:
    iat_address = 0x00402000
    target = bytes.fromhex("ff25") + struct.pack("<I", iat_address)
    mapped = bytearray(0x3000)
    mapped[: len(target)] = target
    image = LoadedImage(bytes(mapped), 0x00400000, len(mapped))
    catalog = ReferenceCatalog(
        {iat_address: ("sprintf",)},
        {"sprintf": (iat_address,)},
        frozenset({iat_address}),
    )
    candidate = extract_object_function(
        parse_coff_object(_import_thunk_object_bytes("sprintf")),
    )

    result = match_function(
        target,
        candidate,
        image=image,
        target_va=0x00400000,
        reference_catalog=catalog,
    )
    wrong = match_function(
        bytes.fromhex("ff25") + struct.pack("<I", iat_address + 4),
        candidate,
        image=image,
        target_va=0x00400000,
        reference_catalog=catalog,
    )

    assert result.exact
    assert result.masked_operand_audit.ok_count == 1
    assert not wrong.exact
    assert wrong.masked_operand_audit.mismatch_count == 1


def test_compile_scratch_suggests_member_defining_missing_symbol(tmp_path: Path) -> None:
    match_root = tmp_path / "match"
    scratch = match_root / "scratches" / "foo"
    scratch.mkdir(parents=True)
    archive_data = build_archive_members(
        [
            ("wrong.obj", build_object(b"\xc3", [("_wrong", 0)], [])),
            ("right.obj", build_object(b"\xc3", [("_foo", 0)], [])),
        ],
    )
    archive = scratch / "provider.lib"
    archive.write_bytes(archive_data)
    digest = hashlib.sha256(archive_data).hexdigest()
    (scratch / "scratch.conf").write_text(
        "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=wrong.obj "
        f"ARCHIVE_SHA256={digest} SYMBOL=_foo\n",
        encoding="utf-8",
    )
    config = load_scratch_config(scratch)

    with pytest.raises(
        ValueError,
        match=r"missing function symbol '_foo'; defining archive members: 'right.obj'",
    ):
        compile_scratch(config, match_root)


def test_validate_command_accepts_pinned_archive_scratch(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    obj_data = build_object(b"\xc3", [("_foo", 0)], [])
    archive_data = build_archive("foo.obj", obj_data)
    (scratch / "provider.lib").write_bytes(archive_data)
    digest = hashlib.sha256(archive_data).hexdigest()
    (scratch / "scratch.conf").write_text(
        "FUNCTION=foo ARCHIVE=provider.lib ARCHIVE_MEMBER=foo.obj "
        f"ARCHIVE_SHA256={digest} SYMBOL=_foo\n",
        encoding="utf-8",
    )

    completed = CliRunner().invoke(match_app, ["validate", str(scratch)])

    assert completed.exit_code == 0
    assert completed.output == "ok\n"


def test_exception_summary_keeps_first_actionable_compiler_diagnostic() -> None:
    error = RuntimeError(
        "cl failed:\n"
        "scratch.cpp\n"
        "scratch.cpp(7) : error C2143: syntax error : missing ';' before '}'\n"
        "scratch.cpp(8) : error C2059: syntax error : '}'\n",
    )

    assert _exception_summary(error) == (
        "cl failed: scratch.cpp(7) : error C2143: "
        "syntax error : missing ';' before '}'"
    )
    assert _exception_summary(RuntimeError("plain failure\nextra detail")) == "plain failure"
    assert _exception_summary(RuntimeError()) == "RuntimeError"


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


def test_source_overlay_can_shadow_an_included_match_header(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    match_root = tmp_path / "match"
    include_root = match_root / "include"
    include_root.mkdir(parents=True)
    header = include_root / "shared_impl.h"
    header.write_text("baseline header\n", encoding="utf-8")
    scratch = match_root / "scratches" / "foo"
    scratch.mkdir(parents=True)
    source = scratch / "scratch.cpp"
    source.write_text('#include "shared_impl.h"\n', encoding="utf-8")
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
    observed: list[tuple[str, str]] = []

    def fake_evaluate(probe_config: ScratchConfig, root: Path) -> ScratchStatus:
        assert root == match_root.resolve()
        observed.append(
            (
                (probe_config.directory / probe_config.source).read_text(encoding="utf-8"),
                (probe_config.directory / "shared_impl.h").read_text(encoding="utf-8"),
            ),
        )
        return ScratchStatus(
            config=probe_config,
            address=0x401000,
            target_size=10,
            ratio=0.75,
            prefix_instructions=2,
            target_instructions=4,
            candidate_instructions=4,
            error=None,
        )

    monkeypatch.setattr("crimson.match.evaluate_scratch", fake_evaluate)

    status = evaluate_source_overlay(
        config,
        "variant header\n",
        source_path=header,
        match_root=match_root,
    )

    assert status.ratio == 0.75
    assert observed == [('#include "shared_impl.h"\n', "variant header\n")]
    assert source.read_text(encoding="utf-8") == '#include "shared_impl.h"\n'
    assert header.read_text(encoding="utf-8") == "baseline header\n"


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
    assert recorded["schema"] == 1
    assert recorded["kind"] == "probe"
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


def test_compiler_scan_prefers_exact_wins_and_canonical_ties(tmp_path: Path) -> None:
    foo_config = ScratchConfig(
        directory=tmp_path / "foo",
        function="foo",
        image="crimsonland.exe",
        compiler="msvc6.5",
        cflags="/O2",
        source="scratch.cpp",
        end_va=None,
        symbol=None,
        note="",
    )
    bar_config = replace(foo_config, directory=tmp_path / "bar", function="bar")
    foo_baseline = ScratchStatus(
        config=foo_config,
        address=0x401000,
        target_size=20,
        ratio=0.75,
        prefix_instructions=2,
        target_instructions=5,
        candidate_instructions=5,
        error=None,
        masked_ok=1,
    )
    bar_baseline = replace(
        foo_baseline,
        config=bar_config,
        address=0x401020,
        ratio=0.9,
        prefix_instructions=4,
    )
    foo_exact = replace(
        foo_baseline,
        config=replace(foo_config, compiler="msvc6.5pp"),
        ratio=1.0,
        prefix_instructions=5,
        masked_ok=2,
    )
    bar_tie = replace(
        bar_baseline,
        config=replace(bar_config, compiler="msvc6.6"),
    )
    bar_error = replace(
        bar_baseline,
        config=replace(bar_config, compiler="msvc7.0"),
        target_size=0,
        ratio=None,
        prefix_instructions=0,
        target_instructions=0,
        candidate_instructions=0,
        error="compiler unavailable",
    )

    rows = build_compiler_scan_rows(
        [foo_baseline, bar_baseline],
        [foo_exact, bar_tie, bar_error],
    )

    assert [row.classification for row in rows] == ["exact", "tied"]
    assert rows[0].best.config.compiler == "msvc6.5pp"
    assert rows[1].best is bar_baseline
    assert compiler_scan_summary(rows, [foo_exact, bar_tie, bar_error]) == {
        "targets": 2,
        "profiles": 3,
        "exact": 1,
        "improved": 0,
        "tied": 1,
        "errors": 1,
    }
    assert compiler_scan_row_payload(rows[0])["fuzzy_delta_bytes"] == 5.0
    rendered = render_compiler_scan_rows(rows)
    assert "msvc6.5pp" in rendered
    assert "exact" in rendered


def test_compiler_scan_cli_reports_only_leads_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = ScratchConfig(
        directory=tmp_path / "foo",
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
        target_size=20,
        ratio=0.75,
        prefix_instructions=2,
        target_instructions=5,
        candidate_instructions=5,
        error=None,
        masked_ok=1,
    )

    def fake_collect(*args: object, **kwargs: object) -> list[ScratchStatus]:
        del args
        compiler = kwargs.get("compiler")
        if compiler == "msvc6.5pp":
            return [
                replace(
                    baseline,
                    config=replace(config, compiler="msvc6.5pp"),
                    ratio=1.0,
                    prefix_instructions=5,
                    masked_ok=2,
                ),
            ]
        return [baseline]

    monkeypatch.setattr("crimson.cli.match.matchlib.collect_scratch_statuses", fake_collect)
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.available_scratch_compilers",
        lambda match_root: ("msvc6.5", "msvc6.5pp"),
    )

    completed = CliRunner().invoke(
        match_app,
        ["compiler-scan", "--match-root", str(tmp_path), "--jobs", "1", "--json", "--check"],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    assert payload["summary"] == {
        "targets": 1,
        "profiles": 2,
        "exact": 1,
        "improved": 0,
        "tied": 0,
        "errors": 0,
    }
    assert payload["rows"][0]["classification"] == "exact"
    assert payload["rows"][0]["best"]["compiler"] == "msvc6.5pp"


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
        lambda obj, symbol, *, extent="symbol", end_symbol=None, size=None: ObjectFunction(
            name="foo",
            data=b"\xc3",
            relocation_offsets=frozenset(),
        ),
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
        lambda obj, symbol, **kwargs: ObjectFunction(
            name="selected",
            data=b"\xc3",
            relocation_offsets=frozenset(),
        ),
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
    assert len(plan["batch_id"]) == 16
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
    first_claim = json.loads(claim_paths[0].read_text(encoding="utf-8"))
    assert first_claim["kind"] == WORKER_CLAIM_KIND
    assert first_claim["batch_id"] == plan["batch_id"]
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


def test_worker_outcome_records_falsification_for_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratches" / "game_is_full_version"
    scratch.mkdir(parents=True)
    (scratch / "scratch.conf").write_text(
        "FUNCTION=game_is_full_version\nRECOVERY=semantic-complete\nRESIDUAL=compiler\n",
        encoding="utf-8",
    )
    (scratch / "scratch.cpp").write_text(
        'extern "C" int game_is_full_version(void) { return 1; }\n',
        encoding="utf-8",
    )
    claim_path = tmp_path / "worker-01.json"
    claim_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": WORKER_CLAIM_KIND,
                "batch_id": "1" * 16,
                "scope": "port",
                "base_commit": "a" * 40,
                "worker": "worker-01",
                "targets": [
                    {
                        "image": "crimsonland.exe",
                        "function": "game_is_full_version",
                        "address": 0x0041DF40,
                        "target_bytes": 6,
                        "state": "wip",
                        "fuzzy_gap_bytes": 3.0,
                        "scratch": "scratches/game_is_full_version",
                        "baseline": {
                            "state": "wip",
                            "match_ratio": 0.5,
                            "prefix_instructions": 1,
                            "candidate_instructions": 2,
                            "target_instructions": 2,
                            "references": {"unresolved": 0, "mismatch": 0},
                        },
                    },
                ],
            },
        ),
        encoding="utf-8",
    )
    status = ScratchStatus(
        config=load_scratch_config(scratch),
        address=0x0041DF40,
        target_size=6,
        ratio=0.5,
        prefix_instructions=1,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.validate_match_claim", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.collect_scratch_statuses",
        lambda *args, **kwargs: [status],
    )

    completed = CliRunner().invoke(
        match_app,
        [
            "worker-outcome",
            str(claim_path),
            "scratches/game_is_full_version",
            "--match-root",
            str(tmp_path),
            "--disposition",
            "falsified",
            "--summary",
            "The alternate profile preserves the same residual.",
            "--hypothesis",
            "toolchain:VC6 profile split",
            "--evidence",
            "profiles.json: all supported profiles retain the mismatch",
            "--json",
        ],
    )

    assert completed.exit_code == 0
    payload = json.loads(completed.output)
    assert payload["kind"] == WORKER_OUTCOME_KIND
    assert payload["disposition"] == "falsified"
    assert payload["hypotheses"] == [
        {"kind": "toolchain", "description": "VC6 profile split"},
    ]
    records = [
        json.loads(line)
        for line in (scratch / WORKER_OUTCOME_FILE).read_text(encoding="utf-8").splitlines()
    ]
    assert records == [payload]


def test_worker_check_can_require_batch_scoped_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratches" / "game_is_full_version"
    scratch.mkdir(parents=True)
    (scratch / "scratch.conf").write_text(
        "FUNCTION=game_is_full_version\nRECOVERY=semantic-complete\nRESIDUAL=compiler\n",
        encoding="utf-8",
    )
    (scratch / "scratch.cpp").write_text(
        'extern "C" int game_is_full_version(void) { return 1; }\n',
        encoding="utf-8",
    )
    target = {
        "image": "crimsonland.exe",
        "function": "game_is_full_version",
        "address": 0x0041DF40,
        "target_bytes": 6,
        "state": "wip",
        "fuzzy_gap_bytes": 3.0,
        "scratch": "scratches/game_is_full_version",
    }
    claim = {
        "schema": 1,
        "kind": WORKER_CLAIM_KIND,
        "batch_id": "2" * 16,
        "scope": "port",
        "base_commit": "a" * 40,
        "worker": "worker-01",
        "targets": [target],
    }
    claim_path = tmp_path / "worker-01.json"
    claim_path.write_text(json.dumps(claim), encoding="utf-8")
    status = ScratchStatus(
        config=load_scratch_config(scratch),
        address=0x0041DF40,
        target_size=6,
        ratio=0.5,
        prefix_instructions=1,
        target_instructions=2,
        candidate_instructions=2,
        error=None,
    )
    monkeypatch.setattr("crimson.cli.match.matchlib.validate_match_claim", lambda *args, **kwargs: [])
    monkeypatch.setattr("crimson.cli.match._batch_changed_paths", lambda base_commit=None: [])
    monkeypatch.setattr(
        "crimson.cli.match.matchlib.collect_scratch_statuses",
        lambda *args, **kwargs: [status],
    )

    missing = CliRunner().invoke(
        match_app,
        [
            "worker-check",
            str(claim_path),
            "--match-root",
            str(tmp_path),
            "--require-outcome",
            "--json",
        ],
    )

    assert missing.exit_code == 1
    assert json.loads(missing.output)["summary"]["missing_outcomes"] == 1

    outcome = {
        "schema": 1,
        "kind": WORKER_OUTCOME_KIND,
        "recorded_at": "2026-07-27T00:00:00+00:00",
        "batch_id": claim["batch_id"],
        "base_commit": claim["base_commit"],
        "worker": claim["worker"],
        "scratch": target["scratch"],
        "function": target["function"],
        "address": target["address"],
        "disposition": "blocked",
        "summary": "The exact historical compiler bundle is unavailable.",
        "hypotheses": [],
        "evidence": ["compiler inventory contains no build-8047 bundle"],
        "baseline": None,
        "status": {"state": "wip"},
    }
    (scratch / WORKER_OUTCOME_FILE).write_text(
        json.dumps(outcome) + "\n",
        encoding="utf-8",
    )

    complete = CliRunner().invoke(
        match_app,
        [
            "worker-check",
            str(claim_path),
            "--match-root",
            str(tmp_path),
            "--require-outcome",
            "--json",
        ],
    )

    assert complete.exit_code == 0
    report = json.loads(complete.output)
    assert report["summary"]["outcomes"] == 1
    assert report["summary"]["missing_outcomes"] == 0
    assert report["targets"][0]["latest_outcome"]["disposition"] == "blocked"
