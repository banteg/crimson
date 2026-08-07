from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

from crimson import match as matchlib
from crimson.native_link import (
    DEFAULT_LINKER_ALIAS_CONFIGS,
    DEFAULT_PROVIDER_CONFIGS,
    DEFAULT_TRANSLATION_UNIT_CONFIGS,
    IMAGE_REL_I386_DIR32,
    IMAGE_SCN_LNK_COMDAT,
    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    NativeCompilerBundleSnapshot,
    NativeDataObjectRecord,
    NativeFunctionBinding,
    NativeLinkerAliasObjectRecord,
    NativeLinkerAliasSpec,
    NativeObjectRecord,
    NativeObjectSet,
    NativeSymbolCatalog,
    NativeToolchainSnapshot,
    _native_link_image_options,
    _normalized_coff_sha256,
    _resolve_wibo_path,
    _select_unique_statuses,
    _validate_loaded_configs,
    _vc6_linker_internal_name,
    data_manifest_payload,
    load_native_data_definitions,
    load_native_linker_alias_config,
    load_native_provider_config,
    load_native_translation_unit_config,
    native_data_object_bytes,
    native_linker_alias_object_bytes,
    native_pe_imports,
    native_pe_summary,
    native_provider_coverage,
    native_provider_placeholder_object_bytes,
    normalize_coff_archive_timestamps,
    normalize_pe_timestamp,
    object_manifest_payload,
    render_export_definition,
    render_native_import_definition,
    render_object_list,
    symbol_closure_payload,
)


def _config(
    directory: Path,
    function: str,
    *,
    end_va: int | None = None,
) -> matchlib.ScratchConfig:
    return matchlib.ScratchConfig(
        directory=directory,
        function=function,
        image="grim.dll",
        compiler="msvc6.5",
        cflags="/O2 /GB /W3 /GR-",
        source="scratch.cpp",
        end_va=end_va,
        symbol=None,
        note="",
    )


def _status(
    directory: Path,
    function: str,
    address: int,
    *,
    end_va: int | None = None,
    state: str = "match",
) -> matchlib.ScratchStatus:
    ratio = None if state == "error" else 1.0 if state in {"match", "audit"} else 0.5
    return matchlib.ScratchStatus(
        config=_config(directory, function, end_va=end_va),
        address=address,
        target_size=4,
        ratio=ratio,
        prefix_instructions=1,
        target_instructions=1,
        candidate_instructions=1,
        error="failed" if state == "error" else None,
        masked_unresolved=1 if state == "audit" else 0,
    )


def _function(name: str, address: int) -> matchlib.FunctionSymbol:
    return matchlib.FunctionSymbol(name=name, address=address, end=address + 4, size=4)


def _coff(
    *,
    definitions: tuple[tuple[str, int], ...] = (),
    undefined: tuple[str, ...] = (),
    comdat_definitions: tuple[str, ...] = (),
    comdat_selection: int = 2,
) -> matchlib.CoffObject:
    sections = (
        matchlib.CoffSection(
            ".text",
            b"\xc3",
            0x60000020,
            (),
            index=1,
            logical_size=1,
        ),
        matchlib.CoffSection(
            ".rdata",
            b"\x00\x00\x00\x00",
            0x40000040 | IMAGE_SCN_LNK_COMDAT,
            (),
            index=2,
            comdat_key=comdat_definitions[0] if comdat_definitions else None,
            comdat_selection=comdat_selection,
            logical_size=4,
        ),
    )
    symbols: list[matchlib.CoffSymbol] = []
    for name, section_number in definitions:
        symbols.append(
            matchlib.CoffSymbol(
                raw_index=len(symbols),
                name=name,
                value=0,
                section_number=section_number,
                symbol_type=0x20,
                storage_class=matchlib.IMAGE_SYM_CLASS_EXTERNAL,
            ),
        )
    for name in comdat_definitions:
        symbols.append(
            matchlib.CoffSymbol(
                raw_index=len(symbols),
                name=name,
                value=0,
                section_number=2,
                symbol_type=0,
                storage_class=matchlib.IMAGE_SYM_CLASS_EXTERNAL,
            ),
        )
    for name in undefined:
        symbols.append(
            matchlib.CoffSymbol(
                raw_index=len(symbols),
                name=name,
                value=0,
                section_number=0,
                symbol_type=0,
                storage_class=matchlib.IMAGE_SYM_CLASS_EXTERNAL,
            ),
        )
    return matchlib.CoffObject(sections=sections, symbols=tuple(symbols))


def test_unique_canonical_selection_is_address_ordered(tmp_path: Path) -> None:
    manifest = matchlib.FunctionManifest(
        image_name="grim.dll",
        image_base=0x10000000,
        functions=(
            _function("first", 0x10001000),
            _function("second", 0x10001010),
        ),
    )
    statuses = [
        _status(tmp_path / "second", "second", 0x10001010),
        _status(tmp_path / "first", "first", 0x10001000),
    ]

    selected = _select_unique_statuses(statuses, manifest)

    assert [status.config.function for status in selected] == ["first", "second"]


def test_unique_canonical_selection_rejects_duplicates(tmp_path: Path) -> None:
    manifest = matchlib.FunctionManifest(
        image_name="grim.dll",
        image_base=0x10000000,
        functions=(_function("first", 0x10001000),),
    )
    statuses = [
        _status(tmp_path / "a", "first", 0x10001000),
        _status(tmp_path / "b", "first", 0x10001000),
    ]

    with pytest.raises(ValueError, match="duplicate canonical target"):
        _select_unique_statuses(statuses, manifest)


def test_unique_canonical_selection_requires_exact_function_name(tmp_path: Path) -> None:
    manifest = matchlib.FunctionManifest(
        image_name="grim.dll",
        image_base=0x10000000,
        functions=(_function("canonical", 0x10001000),),
    )

    with pytest.raises(ValueError, match="must use canonical name"):
        _select_unique_statuses(
            [_status(tmp_path / "alias", "0x10001000", 0x10001000)],
            manifest,
        )


def test_unique_canonical_selection_checks_excluded_native_boundaries(tmp_path: Path) -> None:
    manifest = matchlib.FunctionManifest(
        image_name="grim.dll",
        image_base=0x10000000,
        functions=(
            _function("first", 0x10001000),
            _function("third", 0x10001030),
        ),
    )
    native_manifest = matchlib.FunctionManifest(
        image_name="grim.dll",
        image_base=0x10000000,
        functions=(
            _function("first", 0x10001000),
            _function("excluded", 0x10001020),
            _function("third", 0x10001030),
        ),
    )

    with pytest.raises(ValueError, match="overlaps next function at 0x10001020"):
        _select_unique_statuses(
            [
                _status(
                    tmp_path / "first",
                    "first",
                    0x10001000,
                    end_va=0x10001021,
                ),
                _status(tmp_path / "third", "third", 0x10001030),
            ],
            manifest,
            native_manifest=native_manifest,
        )


def test_object_manifest_is_deterministic_and_content_addressed(tmp_path: Path) -> None:
    scratch = tmp_path / "tools" / "match" / "scratches" / "first"
    scratch.mkdir(parents=True)
    source = scratch / "scratch.cpp"
    config_path = scratch / "scratch.conf"
    object_path = scratch / "build" / "scratch.obj"
    object_path.parent.mkdir()
    source.write_text("void first(void) {}\n", encoding="utf-8")
    config_path.write_text("IMAGE=grim.dll\nFUNCTION=first\n", encoding="utf-8")
    object_path.write_bytes(b"coff")
    match_root = tmp_path / "tools" / "match"
    (match_root / "bin").mkdir(parents=True, exist_ok=True)
    compiler_bin = match_root / "compilers" / "msvc6.5" / "Bin"
    compiler_include = match_root / "compilers" / "msvc6.5" / "Include"
    compiler_bin.mkdir(parents=True)
    compiler_include.mkdir()
    (match_root / "cl.sh").write_bytes(b"wrapper")
    (match_root / "bin" / "wibo").write_bytes(b"wibo")
    (match_root / "bin" / "wibo").chmod(0o755)
    (compiler_bin / "CL.EXE").write_bytes(b"cl")
    (compiler_bin / "C2.DLL").write_bytes(b"c2")
    (compiler_include / "stddef.h").write_bytes(b"stddef")
    image_path = tmp_path / "game_bins" / "grim.dll"
    image_path.parent.mkdir()
    image_path.write_bytes(b"pe")
    function = _function("first", 0x10001000)
    status = _status(scratch, "first", function.address)
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, (function,)),
        image_path=image_path,
        records=(
            NativeObjectRecord(
                function=function,
                status=status,
                object_path=object_path,
                object_symbol="_first",
                coff=_coff(definitions=(("_first", 1),)),
                object_sha256="a" * 64,
            ),
        ),
        match_root=match_root,
    )

    first = object_manifest_payload(objects, repo_root=tmp_path)
    second = object_manifest_payload(objects, repo_root=tmp_path)

    assert first == second
    assert first["function_count"] == 1
    assert first["object_count"] == 1
    assert first["objects"][0]["object"] == "tools/match/scratches/first/build/scratch.obj"
    assert first["objects"][0]["functions"][0]["function"] == "first"
    assert first["translation_units"] == {
        "cluster_count": 0,
        "isolated_count": 1,
    }
    assert len(first["objects"][0]["source_sha256"]) == 64
    assert first["object_hash"]["normalization"] == ["zero COFF TimeDateStamp bytes 4..7"]
    assert first["provenance"]["build_policy"] == "forced-isolated-recompile"
    compiler_bundle = first["provenance"]["toolchain"]["compiler_bundles"][0]
    assert compiler_bundle["included_trees"] == ["Bin", "Include"]
    assert first["provenance"]["toolchain"]["wibo"]["mode"] == 0o755

    ignored_mfc = match_root / "compilers" / "msvc6.5" / "MFC"
    ignored_mfc.mkdir()
    (ignored_mfc / "unused.h").write_bytes(b"ignored")
    assert object_manifest_payload(objects, repo_root=tmp_path) == first

    (compiler_include / "stddef.h").write_bytes(b"changed")
    changed = object_manifest_payload(objects, repo_root=tmp_path)
    assert changed["provenance"]["toolchain"]["compiler_bundles"][0][
        "bundle_sha256"
    ] != compiler_bundle["bundle_sha256"]


def test_object_manifest_represents_cluster_members_on_one_physical_object(
    tmp_path: Path,
) -> None:
    scratch_root = tmp_path / "tools" / "match" / "scratches"
    first_scratch = scratch_root / "first"
    provider_scratch = scratch_root / "second"
    for scratch, function in (
        (first_scratch, "first"),
        (provider_scratch, "second"),
    ):
        scratch.mkdir(parents=True)
        (scratch / "scratch.cpp").write_text(
            f"void {function}(void) {{}}\n",
            encoding="utf-8",
        )
        (scratch / "scratch.conf").write_text(
            f"IMAGE=grim.dll\nFUNCTION={function}\n",
            encoding="utf-8",
        )
    object_path = provider_scratch / "build" / "cluster.obj"
    object_path.parent.mkdir()
    object_path.write_bytes(b"coff")
    translation_unit_config = (
        tmp_path / "tools" / "native" / "translation_units" / "grim.dll.json"
    )
    translation_unit_config.parent.mkdir(parents=True)
    translation_unit_config.write_text("{}\n", encoding="utf-8")
    image_path = tmp_path / "game_bins" / "grim.dll"
    image_path.parent.mkdir()
    image_path.write_bytes(b"pe")
    functions = (
        _function("first", 0x10001000),
        _function("second", 0x10001010),
    )
    statuses = (
        _status(first_scratch, "first", functions[0].address),
        _status(provider_scratch, "second", functions[1].address),
    )
    bindings = tuple(
        NativeFunctionBinding(
            function=function,
            status=status,
            object_symbol=symbol,
            config_sha256="a" * 64,
            source_sha256="b" * 64,
        )
        for function, status, symbol in zip(
            functions,
            statuses,
            ("_$E1", "_$E2"),
            strict=True,
        )
    )
    toolchain = NativeToolchainSnapshot(
        cl_wrapper=tmp_path / "tools" / "match" / "cl.sh",
        cl_wrapper_mode=0o755,
        cl_wrapper_sha256="c" * 64,
        compiler_bundles=(
            NativeCompilerBundleSnapshot(
                compiler="msvc6.5",
                root=tmp_path / "tools" / "match" / "compilers" / "msvc6.5",
                included_trees=("Bin", "Include"),
                sha256="d" * 64,
            ),
        ),
        wibo=tmp_path / "tools" / "match" / "bin" / "wibo",
        wibo_mode=0o755,
        wibo_sha256="e" * 64,
    )
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, functions),
        image_path=image_path,
        records=(
            NativeObjectRecord(
                function=functions[0],
                status=statuses[0],
                object_path=object_path,
                object_symbol="_$E1",
                coff=_coff(),
                config_sha256="f" * 64,
                object_sha256="1" * 64,
                source_sha256="2" * 64,
                compile_config=statuses[1].config,
                members=bindings,
                translation_unit="metadata-lifecycle",
                translation_unit_config=translation_unit_config,
                translation_unit_config_sha256="3" * 64,
            ),
        ),
        match_root=tmp_path / "tools" / "match",
        toolchain=toolchain,
    )

    payload = object_manifest_payload(objects, repo_root=tmp_path)

    assert payload["function_count"] == 2
    assert payload["object_count"] == 1
    assert payload["translation_units"] == {
        "cluster_count": 1,
        "isolated_count": 0,
    }
    assert payload["provenance"]["build_policy"] == (
        "forced-explicit-translation-unit-recompile"
    )
    assert [row["function"] for row in payload["objects"][0]["functions"]] == [
        "first",
        "second",
    ]
    assert payload["objects"][0]["scratch"].endswith("/second")
    assert payload["objects"][0]["translation_unit"]["name"] == (
        "metadata-lifecycle"
    )


def test_loaded_config_validation_rejects_post_selection_change(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    config_path = scratch / "scratch.conf"
    config_path.write_text(
        "IMAGE=grim.dll\nFUNCTION=first\nCFLAGS=/O2\n",
        encoding="utf-8",
    )
    selected = matchlib.load_scratch_config(scratch)
    config_path.write_text(
        "IMAGE=grim.dll\nFUNCTION=first\nCFLAGS=/Od\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="changed after canonical selection"):
        _validate_loaded_configs((selected,))


def test_translation_unit_config_binds_unique_member_symbols(tmp_path: Path) -> None:
    path = tmp_path / "translation-units.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "image": "crimsonland.exe",
                "clusters": [
                    {
                        "name": "metadata-lifecycle",
                        "scratch": "metadata_destroy",
                        "members": [
                            {"function": "metadata_init", "symbol": "_$E1"},
                            {"function": "metadata_destroy", "symbol": "_$E2"},
                        ],
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    config = load_native_translation_unit_config(
        path,
        image="crimsonland.exe",
    )

    assert config.image == "crimsonland.exe"
    assert config.clusters[0].scratch == "metadata_destroy"
    assert [
        (member.function, member.symbol)
        for member in config.clusters[0].members
    ] == [
        ("metadata_init", "_$E1"),
        ("metadata_destroy", "_$E2"),
    ]
    assert len(config.sha256) == 64


def test_default_grim_translation_unit_config_loads_slot_accessor_cluster() -> None:
    config = load_native_translation_unit_config(
        DEFAULT_TRANSLATION_UNIT_CONFIGS["grim.dll"],
        image="grim.dll",
    )

    assert [cluster.name for cluster in config.clusters] == [
        "grim-slot-state-accessors",
        "grim-draw-line-island",
        "grim-jaz-decode-island",
    ]
    assert [member.function for member in config.clusters[0].members] == [
        "grim_get_slot_float",
        "grim_get_slot_int",
        "grim_set_slot_float",
        "grim_set_slot_int",
    ]
    assert [member.function for member in config.clusters[1].members] == [
        "grim_draw_line",
        "grim_line_vector_dtor",
        "grim_draw_line_quad",
    ]
    assert [member.function for member in config.clusters[2].members] == [
        "grim_jaz_decode_scope_init",
        "grim_zlib_status_is_error",
        "grim_zlib_decompress_alloc",
        "grim_jaz_decompress_payload",
    ]


def test_linker_alias_config_normalizes_evidence_addresses(tmp_path: Path) -> None:
    path = tmp_path / "grim.dll.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-linker-aliases",
                "image": "grim.dll",
                "aliases": [
                    {
                        "alias": "??1Scope@@QAE@XZ",
                        "target": "_noop",
                        "target_address": "0x10001160",
                        "reference_function": "decode",
                        "reference_callsites": [
                            "0x10004cb5",
                            "0x10004e69",
                        ],
                        "evidence": "direct native calls",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    config = load_native_linker_alias_config(path, image="grim.dll")

    assert config.aliases == (
        NativeLinkerAliasSpec(
            alias="??1Scope@@QAE@XZ",
            target="_noop",
            target_address=0x10001160,
            reference_function="decode",
            reference_callsites=(0x10004CB5, 0x10004E69),
            evidence="direct native calls",
        ),
    )
    assert len(config.sha256) == 64


def test_default_grim_linker_alias_config_records_native_cleanup_calls() -> None:
    config = load_native_linker_alias_config(
        DEFAULT_LINKER_ALIAS_CONFIGS["grim.dll"],
        image="grim.dll",
    )

    assert config.aliases == (
        NativeLinkerAliasSpec(
            alias="??1GrimJazDecodeScope@@QAE@XZ",
            target="_grim_noop",
            target_address=0x10001160,
            reference_function="grim_decode_jaz_texture",
            reference_callsites=(0x10004CB5, 0x10004E69),
            evidence=(
                "Both native cleanup callsites load the decode-scope address into "
                "ECX and directly call the selected one-byte grim_noop function."
            ),
        ),
    )


def test_default_grim_provider_config_covers_current_non_game_closure() -> None:
    config = load_native_provider_config(
        DEFAULT_PROVIDER_CONFIGS["grim.dll"],
        image="grim.dll",
    )
    closure = json.loads(
        (matchlib.REPO_ROOT / "analysis/native/grim.dll/closure.json").read_text(
            encoding="utf-8",
        ),
    )

    coverage = native_provider_coverage(config, closure)

    assert coverage["covered_symbols"] == 54
    assert coverage["import_symbols"] == 21
    assert coverage["import_exports"] == 20
    assert coverage["generated_import_symbols"] == 5
    assert coverage["archive_symbols"] == 49
    assert coverage["link_dependency_symbols"] == 65
    assert coverage["closure_placeholder_symbols"] == 0
    assert coverage["link_dependency_placeholder_symbols"] == 1
    assert coverage["placeholder_symbols"] == 1
    assert coverage["runnable"] is False
    assert [
        provider.name
        for provider in config.providers
        if provider.resolution == "import-library"
    ] == [
        "user32.dll",
        "winmm.dll",
        "d3d8.dll",
        "recovered-platform-dinput8",
        "recovered-platform-user32",
        "recovered-platform-kernel32",
        "recovered-platform-gdi32",
        "recovered-platform-winmm",
        "recovered-platform-msvcrt",
        "recovered-platform-urlmon",
        "directx-8.1-d3dx8-kernel32",
        "directx-8.1-d3dx8-gdi32",
        "directx-8.1-d3dx8-advapi32",
    ]
    assert [
        provider.name
        for provider in config.providers
        if provider.resolution == "archive-library"
    ] == [
        "msvcrt.dll",
        "recovered-platform",
        "recovered-platform-config-dialog",
        "recovered-platform-dinput-data",
        "recovered-platform-dxguid",
        "directx-8.1-d3dx8-static",
        "grim-jaz-libjpeg-6a-vc6-static",
        "zlib-1.1.3-static",
        "msvc6-runtime-static",
        "msvc6-toolchain",
    ]
    assert len(config.archives) == 7
    archives = {archive.id: archive for archive in config.archives}
    assert archives["grim-recovered-platform-vc6"].size == 100246
    assert archives["grim-recovered-platform-vc6"].sha256 == (
        "192b49592a7671b265dd43f481d4965071abb2306cf0be099b39b3c03b799fe3"
    )
    assert (
        archives["grim-recovered-platform-vc6"].provenance.derived_artifact
        == "grim-recovered-platform-vc6-provider"
    )
    assert archives["directx-8.1-d3dx8"].size == 2150226
    assert archives["directx-8.1-d3dx8"].sha256 == (
        "39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28"
    )
    assert archives["directx-8.1-dinput8"].size == 19978
    assert archives["directx-8.1-dinput8"].sha256 == (
        "1aefd62d9df8a26aa312817bd98b2fc3340477b238c918fc9edc04f7498a5b34"
    )
    assert archives["directx-8.1-dxguid"].size == 104752
    assert archives["directx-8.1-dxguid"].sha256 == (
        "73a147b9ff6e4527e543e9a436cb244adcdae4ad89b89df51a0634f9a8c13682"
    )
    assert archives["vc6-sp6-msvcrt"].size == 235942
    assert archives["vc6-sp6-msvcrt"].sha256 == (
        "3efc3ddf045a459a2b6403f0b821be2cb7c316ffca67dddddb346cea7a9e4f63"
    )
    assert archives["ijg-libjpeg-6a-vc6-jaz"].sha256 == (
        "c0bf240e27e8684357c676030e3cb8913d04e6b1e14f8000f069b43b17de6869"
    )
    assert (
        archives["ijg-libjpeg-6a-vc6-jaz"].provenance.derived_artifact
        == "ijg-libjpeg-6a-vc6-jaz-provider"
    )
    assert archives["zlib-1.1.3-vc6"].sha256 == (
        "6b44ac2a8a67123b929cb9286c343730af5f6777609a54e12e402e5ac7e503b0"
    )
    assert archives["zlib-1.1.3-vc6"].provenance.derived_artifact == "zlib-1.1.3-vc6-provider"


def test_default_crimsonland_provider_config_covers_current_non_game_closure() -> None:
    config = load_native_provider_config(
        DEFAULT_PROVIDER_CONFIGS["crimsonland.exe"],
        image="crimsonland.exe",
    )
    closure = json.loads(
        (
            matchlib.REPO_ROOT
            / "analysis/native/crimsonland.exe/closure.json"
        ).read_text(encoding="utf-8"),
    )

    coverage = native_provider_coverage(config, closure)

    assert coverage["covered_symbols"] == 97
    assert coverage["import_symbols"] == 34
    assert coverage["import_exports"] == 34
    assert coverage["generated_import_symbols"] == 34
    assert coverage["archive_symbols"] == 63
    assert coverage["link_dependency_symbols"] == 99
    assert coverage["closure_placeholder_symbols"] == 0
    assert coverage["link_dependency_placeholder_symbols"] == 10
    assert coverage["placeholder_symbols"] == 10
    assert coverage["runnable"] is False
    assert config.entry == "WinMainCRTStartup"
    assert [
        (alias.alias, alias.target)
        for alias in config.entry_aliases
    ] == [
        ("_WinMain@16", "_crimsonland_main@16"),
    ]
    assert len(config.archives) == 3
    archives = {archive.id: archive for archive in config.archives}
    assert archives["crimsonland-recovered-platform-vc6"].size == 15334
    assert archives["crimsonland-recovered-platform-vc6"].sha256 == (
        "8b2cc07c8c4fbbcc7728b34674221593112dfbe5ec41a159acebd56869131fb3"
    )
    assert (
        archives["crimsonland-recovered-platform-vc6"].provenance.derived_artifact
        == "crimsonland-recovered-platform-vc6-provider"
    )
    assert archives["directx-8.1-d3dx8"].size == 2150226
    assert archives["directx-8.1-d3dx8"].sha256 == (
        "39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28"
    )
    assert archives["vc6-sp6-libcmt"].size == 934378
    assert archives["vc6-sp6-libcmt"].sha256 == (
        "a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a"
    )
    runtime = next(
        provider
        for provider in config.providers
        if provider.name == "msvc6-runtime-static"
    )
    aliases = {alias.alias: alias.target for alias in runtime.aliases}
    assert aliases["_FUN_004623b2"] == "_time"
    assert aliases["_crt_atof_l"] == "_atof"
    assert aliases["_strdup_malloc"] == "__strdup"
    d3dx_math = next(
        provider
        for provider in config.providers
        if provider.name == "directx-8.1-d3dx8-math"
    )
    assert [
        (alias.alias, alias.target)
        for alias in d3dx_math.aliases
    ] == [
        ("_vec2_normalize_dispatch@8", "_D3DXVec2Normalize@8"),
    ]


def test_default_grim_link_manifest_records_recovered_platform_frontier() -> None:
    manifest = json.loads(
        (
            matchlib.REPO_ROOT
            / "analysis/native/grim.dll/link/link.json"
        ).read_text(encoding="utf-8"),
    )

    assert manifest["schema"] == 3
    assert manifest["status"] == "linked"
    assert manifest["runnable"] is False
    assert manifest["summary"]["link_dependency_symbols"] == 65
    assert manifest["summary"]["archive_symbols"] == 49
    assert manifest["summary"]["import_exports"] == 20
    assert manifest["summary"]["closure_placeholder_symbols"] == 0
    assert manifest["summary"]["link_dependency_placeholder_symbols"] == 1
    assert manifest["summary"]["placeholder_symbols"] == 1
    assert manifest["summary"]["discarded_placeholder_symbols"] == 0
    assert manifest["summary"]["retained_closure_placeholder_symbols"] == 0
    assert manifest["summary"]["retained_link_dependency_placeholder_symbols"] == 1
    assert manifest["summary"]["retained_placeholder_symbols"] == 1
    assert manifest["summary"]["retained_link_dependency_import_symbols"] == 56
    assert manifest["summary"]["validated_output_import_symbols"] == 96
    assert manifest["summary"]["input_object_count"] == 166
    assert manifest["entry"] == {"symbol": "DllMain"}
    assert manifest["placeholder_object"]["discarded_symbols"] == []
    assert manifest["placeholder_object"]["retained_symbols"] == [
        "?grim_window_proc@@YGJPAUHWND__@@IIJ@Z",
    ]
    dependencies = {
        row["module"]: row
        for row in manifest["reference_imports"]["link_dependencies"]
    }
    assert dependencies["kernel32"]["discarded_symbols"] == [
        "FindResourceW",
    ]
    assert dependencies["dinput8"]["retained_symbols"] == [
        "DirectInput8Create",
    ]
    assert dependencies["gdi32"]["retained_symbols"] == [
        "DeleteObject",
        "GetStockObject",
    ]
    assert dependencies["advapi32"]["discarded_symbols"] == []


def test_default_crimsonland_link_manifest_records_structural_executable() -> None:
    manifest = json.loads(
        (
            matchlib.REPO_ROOT
            / "analysis/native/crimsonland.exe/link/link.json"
        ).read_text(encoding="utf-8"),
    )

    assert manifest["schema"] == 3
    assert manifest["status"] == "linked"
    assert manifest["runnable"] is True
    assert manifest["summary"]["covered_symbols"] == 97
    assert manifest["summary"]["archive_symbols"] == 63
    assert manifest["summary"]["import_exports"] == 34
    assert manifest["summary"]["link_dependency_symbols"] == 99
    assert manifest["summary"]["closure_placeholder_symbols"] == 0
    assert manifest["summary"]["link_dependency_placeholder_symbols"] == 10
    assert manifest["summary"]["placeholder_symbols"] == 10
    assert manifest["summary"]["discarded_placeholder_symbols"] == 10
    assert manifest["summary"]["retained_closure_placeholder_symbols"] == 0
    assert manifest["summary"]["retained_link_dependency_placeholder_symbols"] == 0
    assert manifest["summary"]["retained_placeholder_symbols"] == 0
    assert manifest["summary"]["retained_link_dependency_import_symbols"] == 87
    assert manifest["summary"]["validated_output_import_symbols"] == 121
    assert manifest["summary"]["input_object_count"] == 706
    assert manifest["entry"]["symbol"] == "WinMainCRTStartup"
    assert manifest["entry"]["aliases"]["symbols"] == [
        {
            "alias": "_WinMain@16",
            "target": "_crimsonland_main@16",
        },
    ]
    assert manifest["placeholder_object"]["symbol_count"] == 10
    assert manifest["placeholder_object"]["retained_symbols"] == []
    assert manifest["placeholder_object"]["discarded_symbols"] == [
        "__imp__EnumSystemLocalesA@8",
        "__imp__FatalAppExitA@8",
        "__imp__GetCurrentThread@0",
        "__imp__GetLocaleInfoA@16",
        "__imp__GetLocaleInfoW@16",
        "__imp__GetUserDefaultLCID@0",
        "__imp__IsValidCodePage@4",
        "__imp__IsValidLocale@8",
        "__imp__SetConsoleCtrlHandler@8",
        "__imp__TlsFree@4",
    ]
    assert manifest["output"]["pe"] == {
        "characteristics": 271,
        "dll": False,
        "entry_point_rva": 323902,
        "image_base": 0x00400000,
        "image_size": 868352,
        "machine": matchlib.IMAGE_FILE_MACHINE_I386,
        "optional_magic": 0x10B,
        "section_count": 4,
        "subsystem": 2,
        "timestamp": 0,
    }
    modules = {
        row["module"]: row["symbols"]
        for row in manifest["reference_imports"]["modules"]
    }
    assert modules["dsound"] == ["#11"]
    dependencies = {
        row["module"]: row
        for row in manifest["reference_imports"]["link_dependencies"]
    }
    assert dependencies["advapi32"]["declared_symbols"] == [
        "RegOpenKeyA",
        "RegQueryValueExA",
        "RegSetValueExA",
    ]
    assert dependencies["advapi32"]["retained_symbols"] == [
        "RegOpenKeyA",
        "RegQueryValueExA",
        "RegSetValueExA",
    ]
    assert dependencies["advapi32"]["discarded_symbols"] == []
    assert len(dependencies["kernel32"]["declared_symbols"]) == 76
    assert len(dependencies["kernel32"]["retained_symbols"]) == 76
    assert dependencies["kernel32"]["discarded_symbols"] == []
    assert dependencies["ole32"]["retained_symbols"] == [
        "CoCreateInstance",
        "CoInitialize",
        "CoUninitialize",
    ]
    assert dependencies["oleaut32"]["retained_symbols"] == ["#8", "#9"]
    assert dependencies["version"]["retained_symbols"] == [
        "GetFileVersionInfoA",
        "GetFileVersionInfoSizeA",
        "VerQueryValueA",
    ]
    d3dx_provider = next(
        provider
        for provider in manifest["providers"]
        if provider["name"] == "directx-8.1-d3dx8-math"
    )
    assert d3dx_provider["archive"] == "directx-8.1-d3dx8"
    assert d3dx_provider["aliases"]["symbols"] == [
        {
            "alias": "_vec2_normalize_dispatch@8",
            "target": "_D3DXVec2Normalize@8",
        },
    ]


def test_provider_archive_can_be_absent_but_present_bytes_are_hash_checked(
    tmp_path: Path,
) -> None:
    provenance = tmp_path / "analysis/library_provenance.json"
    provenance.parent.mkdir()
    provenance.write_text(
        json.dumps(
            {
                "schema": 1,
                "source_artifacts": [
                    {
                        "id": "vc6",
                        "members": [
                            {
                                "path": "vc98/lib/msvcrt.lib",
                                "size": 3,
                                "sha256": (
                                    "ba7816bf8f01cfea414140de5dae2223"
                                    "b00361a396177a9cb410ff61f20015ad"
                                ),
                            },
                        ],
                    },
                ],
            },
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "providers.json"
    config_path.write_text(
        json.dumps(
            {
                "schema": 3,
                "image": "grim.dll",
                "entry": "DllMain",
                "image_base": "0x10000000",
                "mode": "structural",
                "archives": [
                    {
                        "id": "vc6-msvcrt",
                        "path": "providers/build/msvcrt.lib",
                        "sha256": (
                            "ba7816bf8f01cfea414140de5dae2223"
                            "b00361a396177a9cb410ff61f20015ad"
                        ),
                        "provenance": {
                            "path": "analysis/library_provenance.json",
                            "source_artifact": "vc6",
                            "member": "vc98/lib/msvcrt.lib",
                        },
                    },
                ],
                "providers": [
                    {
                        "name": "vc6-toolchain",
                        "kind": "toolchain",
                        "resolution": "archive-library",
                        "archive": "vc6-msvcrt",
                        "evidence": [
                            {
                                "path": "analysis/library_provenance.json",
                                "note": "test evidence",
                            },
                        ],
                        "symbols": [
                            {
                                "name": "__fltused",
                                "binding": "data",
                            },
                        ],
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    config = load_native_provider_config(
        config_path,
        image="grim.dll",
        repo_root=tmp_path,
    )

    assert not config.archives[0].path.exists()
    config.archives[0].path.parent.mkdir(parents=True)
    config.archives[0].path.write_bytes(b"abd")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_native_provider_config(
            config_path,
            image="grim.dll",
            repo_root=tmp_path,
        )


def test_native_provider_import_definitions_preserve_reference_export_names() -> None:
    config = load_native_provider_config(
        DEFAULT_PROVIDER_CONFIGS["grim.dll"],
        image="grim.dll",
    )
    providers = {provider.name: provider for provider in config.providers}

    assert render_native_import_definition(providers["user32.dll"]) == (
        "LIBRARY USER32.dll\n"
        "EXPORTS\n"
        "    LoadIconA\n"
        "    MessageBoxA\n"
    )
    assert [
        (alias.alias, alias.target)
        for alias in providers["user32.dll"].aliases
    ] == [
        ("__imp__LoadIconA@8", "__imp__LoadIconA"),
        ("__imp__MessageBoxA@16", "__imp__MessageBoxA"),
    ]
    assert [
        (alias.alias, alias.target)
        for alias in providers["msvcrt.dll"].aliases
    ] == [("_strdup", "__strdup")]
    assert providers["directx-8.1-d3dx8-kernel32"].scope == "link-dependency"
    assert "    FindResourceW\n" in render_native_import_definition(
        providers["directx-8.1-d3dx8-kernel32"],
    )

    crimson_config = load_native_provider_config(
        DEFAULT_PROVIDER_CONFIGS["crimsonland.exe"],
        image="crimsonland.exe",
    )
    crimson_providers = {
        provider.name: provider
        for provider in crimson_config.providers
    }
    assert render_native_import_definition(crimson_providers["dsound.dll"]) == (
        "LIBRARY DSOUND.dll\n"
        "EXPORTS\n"
        "    DirectSoundCreate8 @11 NONAME\n"
    )
    reference_image = (
        matchlib.REPO_ROOT
        / "game_bins/crimsonland/1.9.93-gog/crimsonland.exe"
    )
    assert native_pe_imports(reference_image.read_bytes())["dsound"] == ("#11",)
    assert native_pe_imports(reference_image.read_bytes())["oleaut32"] == (
        "#8",
        "#9",
    )


def test_native_provider_placeholder_object_is_deterministic() -> None:
    config = load_native_provider_config(
        DEFAULT_PROVIDER_CONFIGS["grim.dll"],
        image="grim.dll",
    )
    providers = tuple(
        provider
        for provider in config.providers
        if provider.resolution == "placeholder-object"
    )

    data = native_provider_placeholder_object_bytes(providers)
    assert data == native_provider_placeholder_object_bytes(providers)
    coff = matchlib.parse_coff_object(data)
    symbols = {
        symbol.name: symbol
        for symbol in coff.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
    }

    assert set(symbols) == {
        "?grim_window_proc@@YGJPAUHWND__@@IIJ@Z",
    }
    assert len(coff.sections) == 1
    assert [section.name for section in coff.sections] == [".text"]
    assert {
        (section.comdat_key, section.comdat_selection)
        for section in coff.sections
    } == {
        (name, 2)
        for name in symbols
    }
    assert "_D3DXCreateTexture@32" not in symbols
    assert "_d3dx_copy_texture_filtered@24" not in symbols
    assert "_jpeg_CreateDecompress" not in symbols
    assert "_grim_jpeg_memory_src" not in symbols
    assert "__fltused" not in symbols


def test_crimsonland_placeholder_object_records_transitive_archive_shims() -> None:
    config = load_native_provider_config(
        DEFAULT_PROVIDER_CONFIGS["crimsonland.exe"],
        image="crimsonland.exe",
    )
    providers = tuple(
        provider
        for provider in config.providers
        if provider.resolution == "placeholder-object"
    )

    coff = matchlib.parse_coff_object(
        native_provider_placeholder_object_bytes(providers),
    )
    symbols = {
        symbol.name: symbol
        for symbol in coff.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
    }

    assert len(symbols) == 10
    assert len(coff.sections) == 10
    assert [section.name for section in coff.sections] == [".data"] * 10
    assert {
        (section.comdat_key, section.comdat_selection)
        for section in coff.sections
    } == {
        (name, 2)
        for name in symbols
    }
    assert "_main" not in symbols
    tls_free = symbols["__imp__TlsFree@4"]
    assert coff.sections[tls_free.section_number - 1].name == ".data"
    assert "_vec2_normalize_dispatch@8" not in symbols
    assert "_dx_get_version" not in symbols
    assert "_RtlUnwind@16" not in symbols


def test_coff_archive_timestamp_normalization_is_idempotent() -> None:
    member = bytearray(20)
    struct.pack_into("<H", member, 0, matchlib.IMAGE_FILE_MACHINE_I386)
    struct.pack_into("<I", member, 4, 0x12345678)
    header = (
        b"provider.obj/".ljust(16)
        + b"1234567890".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(member)).encode().ljust(10)
        + b"`\n"
    )
    archive = b"!<arch>\n" + header + member

    normalized = normalize_coff_archive_timestamps(archive)

    assert normalized == normalize_coff_archive_timestamps(normalized)
    assert normalized[24:36] == b"0           "
    assert normalized[8 + 60 + 4 : 8 + 60 + 8] == b"\x00" * 4


def test_pe_timestamp_normalization_covers_export_directory() -> None:
    image = bytearray(0x300)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        matchlib.IMAGE_FILE_MACHINE_I386,
        1,
        0x12345678,
        0,
        0,
        0xE0,
        0x2000,
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 16, 0x1010)
    struct.pack_into("<I", image, optional + 28, 0x10000000)
    struct.pack_into("<I", image, optional + 56, 0x2000)
    struct.pack_into("<H", image, optional + 68, 2)
    struct.pack_into("<II", image, optional + 96, 0x1000, 40)
    section = optional + 0xE0
    image[section : section + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x100, 0x200)
    struct.pack_into("<I", image, 0x204, 0x87654321)

    normalized = normalize_pe_timestamp(bytes(image))
    summary = native_pe_summary(normalized)

    assert struct.unpack_from("<I", normalized, 0x88)[0] == 0
    assert struct.unpack_from("<I", normalized, 0x204)[0] == 0
    assert summary["machine"] == matchlib.IMAGE_FILE_MACHINE_I386
    assert summary["dll"] is True
    assert summary["image_base"] == 0x10000000
    assert summary["timestamp"] == 0


def test_native_link_image_options_distinguish_dll_and_gui_exe(
    tmp_path: Path,
) -> None:
    export_path = tmp_path / "exports.def"
    import_library_path = tmp_path / "grim.lib"
    expected_export_path = "Z:" + str(export_path.resolve()).replace("/", "\\")
    expected_import_library_path = "Z:" + str(import_library_path.resolve()).replace(
        "/",
        "\\",
    )

    assert _native_link_image_options(
        "grim.dll",
        export_path=export_path,
        import_library_path=import_library_path,
    ) == [
        "/dll",
        f"/implib:{expected_import_library_path}",
        f"/def:{expected_export_path}",
    ]
    assert _native_link_image_options(
        "crimsonland.exe",
        export_path=export_path,
        import_library_path=import_library_path,
    ) == ["/subsystem:windows"]
    with pytest.raises(ValueError, match="does not support image kind"):
        _native_link_image_options(
            "crimsonland.bin",
            export_path=export_path,
            import_library_path=import_library_path,
        )


def test_wibo_resolution_skips_non_executable_repository_copy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    match_root = tmp_path / "match"
    repository_wibo = match_root / "bin" / "wibo"
    repository_wibo.parent.mkdir(parents=True)
    repository_wibo.write_bytes(b"not executable")
    repository_wibo.chmod(0o644)
    path_wibo = tmp_path / "path-bin" / "wibo"
    path_wibo.parent.mkdir()
    path_wibo.write_bytes(b"executable")
    path_wibo.chmod(0o755)
    monkeypatch.delenv("WIBO", raising=False)
    monkeypatch.setenv("PATH", str(path_wibo.parent))

    assert _resolve_wibo_path(match_root) == path_wibo.resolve()


def test_normalized_coff_hash_ignores_only_header_timestamp() -> None:
    first = bytearray(20)
    struct.pack_into("<H", first, 0, matchlib.IMAGE_FILE_MACHINE_I386)
    struct.pack_into("<I", first, 4, 1)
    second = bytearray(first)
    struct.pack_into("<I", second, 4, 2)

    assert _normalized_coff_sha256(bytes(first)) == _normalized_coff_sha256(bytes(second))
    second[12] = 1
    assert _normalized_coff_sha256(bytes(first)) != _normalized_coff_sha256(bytes(second))


def test_native_data_object_emits_overlapping_exact_symbol_aliases(
    tmp_path: Path,
) -> None:
    definitions = {
        "entries": [
            {
                "address": 0x1001,
                "alignment": 1,
                "initializer_hex": "0102030405060708",
                "name": "owner",
                "size": 8,
            },
            {
                "address": 0x1004,
                "alignment": 4,
                "initializer_hex": "04050607",
                "name": "interior",
                "size": 4,
            },
            {
                "address": 0x1010,
                "alignment": 4,
                "initializer_fill": "ab",
                "name": "fill",
                "size": 4,
            },
        ],
    }
    closure = {
        "unresolved": [
            {
                "catalog": [{"address": 0x1001, "name": "owner"}],
                "category": "game_data",
                "lookup_name": "owner",
                "name": "?owner@@3HA",
                "referenced_by": [{"function": "first"}],
            },
            {
                "catalog": [{"address": 0x1001, "name": "owner"}],
                "category": "game_data",
                "lookup_name": "owner",
                "name": "_owner",
                "referenced_by": [{"function": "second"}],
            },
            {
                "catalog": [{"address": 0x1004, "name": "interior"}],
                "category": "game_data",
                "lookup_name": "interior",
                "name": "_interior",
                "referenced_by": [{"function": "third"}],
            },
            {
                "catalog": [{"address": 0x1010, "name": "fill"}],
                "category": "game_data",
                "lookup_name": "fill",
                "name": "_fill",
                "referenced_by": [{"function": "fourth"}],
            },
            {
                "catalog": [{"address": 0x1006, "name": "implicit"}],
                "category": "game_data",
                "lookup_name": "implicit",
                "name": "_implicit",
                "referenced_by": [{"function": "fifth"}],
            },
        ],
    }

    data, bindings, regions = native_data_object_bytes(definitions, closure)
    repeated, _, _ = native_data_object_bytes(definitions, closure)
    coff = matchlib.parse_coff_object(data)
    symbols = {symbol.name: symbol for symbol in coff.symbols}

    assert data == repeated
    assert len(regions) == 2
    assert regions[0].address == 0x1000
    assert regions[0].alignment == 4
    assert regions[0].data == bytes.fromhex("000102030405060708")
    assert regions[1].data == bytes.fromhex("abababab")
    assert {binding.name for binding in bindings} == {
        "owner",
        "interior",
        "fill",
        "implicit",
    }
    assert symbols["?owner@@3HA"].section_number == 1
    assert symbols["?owner@@3HA"].value == 1
    assert symbols["_owner"].value == 1
    assert symbols["_interior"].value == 4
    assert symbols["_fill"].section_number == 2
    assert symbols["_fill"].value == 0
    assert symbols["_implicit"].section_number == 1
    assert symbols["_implicit"].value == 6
    implicit = next(binding for binding in bindings if binding.name == "implicit")
    assert implicit.kind == "interior-alias"
    assert implicit.size is None
    assert implicit.alignment is None
    assert implicit.initializer is None
    assert implicit.storage_address == 0x1004
    assert implicit.storage_name == "interior"

    function = _function("first", 0x2000)
    data_path = tmp_path / "definitions.obj"
    definitions_path = tmp_path / "definitions.json"
    data_path.write_bytes(data)
    definitions_path.write_text("{}\n", encoding="utf-8")
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x1000, (function,)),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=function,
                status=_status(tmp_path / "first", "first", function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_first",
                coff=_coff(
                    definitions=(("_first", 1),),
                    undefined=(
                        "?owner@@3HA",
                        "_owner",
                        "_interior",
                        "_fill",
                        "_implicit",
                    ),
                ),
            ),
        ),
        data_records=(
            NativeDataObjectRecord(
                object_path=data_path,
                coff=coff,
                definitions_path=definitions_path,
                definitions_sha256="a" * 64,
                object_sha256="b" * 64,
                bindings=bindings,
                regions=regions,
            ),
        ),
    )
    catalog = NativeSymbolCatalog(
        port_functions={},
        excluded_functions={},
        data={
            "interior": ({"address": 0x1004, "name": "interior"},),
            "fill": ({"address": 0x1010, "name": "fill"},),
            "implicit": ({"address": 0x1006, "name": "implicit"},),
            "owner": ({"address": 0x1001, "name": "owner"},),
        },
        imports={},
        exports=(),
    )

    result = symbol_closure_payload(objects, catalog=catalog, repo_root=tmp_path)

    assert result["summary"]["object_count"] == 2
    assert result["summary"]["function_count"] == 1
    assert result["summary"]["game_owned_closure"] is True
    assert result["summary"]["unresolved_symbols"] == 0
    assert {row["name"] for row in result["resolved"]} == {
        "?owner@@3HA",
        "_fill",
        "_implicit",
        "_interior",
        "_owner",
    }
    assert render_object_list(objects, repo_root=tmp_path) == (
        "first.obj\n"
        "definitions.obj\n"
    )


def test_native_data_object_emits_symbolic_pointer_relocation() -> None:
    definitions = {
        "entries": [
            {
                "address": 0x1000,
                "alignment": 4,
                "initializer_target": {
                    "address": 0x2000,
                    "name": "target_string",
                },
                "name": "pointer",
                "size": 4,
            },
            {
                "address": 0x2000,
                "alignment": 1,
                "initializer_hex": "686900",
                "name": "target_string",
                "size": 3,
            },
        ],
    }
    closure = {
        "unresolved": [
            {
                "catalog": [{"address": 0x1000, "name": "pointer"}],
                "category": "game_data",
                "lookup_name": "pointer",
                "name": "_pointer",
                "referenced_by": [{"function": "first"}],
            },
        ],
    }

    data, bindings, regions = native_data_object_bytes(definitions, closure)
    repeated, _, _ = native_data_object_bytes(definitions, closure)
    coff = matchlib.parse_coff_object(data)
    pointer = next(binding for binding in bindings if binding.name == "pointer")
    target = next(
        binding for binding in bindings if binding.name == "target_string"
    )
    section = coff.sections[pointer.section_number - 1]
    relocation = section.relocations[0]
    relocation_symbol = next(
        symbol
        for symbol in coff.symbols
        if symbol.raw_index == relocation.symbol_index
    )

    assert data == repeated
    assert len(bindings) == 2
    assert len(regions) == 2
    assert pointer.initializer_target == (0x2000, "target_string")
    assert target.symbols == ()
    assert section.data == b"\x00\x00\x00\x00"
    assert relocation.virtual_address == 0
    assert relocation.relocation_type == 0x0006
    assert relocation_symbol.name == "$data$00002000"
    assert relocation_symbol.storage_class == matchlib.IMAGE_SYM_CLASS_STATIC
    assert relocation_symbol.section_number == target.section_number
    assert relocation_symbol.value == target.section_offset


def test_native_data_object_emits_external_symbol_relocations(tmp_path: Path) -> None:
    definitions = {
        "entries": [
            {
                "address": 0x1000,
                "alignment": 4,
                "initializer_symbols": [
                    {
                        "offset": 0,
                        "address": 0x2000,
                        "symbol": "_first",
                    },
                    {
                        "offset": 4,
                        "address": 0x3000,
                        "symbol": "?second@@YAXXZ",
                    },
                ],
                "name": "vtable",
                "size": 8,
            },
        ],
    }
    closure = {
        "unresolved": [
            {
                "catalog": [{"address": 0x1000, "name": "vtable"}],
                "category": "game_data",
                "lookup_name": "vtable",
                "name": "_vtable",
                "referenced_by": [{"function": "factory"}],
            },
        ],
    }

    data, bindings, regions = native_data_object_bytes(definitions, closure)
    coff = matchlib.parse_coff_object(data)
    symbols = {symbol.name: symbol for symbol in coff.symbols}
    binding = next(binding for binding in bindings if binding.name == "vtable")
    section = coff.sections[binding.section_number - 1]

    assert binding.initializer_symbols == (
        (0, 0x2000, "_first"),
        (4, 0x3000, "?second@@YAXXZ"),
    )
    assert section.data == b"\x00" * 8
    assert [relocation.virtual_address for relocation in section.relocations] == [0, 4]
    assert [
        next(
            symbol.name
            for symbol in coff.symbols
            if symbol.raw_index == relocation.symbol_index
        )
        for relocation in section.relocations
    ] == ["_first", "?second@@YAXXZ"]
    assert symbols["_first"].section_number == 0
    assert symbols["?second@@YAXXZ"].section_number == 0
    assert all(
        relocation.relocation_type == IMAGE_REL_I386_DIR32
        for relocation in section.relocations
    )
    assert regions[0].relocations[0].target_symbol == "_first"
    assert regions[0].relocations[1].target_symbol == "?second@@YAXXZ"

    function = _function("first", 0x2000)
    data_path = tmp_path / "definitions.obj"
    definitions_path = tmp_path / "definitions.json"
    data_path.write_bytes(data)
    definitions_path.write_text("{}\n", encoding="utf-8")
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x1000, (function,)),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=function,
                status=_status(tmp_path / "first", "first", function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_first",
                coff=_coff(definitions=(("_first", 1),)),
            ),
        ),
        data_records=(
            NativeDataObjectRecord(
                object_path=data_path,
                coff=coff,
                definitions_path=definitions_path,
                definitions_sha256="a" * 64,
                object_sha256="b" * 64,
                bindings=bindings,
                regions=regions,
            ),
        ),
    )
    catalog = NativeSymbolCatalog(
        port_functions={},
        excluded_functions={},
        data={},
        imports={},
        exports=(),
    )

    closure_result = symbol_closure_payload(
        objects,
        catalog=catalog,
        repo_root=tmp_path,
    )

    assert [row["name"] for row in closure_result["resolved"]] == ["_first"]
    assert [row["name"] for row in closure_result["unresolved"]] == [
        "?second@@YAXXZ",
    ]
    assert closure_result["unresolved"][0]["referenced_by"] == [
        {
            "function": None,
            "object": "definitions.obj",
            "weak": False,
        },
    ]


def test_symbol_closure_keeps_exact_link_identity_and_classifies_debt(tmp_path: Path) -> None:
    first_function = _function("first", 0x10001000)
    second_function = _function("second", 0x10001010)
    first_object = tmp_path / "first.obj"
    second_object = tmp_path / "second.obj"
    first = NativeObjectRecord(
        function=first_function,
        status=_status(tmp_path / "first", "first", first_function.address),
        object_path=first_object,
        object_symbol="_first",
        coff=_coff(
            definitions=(("_first", 1), ("_duplicate", 1)),
            undefined=("_second", "_game_data", "__imp__MessageBoxA@16"),
            comdat_definitions=("??_C@literal",),
        ),
    )
    second = NativeObjectRecord(
        function=second_function,
        status=_status(tmp_path / "second", "second", second_function.address),
        object_path=second_object,
        object_symbol="_second",
        coff=_coff(
            definitions=(("_second", 1), ("_duplicate", 1)),
            comdat_definitions=("??_C@literal",),
        ),
    )
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest(
            "grim.dll",
            0x10000000,
            (first_function, second_function),
        ),
        image_path=tmp_path / "grim.dll",
        records=(first, second),
    )
    catalog = NativeSymbolCatalog(
        port_functions={},
        excluded_functions={},
        data={"game_data": ({"address": 0x10050000, "name": "game_data"},)},
        imports={
            "MessageBoxA": (
                {"address": 0x1004C120, "module": "USER32", "name": "MessageBoxA"},
            ),
        },
        exports=(),
    )

    closure = symbol_closure_payload(objects, catalog=catalog, repo_root=tmp_path)

    assert [row["name"] for row in closure["resolved"]] == ["_second"]
    assert [row["name"] for row in closure["duplicate_definitions"]] == ["_duplicate"]
    assert [row["name"] for row in closure["coalescible_definitions"]] == ["??_C@literal"]
    assert closure["summary"]["unresolved_by_category"] == {
        "game_data": 1,
        "import": 1,
    }
    assert closure["summary"]["game_function_debt"] == {}
    assert closure["summary"]["hard_duplicate_by_section"] == {".text": 1}
    assert closure["summary"]["function_closure"] is False
    assert closure["summary"]["game_owned_closure"] is False
    isolated_reference = closure["resolved"][0]["referenced_by"][0]
    assert "functions" not in isolated_reference
    assert "translation_unit" not in isolated_reference


def test_symbol_closure_splits_game_function_linkage_debt(tmp_path: Path) -> None:
    function = _function("first", 0x10001000)
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, (function,)),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=function,
                status=_status(tmp_path / "first", "first", function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="?first@@YAXXZ",
                coff=_coff(
                    definitions=(("?first@@YAXXZ", 1),),
                    undefined=("_first", "_missing"),
                ),
            ),
        ),
    )
    catalog = NativeSymbolCatalog(
        port_functions={
            "first": ({"address": function.address, "function": "first"},),
            "missing": ({"address": 0x10001010, "function": "missing"},),
        },
        excluded_functions={},
        data={},
        imports={},
        exports=(),
    )

    closure = symbol_closure_payload(objects, catalog=catalog, repo_root=tmp_path)

    assert closure["summary"]["game_function_debt"] == {
        "emitted_name_mismatch": 1,
        "missing_definition": 1,
    }
    assert closure["summary"]["function_closure"] is False


def test_symbol_closure_counts_cluster_object_once_and_closes_local_members(
    tmp_path: Path,
) -> None:
    functions = tuple(
        _function(name, 0x10001000 + index * 0x10)
        for index, name in enumerate(
            (
                "metadata_global_construct",
                "metadata_init",
                "metadata_register",
                "metadata_destroy",
            ),
        )
    )
    coff = _coff(
        definitions=(("?metadata_table@@3PAUmetadata@@A", 1),),
        undefined=("_atexit",),
    )
    local_symbols = tuple(
        matchlib.CoffSymbol(
            raw_index=len(coff.symbols) + index,
            name=symbol,
            value=index,
            section_number=1,
            symbol_type=0x20,
            storage_class=matchlib.IMAGE_SYM_CLASS_STATIC,
        )
        for index, symbol in enumerate(("_$E4", "_$E1", "_$E3", "_$E2"))
    )
    coff = matchlib.CoffObject(
        sections=coff.sections,
        symbols=(*coff.symbols, *local_symbols),
    )
    statuses = tuple(
        _status(tmp_path / function.name, function.name, function.address)
        for function in functions
    )
    bindings = tuple(
        NativeFunctionBinding(
            function=function,
            status=status,
            object_symbol=symbol,
            config_sha256="a" * 64,
            source_sha256="b" * 64,
        )
        for function, status, symbol in zip(
            functions,
            statuses,
            ("_$E4", "_$E1", "_$E3", "_$E2"),
            strict=True,
        )
    )
    cluster_object = tmp_path / "metadata-lifecycle.obj"
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, functions),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=functions[0],
                status=statuses[0],
                object_path=cluster_object,
                object_symbol="_$E4",
                coff=coff,
                members=bindings,
                translation_unit="metadata-lifecycle",
            ),
        ),
    )
    catalog = NativeSymbolCatalog(
        port_functions={
            function.name: (
                {"address": function.address, "function": function.name},
            )
            for function in functions
        },
        excluded_functions={},
        data={},
        imports={
            "atexit": (
                {"address": 0x10004000, "module": "MSVCRT", "name": "atexit"},
            ),
        },
        exports=(),
    )

    closure = symbol_closure_payload(objects, catalog=catalog, repo_root=tmp_path)

    assert closure["summary"]["object_count"] == 1
    assert closure["summary"]["function_count"] == 4
    assert closure["summary"]["game_function_debt"] == {}
    assert closure["summary"]["function_closure"] is True
    assert [row["name"] for row in closure["unresolved"]] == ["_atexit"]
    clustered_reference = closure["unresolved"][0]["referenced_by"][0]
    assert clustered_reference["function"] is None
    assert clustered_reference["functions"] == [
        function.name
        for function in functions
    ]
    assert clustered_reference["translation_unit"] == "metadata-lifecycle"
    assert render_object_list(objects, repo_root=tmp_path) == (
        "metadata-lifecycle.obj\n"
    )


def test_symbol_closure_rejects_mixed_or_non_any_comdat_duplicates(tmp_path: Path) -> None:
    first_function = _function("first", 0x10001000)
    second_function = _function("second", 0x10001010)
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest(
            "grim.dll",
            0x10000000,
            (first_function, second_function),
        ),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=first_function,
                status=_status(tmp_path / "first", "first", first_function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_first",
                coff=_coff(definitions=(("_mixed", 1),)),
            ),
            NativeObjectRecord(
                function=second_function,
                status=_status(tmp_path / "second", "second", second_function.address),
                object_path=tmp_path / "second.obj",
                object_symbol="_second",
                coff=_coff(comdat_definitions=("_mixed",), comdat_selection=3),
            ),
        ),
    )
    catalog = NativeSymbolCatalog({}, {}, {}, {}, ())

    closure = symbol_closure_payload(objects, catalog=catalog, repo_root=tmp_path)

    assert [row["name"] for row in closure["duplicate_definitions"]] == ["_mixed"]
    assert closure["summary"]["function_closure"] is False


def test_symbol_closure_rejects_secondary_symbol_in_distinct_any_comdats(
    tmp_path: Path,
) -> None:
    first_function = _function("first", 0x10001000)
    second_function = _function("second", 0x10001010)
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest(
            "grim.dll",
            0x10000000,
            (first_function, second_function),
        ),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=first_function,
                status=_status(tmp_path / "first", "first", first_function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_first",
                coff=_coff(comdat_definitions=("_key_a", "_shared")),
            ),
            NativeObjectRecord(
                function=second_function,
                status=_status(tmp_path / "second", "second", second_function.address),
                object_path=tmp_path / "second.obj",
                object_symbol="_second",
                coff=_coff(comdat_definitions=("_key_b", "_shared")),
            ),
        ),
    )

    closure = symbol_closure_payload(
        objects,
        catalog=NativeSymbolCatalog({}, {}, {}, {}, ()),
        repo_root=tmp_path,
    )

    assert [row["name"] for row in closure["duplicate_definitions"]] == ["_shared"]
    assert closure["summary"]["function_closure"] is False


def test_native_linker_alias_object_emits_weak_external_fallback() -> None:
    alias = NativeLinkerAliasSpec(
        alias="??1Scope@@QAE@XZ",
        target="_noop",
        target_address=0x10001160,
        reference_function="decode",
        reference_callsites=(0x10001234,),
        evidence="direct native call",
    )

    data = native_linker_alias_object_bytes((alias,))
    repeated = native_linker_alias_object_bytes((alias,))
    coff = matchlib.parse_coff_object(data)
    symbols = {symbol.name: symbol for symbol in coff.symbols}
    weak = symbols[alias.alias]
    fallback = next(
        symbol
        for symbol in coff.symbols
        if symbol.raw_index == weak.weak_default_symbol_index
    )

    assert data == repeated
    assert coff.sections == ()
    assert symbols[alias.target].storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
    assert symbols[alias.target].section_number == 0
    assert weak.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL
    assert weak.weak_search == 3
    assert fallback.name == alias.target


def test_symbol_closure_applies_linker_alias_to_strong_reference(
    tmp_path: Path,
) -> None:
    function = _function("first", 0x10001000)
    alias = NativeLinkerAliasSpec(
        alias="_weak",
        target="_foo",
        target_address=function.address,
        reference_function=function.name,
        reference_callsites=(function.address,),
        evidence="direct native call",
    )
    alias_data = native_linker_alias_object_bytes((alias,))
    alias_object = tmp_path / "aliases.obj"
    alias_object.write_bytes(alias_data)
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, (function,)),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=function,
                status=_status(tmp_path / "first", "first", function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_foo",
                coff=_coff(
                    definitions=(("_foo", 1),),
                    undefined=("_weak",),
                ),
            ),
        ),
        linker_alias_records=(
            NativeLinkerAliasObjectRecord(
                object_path=alias_object,
                coff=matchlib.parse_coff_object(alias_data),
                config_path=tmp_path / "aliases.json",
                config_sha256="a" * 64,
                object_sha256="b" * 64,
                aliases=(alias,),
            ),
        ),
    )

    closure = symbol_closure_payload(
        objects,
        catalog=NativeSymbolCatalog({}, {}, {}, {}, ()),
        repo_root=tmp_path,
    )

    assert closure["unresolved"] == []
    assert closure["linker_aliases"] == [
        {
            "alias": "_weak",
            "objects": ["aliases.obj"],
            "target": "_foo",
        },
    ]
    assert closure["summary"]["object_count"] == 2
    strong_reference = next(
        reference
        for reference in closure["resolved"][0]["referenced_by"]
        if reference["object"] == "first.obj"
    )
    assert strong_reference["linker_alias"] == "_weak"
    assert render_object_list(objects, repo_root=tmp_path) == (
        "first.obj\n"
        "aliases.obj\n"
    )


def test_symbol_closure_classifies_sscanf_from_static_crt_directive(
    tmp_path: Path,
) -> None:
    function = _function("first", 0x10001000)
    base_coff = _coff(
        definitions=(("_first", 1),),
        undefined=("_sscanf",),
    )
    coff = matchlib.CoffObject(
        sections=(
            *base_coff.sections,
            matchlib.CoffSection(
                ".drectve",
                b"-defaultlib:LIBC -defaultlib:OLDNAMES ",
                0,
                (),
                index=3,
                logical_size=39,
            ),
        ),
        symbols=base_coff.symbols,
    )

    def closure_for(candidate: matchlib.CoffObject) -> dict[str, Any]:
        objects = NativeObjectSet(
            image="crimsonland.exe",
            scope="port",
            manifest=matchlib.FunctionManifest(
                "crimsonland.exe",
                0x400000,
                (function,),
            ),
            image_path=tmp_path / "crimsonland.exe",
            records=(
                NativeObjectRecord(
                    function=function,
                    status=_status(tmp_path / "first", "first", function.address),
                    object_path=tmp_path / "first.obj",
                    object_symbol="_first",
                    coff=candidate,
                ),
            ),
        )
        return symbol_closure_payload(
            objects,
            catalog=NativeSymbolCatalog({}, {}, {}, {}, ()),
            repo_root=tmp_path,
        )

    closure = closure_for(coff)
    row = closure["unresolved"][0]

    assert row["name"] == "_sscanf"
    assert row["category"] == "toolchain"
    assert row["classification_evidence"] == {
        "default_libraries": ["LIBC"],
        "kind": "msvc-crt-default-library",
    }
    assert closure["summary"]["game_owned_closure"] is True

    without_crt_directive = closure_for(base_coff)
    assert without_crt_directive["unresolved"][0]["category"] == "external"
    assert without_crt_directive["summary"]["game_owned_closure"] is False


def test_symbol_closure_resolves_weak_alias_fallback(tmp_path: Path) -> None:
    function = _function("first", 0x10001000)
    coff = _coff(definitions=(("_foo", 1),))
    coff = matchlib.CoffObject(
        sections=coff.sections,
        symbols=(
            *coff.symbols,
            matchlib.CoffSymbol(
                raw_index=1,
                name="_weak",
                value=0,
                section_number=0,
                symbol_type=0,
                storage_class=IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                aux_records=(b"\x00" * 18,),
                weak_default_symbol_index=0,
                weak_search=3,
            ),
        ),
    )
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, (function,)),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=function,
                status=_status(tmp_path / "first", "first", function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_foo",
                coff=coff,
            ),
        ),
    )

    closure = symbol_closure_payload(
        objects,
        catalog=NativeSymbolCatalog({}, {}, {}, {}, ()),
        repo_root=tmp_path,
    )

    assert closure["unresolved"] == []
    assert closure["resolved"][0]["name"] == "_foo"
    assert closure["resolved"][0]["referenced_by"][0]["weak_alias"] == "_weak"


def test_symbol_closure_prefers_strong_definition_over_weak_alias_fallback(
    tmp_path: Path,
) -> None:
    first_function = _function("first", 0x10001000)
    second_function = _function("second", 0x10001010)
    first_coff = _coff(definitions=(("_foo", 1),))
    first_coff = matchlib.CoffObject(
        sections=first_coff.sections,
        symbols=(
            *first_coff.symbols,
            matchlib.CoffSymbol(
                raw_index=1,
                name="_weak",
                value=0,
                section_number=0,
                symbol_type=0,
                storage_class=IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                aux_records=(b"\x00" * 18,),
                weak_default_symbol_index=0,
                weak_search=3,
            ),
        ),
    )
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest(
            "grim.dll",
            0x10000000,
            (first_function, second_function),
        ),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=first_function,
                status=_status(tmp_path / "first", "first", first_function.address),
                object_path=tmp_path / "first.obj",
                object_symbol="_foo",
                coff=first_coff,
            ),
            NativeObjectRecord(
                function=second_function,
                status=_status(tmp_path / "second", "second", second_function.address),
                object_path=tmp_path / "second.obj",
                object_symbol="_weak",
                coff=_coff(definitions=(("_weak", 1),)),
            ),
        ),
    )

    closure = symbol_closure_payload(
        objects,
        catalog=NativeSymbolCatalog({}, {}, {}, {}, ()),
        repo_root=tmp_path,
    )

    assert [row["name"] for row in closure["resolved"]] == ["_weak"]
    reference = closure["resolved"][0]["referenced_by"][0]
    assert reference["weak_fallback"] == "_foo"
    assert "weak_alias" not in reference


def test_reference_export_emits_linkable_definition_mapping(tmp_path: Path) -> None:
    function = _function("GRIM__GetInterface", 0x10001000)
    objects = NativeObjectSet(
        image="grim.dll",
        scope="port",
        manifest=matchlib.FunctionManifest("grim.dll", 0x10000000, (function,)),
        image_path=tmp_path / "grim.dll",
        records=(
            NativeObjectRecord(
                function=function,
                status=_status(
                    tmp_path / "factory",
                    "GRIM__GetInterface",
                    function.address,
                ),
                object_path=tmp_path / "factory.obj",
                object_symbol="_GRIM__GetInterface",
                coff=_coff(definitions=(("_GRIM__GetInterface", 1),)),
            ),
        ),
    )
    catalog = NativeSymbolCatalog(
        {},
        {},
        {},
        {},
        (
            {
                "address": function.address,
                "name": "GRIM__GetInterface",
                "noname": False,
                "ordinal": 1,
            },
        ),
    )

    closure = symbol_closure_payload(objects, catalog=catalog, repo_root=tmp_path)

    assert closure["summary"]["reference_exports_closed"] is True
    assert closure["exports"][0]["definition_mapping"]["internal_symbol"] == "_GRIM__GetInterface"
    assert closure["exports"][0]["definition_mapping"]["linker_internal_name"] == (
        "GRIM__GetInterface"
    )
    assert render_export_definition("grim.dll", closure) == (
        "LIBRARY grim.dll\n"
        "EXPORTS\n"
        "    GRIM__GetInterface=GRIM__GetInterface @1\n"
    )


def test_vc6_export_spelling_preserves_stdcall_suffix() -> None:
    assert _vc6_linker_internal_name("_function@8") == "function@8"
    assert _vc6_linker_internal_name("__leading_underscore") == "_leading_underscore"
    assert _vc6_linker_internal_name("?decorated@Cpp@@") == "?decorated@Cpp@@"


def test_grim_data_manifest_applies_typed_data_tranche() -> None:
    payload = data_manifest_payload("grim.dll")

    assert payload["summary"]["source_entry_count"] == 447
    assert payload["summary"]["code_label_entries"] == 6
    assert payload["summary"]["entry_count"] == 441
    assert payload["summary"]["typed_entries"] == 391
    assert payload["summary"]["explicit_size_entries"] == 349
    assert payload["summary"]["explicit_alignment_entries"] == 349
    assert payload["summary"]["explicit_initializer_entries"] == 349
    assert payload["summary"]["fully_specified_entries"] == 349
    assert payload["summary"]["definition_group_entries"] == 215
    assert payload["summary"]["definition_groups"] == 57
    assert payload["source"]["definitions"] == (
        "tools/native/data_definitions/grim.dll.json"
    )
    assert payload["source"]["data_map_projection"] == {
        "kind": "json-program-v1",
        "program": "grim.dll",
    }
    assert payload["source"]["data_map_sha256"] == (
        matchlib.native_json_program_sha256(
            matchlib.DEFAULT_DATA_MAP_PATH,
            "grim.dll",
        )
    )
    observed = {entry["name"]: entry for entry in payload["entries"]}
    assert observed["d3dx_format_conversion_matrix"]["type"] == "const int[5][5]"
    assert observed["grim_dxt1_optimize_epsilon"]["type"] == "const float"
    assert observed["grim_dxt_luminance_weights"]["type"] == "const float[3]"
    assert observed["grim_dxt_luminance_inverse"]["type"] == "const float[3]"
    assert observed["d3dx_sse_math_constants"]["type"] == "unsigned char[448]"
    assert observed["d3dx_sse2_quaternion_vectors"]["type"] == "unsigned char[160]"
    assert observed["d3dx_sse_trig_constants"]["type"] == "unsigned char[736]"
    assert observed["d3dx_sse2_trig_table"]["type"] == "unsigned char[768]"
    assert observed["d3dx_sse_math_bss"]["type"] == "unsigned char[32]"
    assert observed["d3dx_x87_math_pi_over_4_head_tail"]["type"] == "uint64_t"
    assert observed["d3dx_x87_math_sign"]["type"] == "uint32_t"
    assert observed["d3dx_rsqrt_half_vector"]["type"] == "float[4]"
    assert observed["d3dx_dds_pixel_format_table"]["type"] == "unsigned char[1224]"
    assert observed["grim_dither_bayer_pattern"]["type"] == "float[32]"
    assert observed["d3dx_debug_mute_d3d8_callback"]["type"] == "void (__cdecl *)(int)"
    assert observed["d3dx_debug_mute_d3d8d_callback"]["type"] == "void (__cdecl *)(int)"
    assert observed["fpu_control_word_saved_dxt"]["type"] == "unsigned long"
    assert observed["d3dx_box_filter_2d_a8r8g8b8_impl"]["type"] == "void *"
    assert observed["d3dx_box_filter_2d_x8r8g8b8_impl"]["type"] == "void *"
    assert observed["fpu_control_word_saved_blt"]["type"] == "unsigned long"
    assert observed["png_gamma_shift"]["type"] == "int[8]"
    assert observed["png_pass_mask"]["type"] == "const int[7]"
    assert observed["png_pass_dsp_mask"]["type"] == "const int[7]"
    assert observed["png_IHDR"]["type"] == "const png_byte[5]"
    assert observed["png_read_IDAT"]["type"] == "const png_byte[5]"
    assert observed["png_tRNS"]["type"] == "const png_byte[5]"
    assert observed["IID_IDirect3DVolumeTexture8"]["type"] == "const GUID"
    assert observed["IID_IDirect3DTexture8"]["type"] == "const GUID"
    assert observed["IID_IDirect3DBaseTexture8"]["type"] == "const GUID"
    assert observed["x3d_const3dn_0_1"]["type"] == "const float[2]"
    assert observed["x3d_const3dn_sign_bit_hi"]["type"] == "const uint32_t[2]"
    assert observed["x3d_const_half"]["type"] == "const float[2]"
    assert observed["x3d_const_negate_high_low"]["type"] == "const uint32_t[2]"
    assert observed["d3dx_jpeg_std_message_table"]["type"] == "const char *[120]"
    assert observed["grim_jpeg_first_pool_slop"]["type"] == "const size_t[2]"
    assert observed["grim_jpeg_extra_pool_slop"]["type"] == "const size_t[2]"
    assert observed["grim_jpeg_base_dither_matrix"]["type"] == "const unsigned char[16][16]"
    assert observed["grim_jpeg_quant1_rgb_order"]["type"] == "const int[3]"
    assert observed["grim_jpeg_idct_float_factor_1_082392200"]["type"] == "const float"
    assert observed["d3dx_jpeg_mmx_idct_enabled"]["type"] == "unsigned char"
    assert observed["d3dx_jpeg_idct_aanscales"]["type"] == "const short[64]"
    assert observed["d3dx_jpeg_idct_aanscalefactor"]["type"] == "const double[8]"
    assert observed["d3dx_jpeg_mmx_sub128"]["type"] == "const unsigned char[8]"
    assert observed["d3dx_jpeg_mmx_vu_mul"]["type"] == "const unsigned char[8]"
    assert observed["d3dx_jpeg_mmx_yv_mul"]["type"] == "const unsigned char[8]"
    assert observed["d3dx_jpeg_mmx_yu_mul"]["type"] == "const unsigned char[8]"
    assert observed["d3dx_jpeg_mmx_high_dword_mask"]["type"] == (
        "const unsigned char[8]"
    )
    assert observed["d3dx_jpeg_mmx_zero"]["type"] == "unsigned char[8]"
    assert observed["grim_crt_xc_a"]["type"] == "void *"
    assert observed["grim_crt_xc_z"]["type"] == "void *"
    assert observed["grim_crt_proc_attached"]["type"] == "int"
    assert observed["grim_crt_adjust_fdiv"]["type"] == "int"
    assert observed["grim_crt_raw_dll_main"]["type"] == "void *"
    assert observed["grim_crt_onexit_end"]["type"] == "void *"
    assert observed["grim_crt_onexit_begin"]["type"] == "void *"
    assert observed["d3dx_jpeg_base_dither_matrix"]["type"] == (
        "const unsigned char[16][16]"
    )
    assert observed["d3dx_jpeg_quant1_rgb_order"]["type"] == "const int[3]"
    assert observed["d3dx_zlib_inflate_border"]["type"] == (
        "const unsigned int[19]"
    )
    assert observed["d3dx_zlib_cplens"]["type"] == "const unsigned int[31]"
    assert observed["d3dx_zlib_cplext"]["type"] == "const unsigned int[31]"
    assert observed["d3dx_zlib_cpdist"]["type"] == "const unsigned int[30]"
    assert observed["d3dx_zlib_cpdext"]["type"] == "const unsigned int[30]"
    assert observed["d3dx_zlib_crc_table"]["type"] == "const unsigned long[256]"
    assert observed["d3dx_zlib_fixed_literal_bits"]["type"] == "unsigned int"
    assert observed["d3dx_zlib_fixed_distance_bits"]["type"] == "unsigned int"
    assert observed["d3dx_zlib_fixed_literal_tree"]["type"] == (
        "unsigned char[4096]"
    )
    assert observed["d3dx_zlib_fixed_distance_tree"]["type"] == (
        "unsigned char[256]"
    )
    assert observed["d3dx_zlib_inflate_mask"]["type"] == "unsigned int[17]"
    assert observed["png_pass_start"]["type"] == "const int[7]"
    assert observed["png_pass_inc"]["type"] == "const int[7]"
    assert observed["png_pass_ystart"]["type"] == "const int[7]"
    assert observed["png_pass_yinc"]["type"] == "const int[7]"
    assert observed["png_IDAT"]["type"] == "const png_byte[5]"
    assert observed["grim_window_proc_dc_flag"]["type"] == "unsigned char"
    assert observed["grim_window_proc_dc_flag"]["definition_state"] == "unknown"
    assert observed["grim_window_proc_paint_flag"]["type"] == "unsigned char"
    assert observed["grim_window_proc_paint_flag"]["definition_state"] == "unknown"
    defined = {
        entry["name"]: entry
        for entry in payload["entries"]
        if entry["definition_state"] == "fully-specified"
    }
    assert defined["grim_d3d_device"]["size"] == 4
    assert defined["grim_d3d_device"]["initializer_hex"] == "00000000"
    assert defined["grim_render_disabled"]["size"] == 1
    assert defined["grim_render_disabled"]["initializer_hex"] == "00"
    assert defined["grim_parental_lock_enabled_text"]["initializer_target"] == {
        "address": 0x100530A8,
        "name": "grim_parental_lock_enabled_text_data",
    }
    assert defined["grim_parental_password_buffer"]["size"] == 0x100
    assert defined["grim_parental_password_buffer"]["initializer_fill"] == "00"
    assert defined["grim_advanced_texture_formats"]["size"] == 6 * 4
    assert defined["grim_advanced_texture_format_count"]["initializer_hex"] == (
        "00000000"
    )
    assert defined["grim_adapter_identifier"]["size"] == 0x42C
    assert defined["grim_pixel_format_vtable_dxt"]["size"] == 0x10
    assert [
        (slot["offset"], slot["address"])
        for slot in defined["grim_pixel_format_vtable_dxt"]["initializer_symbols"]
    ] == [
        (0x0, 0x1001AEC8),
        (0x4, 0x1001B0FD),
        (0x8, 0x10016CDC),
        (0xC, 0x1001AF00),
    ]
    assert defined["grim_present_width"]["size"] == 0x34
    assert defined["grim_app"]["size"] == 0x2C
    assert defined["grim_client_rect"]["size"] == 0x10
    assert defined["grim_joystick_buttons"]["size"] == 0x80
    assert defined["fpu_control_word_saved_ftol"]["size"] == 2
    assert defined["grim_config_selected_width"]["initializer_hex"] == "80020000"
    assert defined["grim_caps_can_render_windowed"]["initializer_hex"] == "01"
    assert defined["grim_dither_half_pattern"]["size"] == 0x80
    assert defined["grim_window_class"]["size"] == 0x30
    assert defined["grim_device_caps"]["size"] == 0xD4
    assert defined["grim_config_dialog_system_time"]["size"] == 0x10
    assert defined["grim_mouse_state"]["size"] == 0x14
    assert defined["grim_mouse_buttons"]["size"] == 8
    assert defined["grim_uint32_float_bias"]["initializer_hex"] == "0000804f"
    assert defined["grim_dxt5_alpha_weights_max_8"]["size"] == 0x20
    assert defined["grim_dxt1_color_weights_min_3"]["size"] == 0x0C
    assert defined["grim_dxt5_alpha_index_map_6"]["size"] == 0x18
    assert defined["grim_dxt1_optimize_epsilon"]["initializer_hex"] == "00008037"
    assert defined["grim_dxt_luminance_weights"]["size"] == 0x0C
    assert defined["grim_dxt_luminance_inverse"]["size"] == 0x0C
    assert defined["fpu_control_word_saved_dxt"]["size"] == 4
    assert defined["d3dx_box_filter_2d_a8r8g8b8_impl"]["initializer_symbols"] == [
        {
            "address": 0x100134EA,
            "offset": 0,
            "symbol": "d3dx_init_box_filter_2d_a8r8g8b8",
        },
    ]
    assert defined["d3dx_box_filter_2d_x8r8g8b8_impl"]["initializer_symbols"] == [
        {
            "address": 0x10013522,
            "offset": 0,
            "symbol": "d3dx_init_box_filter_2d_x8r8g8b8",
        },
    ]
    assert defined["fpu_control_word_saved_blt"]["initializer_hex"] == "00000000"
    assert defined["png_gamma_shift"]["initializer_hex"] == (
        "10000000210000004200000084000000100100004802000050050000f00f0000"
    )
    assert defined["grim_format_info_default"]["size"] == 0x24
    assert defined["grim_format_info_entries"]["size"] == 43 * 0x24
    assert defined["grim_format_info_end"]["initializer_hex"] == "bcc90410"
    assert defined["grim_png_signature"]["size"] == 8
    assert defined["grim_png_signature"]["initializer_hex"] == (
        "89504e470d0a1a0a"
    )
    assert defined["c_dfDIJoystick2"]["initializer_hex"] == (
        "18000000100000000100000010010000a4000000808e0310"
    )
    assert defined["c_dfDIKeyboard"]["initializer_hex"] == (
        "1800000010000000020000000001000000010000d0980310"
    )
    assert defined["c_dfDIMouse2"]["initializer_hex"] == (
        "180000001000000002000000140000000b000000d0a80310"
    )
    assert defined["IID_IDirectInput8A"]["initializer_hex"] == (
        "308079bf3a48a24daa995d64ed369700"
    )
    assert defined["grim_config_blob"]["size"] == 0x480
    assert defined["grim_config_values"]["size"] == 128 * 0x10
    assert defined["grim_joystick_state"]["size"] == 0x110
    assert defined["grim_keyboard_event_buffer"]["size"] == 10 * 0x14
    assert defined["grim_vertex_z"]["definition_group"] == "literal-float32"
    assert defined["grim_interface_instance"]["definition_group"] == (
        "zero-pointer32"
    )
    assert defined["grim_subrect_ptr3"]["definition_group"] == "zero-pointer32"
    assert defined["grim_vertex_write_ptr"]["size"] == 4
    assert defined["grim_uv_u0"]["size"] == 4 * 8
    assert defined["grim_font2_uv_u"]["size"] == 256 * 8
    assert defined["grim_color_slot0"]["size"] == 4 * 4
    assert defined["grim_slot_ints"]["size"] == 128 * 4
    assert defined["grim_texture_slots"]["size"] == 256 * 4
    assert defined["grim_interface_vtable"]["size"] == 84 * 4
    assert len(defined["grim_interface_vtable"]["initializer_symbols"]) == 84
    assert defined["grim_lookup_blob_magic"]["initializer_target"] == {
        "address": 0x100530F0,
        "name": "grim_lookup_blob_magic_text",
    }
    assert defined["grim_key_char_buffer"]["initializer_target"] == {
        "address": 0x10059BBC,
        "name": "grim_key_char_default_buffer",
    }
    assert defined["grim_key_char_buffer_count"]["initializer_target"] == {
        "address": 0x1005D3C0,
        "name": "grim_key_char_default_count",
    }
    assert defined["grim_lookup_blob_magic_text"]["initializer_hex"] == "70617100"
    assert defined["grim_key_char_default_buffer"]["size"] == 510
    assert defined["grim_key_char_default_count"]["size"] == 4
    names = {entry["name"] for entry in payload["entries"]}
    assert "grim_dxt2_decode_block" not in names
    assert "grim_dxt4_decode_block" not in names


def test_crimsonland_data_manifest_applies_high_fan_in_definitions() -> None:
    payload = data_manifest_payload("crimsonland.exe")

    assert payload["summary"]["source_entry_count"] == 1823
    assert payload["summary"]["code_label_entries"] == 54
    assert payload["summary"]["entry_count"] == 1769
    assert payload["summary"]["typed_entries"] == 1769
    assert payload["summary"]["untyped_entries"] == 0
    assert payload["summary"]["explicit_size_entries"] == 1769
    assert payload["summary"]["explicit_alignment_entries"] == 1769
    assert payload["summary"]["explicit_initializer_entries"] == 1769
    assert payload["summary"]["fully_specified_entries"] == 1769
    assert payload["summary"]["definition_group_entries"] == 1660
    assert payload["summary"]["definition_groups"] == 174
    assert {
        entry["name"]
        for entry in payload["entries"]
    }.isdisjoint(
        {
            "game_startup_intro_mute_callsite",
            "game_startup_theme_play_callsite",
            "game_startup_intro_play_callsite",
        },
    )
    assert payload["source"]["definitions"] == (
        "tools/native/data_definitions/crimsonland.exe.json"
    )
    defined = {
        entry["name"]: entry
        for entry in payload["entries"]
        if entry["definition_state"] == "fully-specified"
    }
    for scope_table in (
        "crt_calloc_scope_table",
        "crt_free_scope_table",
        "crt_msize_scope_table",
        "crt_realloc_scope_table",
    ):
        assert defined[scope_table]["size"] == 24
        assert defined[scope_table]["definition_group"] == "literal-compiler-rdata-00018"
    assert defined["d3dx_sse_rsqrt_half_vector"]["size"] == 16
    assert defined["d3dx_sse_rsqrt_half_vector"]["alignment"] == 16
    assert defined["d3dx_sse_rsqrt_three_vector"]["size"] == 16
    assert defined["d3dx_sse_rsqrt_three_vector"]["alignment"] == 16
    assert defined["d3dx_sse_rsqrt_init_guard"]["size"] == 1
    assert defined["d3dx_sse_rsqrt_init_guard"]["alignment"] == 1
    assert defined["config_blob"]["size"] == 0x480
    assert defined["config_blob"]["initializer_fill"] == "00"
    assert defined["config_direction_arrow_flags"]["size"] == 2
    assert defined["config_player_mode_flags"]["size"] == 4 * 4
    assert defined["config_saved_name_0"]["size"] == 27
    assert defined["config_key_reload"]["definition_group"] == (
        "mapped-bss-zero-int32"
    )
    assert defined["x3d_const3dn_1_1"]["initializer_hex"] == (
        "0000803f0000803f"
    )
    assert defined["x3d_const3dn_1_1"]["definition_group"] == (
        "literal-d3dx-x3d-m64"
    )
    assert defined["d3dx_x87_math_ones"]["initializer_hex"] == (
        "0000803f0000803f"
    )
    assert defined["d3dx_x87_math_ones"]["definition_group"] == (
        "literal-d3dx-x87-packed64"
    )
    assert defined["d3dx_x87_math_half"]["initializer_hex"] == "0000003f"
    assert defined["d3dx_x87_math_half"]["definition_group"] == (
        "literal-d3dx-x87-word32"
    )
    assert defined["d3dx_sse_math_constants"]["size"] == 448
    assert defined["d3dx_sse_quaternion_constants"]["size"] == 64
    assert defined["d3dx_sse_math_bss"]["initializer_fill"] == "00"
    assert defined["d3dx_sse_quaternion_vectors"]["size"] == 160
    assert defined["d3dx_sse2_math_vectors"]["size"] == 192
    assert defined["d3dx_inverse_sqrt_table"]["size"] == 4096
    assert defined["d3dx_inverse_sqrt_table"]["initializer_hex"].startswith(
        "007eb4bffaa10740",
    )
    assert defined["d3dx_sse_trig_constants"]["size"] == 736
    assert defined["d3dx_sse2_trig_table"]["size"] == 768
    assert defined["player_state_table"]["size"] == 0x6C0
    assert defined["player_perk_counts"]["size"] == 0x200
    assert defined["player_perk_counts"]["definition_group"] == (
        "player-state-zero-int-array-00200"
    )
    assert defined["player_health"]["size"] == 4
    assert defined["player_reload_active"]["size"] == 1
    assert defined["player_alt_fire_key"]["size"] == 4
    assert defined["creature_pool"]["size"] == 0xE400
    assert defined["creature_health"]["size"] == 4
    assert defined["creature_target_player"]["size"] == 1
    assert defined["creature_orbit_radius"]["definition_group"] == (
        "creature-state-zero-orbit-radius-00004"
    )
    assert defined["creature_type_lizard"]["size"] == 0x44
    assert defined["creature_type_lizard"]["definition_group"] == (
        "creature-type-zero-record-00044"
    )
    assert defined["highscore_table"]["size"] == 0x1C20
    assert defined["ui_element_table_end"]["size"] == 0xA4
    assert defined["ui_element_table_slot_01_main_menu_aux"]["size"] == 4
    assert defined["ui_element_table_start"]["definition_group"] == "zero-pointer32"
    assert defined["bonus_state"]["size"] == 1
    assert defined["bonus_icon_fire_bullets"]["size"] == 4
    assert defined["bonus_hud_slot_timer_ptr"]["definition_group"] == "zero-pointer32"
    assert defined["projectile_type_id"]["definition_group"] == "zero-enum32"
    assert defined["secondary_proj_unused_0x28"]["definition_group"] == "zero-uint32"
    assert defined["effect_template"]["size"] == 0x3C
    assert defined["effect_template_scale_step"]["size"] == 4
    assert defined["effect_pool_pos_x"]["size"] == 0xBC
    assert defined["effect_pool_quad_data"]["size"] == 0x70
    assert defined["quest_selected_builder"]["definition_group"] == "zero-pointer32"
    assert defined["quest_meta_terrain_desc_unlock_gt_0x13"]["size"] == 0x2C
    assert defined["weapon_usage_counts"]["size"] == 0xD4
    assert defined["quest_play_counts"]["size"] == 0x16C
    assert defined["game_sequence_id"]["definition_group"] == "zero-uint32"
    assert defined["fire_bullets_fallback_spread_heat"]["size"] == 4
    assert defined["perk_available_table"]["size"] == 1
    assert defined["survival_elapsed_ms"]["definition_group"] == "zero-uint32"
    assert defined["highscore_hardcore_marker"]["size"] == 1
    assert defined["game_over_name_input_state_alpha"]["definition_group"] == (
        "mapped-bss-zero-float32"
    )
    assert defined["credits_line_table_flags"]["size"] == 4
    assert defined["survival_recent_death_pos_1"]["size"] == 8
    assert defined["player_overlay_torso_uv8"]["definition_group"] == (
        "zero-abi-00008"
    )
    assert defined["local_system_day"]["definition_group"] == "zero-ushort16"
    assert defined["sfx_entry_table_state"]["definition_group"] == "zero-pointer32"
    assert defined["effect_id_frame"]["initializer_hex"] == "02000000"
    assert defined["console_command_list_head"]["definition_group"] == "zero-pointer32"
    assert defined["console_echo_enabled"]["definition_group"] == "zero-uchar"
    assert defined["console_height_px"]["definition_group"] == "zero-int32"
    assert defined["IID_IDxDiagProvider"]["initializer_hex"] == (
        "b04c6b9cf823cc49a3ed45a55000a6d2"
    )
    assert defined["aim_screen_x"]["definition_group"] == "mapped-bss-zero-float32"
    assert defined["credits_secret_button"]["definition_group"] == (
        "mapped-bss-zero-ui-button"
    )
    assert defined["sfx_bullet_hit_06"]["definition_group"] == "source-zero-int32"
    assert defined["play_game_menu_button_survival"]["definition_group"] == (
        "zero-abi-00018"
    )
    assert defined["crt_onexit_table_begin"]["definition_group"] == (
        "mapped-bss-zero-pointer32"
    )
    assert len(defined["mod_api_vtable"]["initializer_symbols"]) == 34
    assert defined["renderer_dispatch_table"]["size"] == 57 * 4
    assert defined["vec2_normalize_impl"]["initializer_hex"] == "1d2f4500"
    assert defined["renderer_dispatch_defaults"]["size"] == 57 * 4
    assert defined["crt_output_lookup_table"]["size"] == 0x5C
    assert defined["crt_xc_begin"]["initializer_hex"] == "00000000"
    assert defined["crt_xi_end"]["initializer_hex"] == "00000000"
    assert defined["crt_fp_init_hook"]["initializer_hex"] == "b80c4600"
    assert defined["crt_cfltcvt_table"]["size"] == 6 * 4
    assert defined["crt_nlg_destination"]["initializer_hex"] == (
        "20059319000000000000000000000000"
    )
    assert defined["crt_iob"]["size"] == 20 * 32
    assert defined["crt_ctype_table"]["initializer_hex"] == "cab14700"
    assert defined["crt_ctype_data"]["size"] == 258 * 2
    assert defined["crt_null_string"]["initializer_hex"] == "44fb4600"
    assert defined["crt_wide_null_string"]["initializer_hex"] == "34fb4600"
    assert defined["crt_dosmaperr_table"]["size"] == 45 * 8
    assert defined["crt_bad_ioinfo"]["size"] == 0x24
    assert defined["crt_runtime_errors"]["size"] == 18 * 8
    assert defined["crt_x87_overflow_value"]["size"] == 10
    assert defined["crt_x87_underflow_value"]["size"] == 10
    assert defined["crt_double_format_descriptor"]["size"] == 24
    assert defined["crt_double_format_descriptor"]["alignment"] == 8
    assert defined["crt_float_format_descriptor"]["size"] == 24
    assert defined["crt_float_format_descriptor"]["alignment"] == 8
    assert defined["crt_codepage_ctype_flags"]["initializer_hex"] == "01020408"
    assert defined["crt_codepage_info"]["size"] == 5 * 0x30
    assert defined["crt_gmt_cache"]["initializer_fill"] == "00"
    assert defined["crt_lock_table"]["size"] == 48 * 4
    assert defined["crt_lock_table"]["definition_group"] == (
        "literal-pointer-array-000c0"
    )
    assert defined["crt_old_small_block_heap"]["size"] == 0x2020
    assert defined["crt_fdiv_risc_table"]["size"] == 0x10
    assert defined["crt_fprem_risc_table"]["size"] == 0x18
    assert defined["crt_fdiv_dispatch_table"]["size"] == 0x102
    assert defined["crt_pow10_positive"]["size"] == 0x160
    assert defined["crt_pow10_negative"]["size"] == 0x15C
    assert defined["crt_standard_buffers"]["initializer_fill"] == "00"
    assert defined["crt_file_mode"]["definition_group"] == (
        "mapped-bss-zero-int32"
    )
    assert defined["crt_ehvec_ctor_scope_table"]["size"] == 0x0C
    assert defined["crt_start_scope_table"]["initializer_hex"] == (
        "ffffffff0f31460023314600"
    )
    assert defined["crt_call_catch_block_scope_table"]["size"] == 0x18
    assert defined["crt_compare_string_a_scope_table"]["definition_group"] == (
        "literal-compiler-rdata-00018"
    )
    assert defined["crt_four_nul_literal"]["initializer_hex"] == "00000000"
    assert defined["crt_two_nul_literal"]["initializer_hex"] == "0000"
    assert defined["crt_windows_minor"]["definition_group"] == (
        "mapped-bss-zero-uint32"
    )
    assert defined["crt_tz_names"]["initializer_hex"] == "7cde4700bcde4700"
    assert defined["crt_dst_start_rule"]["size"] == 3 * 4
    assert defined["crt_dst_end_rule"]["size"] == 3 * 4
    assert defined["crt_leap_year_days"]["size"] == 13 * 4
    assert defined["crt_month_days"]["size"] == 13 * 4
    assert defined["crt_timezone_info"]["initializer_fill"] == "00"
    assert defined["ui_perk_prompt_on_activate"]["definition_group"] == (
        "zero-pointer32"
    )
    assert defined["ui_perk_prompt_levelup_element"]["size"] == 0xE8
    assert defined["controls_key_reload_item"]["size"] == 0x10
    assert defined["music_entry_table"]["size"] == 0x4200
    assert defined["weapon_table"]["size"] == 0x1F00
    assert defined["weapon_ammo_class"]["size"] == 0x1F00
    assert defined["console_log_queue"]["size"] == 0x2C
    assert defined["grim_interface_ptr"]["size"] == 4
    assert defined["sfx_unmuted_flag"]["size"] == 1
    assert defined["quest_unlock_index"]["size"] == 2
    assert defined["perk_pending_count"]["definition_group"] == "zero-int32"
    assert defined["plugin_interface_ptr"]["definition_group"] == "zero-pointer32"
    assert defined["ui_elements_timeline"]["definition_group"] == (
        "source-zero-int32"
    )
    assert defined["ui_transition_alpha"]["definition_group"] == (
        "source-zero-float32"
    )
    assert defined["time_scale_active"]["definition_group"] == (
        "source-zero-uchar"
    )
    assert defined["effect_pool"]["size"] == 0x17800
    assert defined["quest_spawn_table"]["size"] == 0x1800
    assert defined["ui_sign_crimson_template"]["size"] == 0xE8
    assert defined["ui_element_slot_footer_variant_a"]["definition_group"] == (
        "zero-ui-element-slots"
    )
    assert defined["demo_time_limit_ms"]["initializer_hex"] == "10270000"
    assert defined["default_player_name"]["size"] == 7
    assert defined["input_key_name_mail"]["type"] == "char[5]"
    assert defined["input_key_name_mail"]["initializer_hex"] == "4d41494c00"
    assert defined["input_key_name_rim1_y_axis"]["size"] == 10
    assert defined["input_key_name_dik_dispatch_map"]["size"] == 237
    assert (
        defined["input_key_name_dik_dispatch_map"]["initializer_hex"][:16]
        == "0001020304050607"
    )
    assert defined["console_cmd_exec_str"]["type"] == "char[5]"
    assert defined["console_cmd_exec_str"]["initializer_hex"] == "6578656300"
    assert defined["highscore_month_label_jan"]["size"] == 4
    assert defined["s_highscore_tooltip_hit_ratio"]["size"] == 37
    assert defined["renderer_backend_kind"]["initializer_hex"] == "ffff0000"
    assert defined["perk_selection_screen_flags"]["definition_group"] == (
        "mapped-bss-zero-int32"
    )
    assert defined["typo_target_world_y"]["size"] == 4
    assert defined["play_game_menu_survival_enabled"]["size"] == 1
    assert defined["game_completed_survival_button"]["size"] == 0x18
    assert defined["perk_selection_choice_items"]["size"] == 0xA0
    assert defined["mod_info_block"]["size"] == 0x48
    assert defined["highscore_screen_score_line_buffers"]["size"] == 0x668
    assert defined["console_log_queue"]["type"] == "console_queue_t"
    assert defined["frame_dt"]["type"] == "float"
    assert defined["perk_id_doctor"]["type"] == "int"
    assert defined["console_input_buf"]["size"] == 1024
    assert defined["typo_target_name_table"]["size"] == 384 * 64
    assert defined["terrain_texture_handles"]["size"] == 8 * 4
    assert defined["effect_id_table"]["size"] == 19 * 8
    assert defined["console_tokenize_buf"]["size"] == 1024
    assert defined["resource_pack_entry_name_buf"]["size"] == 512
    assert defined["grim_dll_name"]["size"] == 256
    assert defined["typo_word_highscore_cache"]["size"] == 20 * 32
    assert defined["camera_offset"]["size"] == 8
    assert defined["render_tint_color"]["size"] == 16
    assert defined["reserved_color_4871b8"]["size"] == 16
    assert defined["console_empty_arg"]["initializer_target"] == {
        "address": 0x0047F4D8,
        "name": "s_empty_string",
    }


def test_data_manifest_ranks_game_data_by_reference_fan_in() -> None:
    closure = {
        "unresolved": [
            {
                "category": "game_data",
                "name": "?grim_d3d_device@@3PAUIDirect3DDevice8@@A",
                "lookup_name": "grim_d3d_device",
                "catalog": [
                    {
                        "address": 0x10059DBC,
                        "name": "grim_d3d_device",
                    },
                ],
                "referenced_by": [
                    {"function": "first"},
                    {"function": "second"},
                ],
            },
        ],
    }

    payload = data_manifest_payload("grim.dll", symbol_closure=closure)

    assert payload["summary"]["referenced_entries"] == 1
    assert payload["summary"]["game_data_reference_count"] == 2
    assert payload["priorities"][0] == {
        "address": 0x10059DBC,
        "definition_state": "fully-specified",
        "name": "grim_d3d_device",
        "reference_count": 2,
        "requested_symbols": [
            {
                "lookup_name": "grim_d3d_device",
                "name": "?grim_d3d_device@@3PAUIDirect3DDevice8@@A",
                "reference_count": 2,
            },
        ],
    }


def test_data_definitions_reject_initializer_size_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "grim.dll.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "bad",
                        "size": 4,
                        "size_source": "type evidence",
                        "initializer_hex": "00",
                        "initializer_source": "image evidence",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="initializer has 1 bytes, expected size 4"):
        load_native_data_definitions("grim.dll", path=path)


def test_data_definitions_normalize_symbolic_initializer_target(
    tmp_path: Path,
) -> None:
    path = tmp_path / "grim.dll.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "pointer",
                        "size": 4,
                        "size_source": "pointer ABI",
                        "alignment": 4,
                        "alignment_source": "pointer ABI",
                        "initializer_target": [
                            "0x10054000",
                            "target_string",
                        ],
                        "initializer_source": "reference image pointer",
                    },
                    {
                        "address": "0x10054000",
                        "name": "target_string",
                        "size": 2,
                        "size_source": "CString extent",
                        "alignment": 1,
                        "alignment_source": "char ABI",
                        "initializer_hex": "7800",
                        "initializer_source": "reference image string",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    payload = load_native_data_definitions("grim.dll", path=path)

    assert payload is not None
    assert payload["entries"][0]["initializer_target"] == {
        "address": 0x10054000,
        "name": "target_string",
    }


def test_data_definitions_normalize_external_symbol_initializers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "grim.dll.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "vtable",
                        "size": 8,
                        "size_source": "vtable layout",
                        "alignment": 4,
                        "alignment_source": "pointer ABI",
                        "initializer_symbols": [
                            [0, "0x10002000", "_first"],
                            [4, "0x10003000", "?second@@YAXXZ"],
                        ],
                        "initializer_source": "reference image vtable",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    payload = load_native_data_definitions("grim.dll", path=path)

    assert payload is not None
    assert payload["entries"][0]["initializer_symbols"] == [
        {
            "offset": 0,
            "address": 0x10002000,
            "symbol": "_first",
        },
        {
            "offset": 4,
            "address": 0x10003000,
            "symbol": "?second@@YAXXZ",
        },
    ]


def test_data_definition_groups_expand_data_map_checked_members(
    tmp_path: Path,
) -> None:
    path = tmp_path / "grim.dll.json"
    data_map_path = tmp_path / "data.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "groups": [
                    {
                        "name": "zero-int32",
                        "types": [None],
                        "size": 4,
                        "size_source": "data-map type",
                        "alignment": 4,
                        "alignment_source": "data-map type",
                        "initializer_fill": "00",
                        "initializer_source": "reference image",
                        "members": [["0x10053000", "counter"]],
                    },
                ],
                "entries": [],
            },
        ),
        encoding="utf-8",
    )
    data_map_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "counter",
                        "program": "grim.dll",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    payload = load_native_data_definitions(
        "grim.dll",
        path=path,
        data_map_path=data_map_path,
    )

    assert payload is not None
    assert payload["groups"] == ["zero-int32"]
    assert payload["entries"] == [
        {
            "address": 0x10053000,
            "alignment": 4,
            "alignment_source": "data-map type",
            "definition_group": "zero-int32",
            "initializer_fill": "00",
            "initializer_hex": None,
            "initializer_source": "reference image",
            "initializer_symbols": [],
            "initializer_target": None,
            "name": "counter",
            "note": "",
            "size": 4,
            "size_source": "data-map type",
        },
    ]


def test_data_definition_groups_reject_data_map_type_mismatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "grim.dll.json"
    data_map_path = tmp_path / "data.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "groups": [
                    {
                        "name": "zero-int32",
                        "types": ["int"],
                        "size": 4,
                        "size_source": "data-map type",
                        "members": [["0x10053000", "counter"]],
                    },
                ],
                "entries": [],
            },
        ),
        encoding="utf-8",
    )
    data_map_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "counter",
                        "program": "grim.dll",
                        "type": "float",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="data-map type 'float'"):
        load_native_data_definitions(
            "grim.dll",
            path=path,
            data_map_path=data_map_path,
        )


def test_data_definition_groups_expand_member_initializers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "grim.dll.json"
    data_map_path = tmp_path / "data.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "groups": [
                    {
                        "name": "literal-int32",
                        "types": ["int"],
                        "size": 4,
                        "size_source": "data-map type",
                        "alignment": 4,
                        "alignment_source": "data-map type",
                        "member_initializer_hex": True,
                        "initializer_source": "reference image",
                        "members": [
                            ["0x10053000", "first", "01000000"],
                            ["0x10053004", "second", "ffffffff"],
                        ],
                    },
                ],
                "entries": [],
            },
        ),
        encoding="utf-8",
    )
    data_map_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "first",
                        "program": "grim.dll",
                        "type": "int",
                    },
                    {
                        "address": "0x10053004",
                        "name": "second",
                        "program": "grim.dll",
                        "type": "int",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    payload = load_native_data_definitions(
        "grim.dll",
        path=path,
        data_map_path=data_map_path,
    )

    assert payload is not None
    assert [
        (entry["name"], entry["initializer_hex"])
        for entry in payload["entries"]
    ] == [
        ("first", "01000000"),
        ("second", "ffffffff"),
    ]


def test_data_definition_groups_reject_malformed_member_initializer(
    tmp_path: Path,
) -> None:
    path = tmp_path / "grim.dll.json"
    data_map_path = tmp_path / "data.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "kind": "crimson-native-data-definitions",
                "image": "grim.dll",
                "reference_image": {
                    "path": "game_bins/grim.dll",
                    "sha256": "0" * 64,
                },
                "groups": [
                    {
                        "name": "literal-int32",
                        "types": ["int"],
                        "size": 4,
                        "size_source": "data-map type",
                        "member_initializer_hex": True,
                        "initializer_source": "reference image",
                        "members": [["0x10053000", "counter", "not-hex"]],
                    },
                ],
                "entries": [],
            },
        ),
        encoding="utf-8",
    )
    data_map_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "address": "0x10053000",
                        "name": "counter",
                        "program": "grim.dll",
                        "type": "int",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="lowercase byte hex"):
        load_native_data_definitions(
            "grim.dll",
            path=path,
            data_map_path=data_map_path,
        )


def _build_auxiliary_coff(*, relocation_symbol_index: int | None = None) -> bytes:
    code = b"\xc3\x00\x00\x00"
    header_size = 20
    section_header_size = 40
    code_offset = header_size + section_header_size
    relocations = (
        b""
        if relocation_symbol_index is None
        else struct.pack("<IIH", 0, relocation_symbol_index, matchlib.IMAGE_REL_I386_REL32)
    )
    relocation_offset = code_offset + len(code) if relocations else 0
    symbol_table_offset = code_offset + len(code) + len(relocations)

    section_symbol = struct.pack("<8sIhHBB", b".text", 0, 1, 0, 3, 1)
    section_aux = struct.pack("<IHHIhB3x", len(code), 0, 0, 0, 0, 2)
    function_symbol = struct.pack("<8sIhHBB", b"_foo", 0, 1, 0x20, 2, 0)
    weak_symbol = struct.pack(
        "<8sIhHBB",
        b"_weak",
        0,
        0,
        0,
        IMAGE_SYM_CLASS_WEAK_EXTERNAL,
        1,
    )
    weak_aux = struct.pack("<II10x", 2, 3)
    symbols = section_symbol + section_aux + function_symbol + weak_symbol + weak_aux
    symbol_count = 5
    header = struct.pack(
        "<HHIIIHH",
        matchlib.IMAGE_FILE_MACHINE_I386,
        1,
        0,
        symbol_table_offset,
        symbol_count,
        0,
        0,
    )
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        0,
        0,
        len(code),
        code_offset,
        relocation_offset,
        0,
        1 if relocations else 0,
        0,
        0x60000020 | IMAGE_SCN_LNK_COMDAT,
    )
    return header + section + code + relocations + symbols + struct.pack("<I", 4)


def test_coff_parser_preserves_comdat_and_weak_auxiliary_records() -> None:
    obj = matchlib.parse_coff_object(_build_auxiliary_coff())

    assert obj.sections[0].index == 1
    assert obj.sections[0].comdat_key == "_foo"
    assert obj.sections[0].comdat_selection == 2
    assert [symbol.raw_index for symbol in obj.symbols] == [0, 2, 3]
    weak = obj.symbols[-1]
    assert weak.weak_default_symbol_index == 2
    assert weak.weak_search == 3
    assert len(weak.aux_records) == 1


def test_coff_parser_rejects_symbol_in_nonexistent_section() -> None:
    data = bytearray(_build_auxiliary_coff())
    symbol_table_offset = struct.unpack_from("<I", data, 8)[0]
    function_symbol_offset = symbol_table_offset + 2 * 18
    struct.pack_into("<h", data, function_symbol_offset + 12, 99)

    with pytest.raises(ValueError, match="references invalid section 99"):
        matchlib.parse_coff_object(bytes(data))


def test_coff_parser_rejects_relocation_to_auxiliary_symbol() -> None:
    with pytest.raises(ValueError, match="invalid symbol index"):
        matchlib.parse_coff_object(
            _build_auxiliary_coff(relocation_symbol_index=1),
        )


def test_coff_parser_rejects_relocation_past_section_end() -> None:
    data = bytearray(_build_auxiliary_coff(relocation_symbol_index=2))
    relocation_offset = struct.unpack_from("<I", data, 20 + 24)[0]
    struct.pack_into("<I", data, relocation_offset, 1)

    with pytest.raises(ValueError, match="exceeds section size"):
        matchlib.parse_coff_object(bytes(data))


@pytest.mark.parametrize("relocation_type", (0x01, 0x02, 0x09, 0x15))
def test_coff_parser_rejects_non_i386_relocation_type(relocation_type: int) -> None:
    data = bytearray(_build_auxiliary_coff(relocation_symbol_index=2))
    relocation_offset = struct.unpack_from("<I", data, 20 + 24)[0]
    struct.pack_into("<H", data, relocation_offset + 8, relocation_type)

    with pytest.raises(
        ValueError,
        match=f"unsupported i386 relocation type 0x{relocation_type:x}",
    ):
        matchlib.parse_coff_object(bytes(data))


def test_coff_parser_rejects_invalid_associative_comdat_parent() -> None:
    data = bytearray(_build_auxiliary_coff())
    symbol_table_offset = struct.unpack_from("<I", data, 8)[0]
    section_aux_offset = symbol_table_offset + 18
    struct.pack_into("<h", data, section_aux_offset + 12, 99)
    data[section_aux_offset + 14] = 5

    with pytest.raises(ValueError, match="invalid parent 99"):
        matchlib.parse_coff_object(bytes(data))


@pytest.mark.parametrize(
    ("field_offset", "field_format", "value"),
    (
        (8, "<I", 1),
        (14, "<H", 0x20),
    ),
)
def test_coff_parser_rejects_invalid_comdat_section_symbol_fields(
    field_offset: int,
    field_format: str,
    value: int,
) -> None:
    data = bytearray(_build_auxiliary_coff())
    symbol_table_offset = struct.unpack_from("<I", data, 8)[0]
    struct.pack_into(field_format, data, symbol_table_offset + field_offset, value)

    with pytest.raises(ValueError, match="invalid value or type"):
        matchlib.parse_coff_object(bytes(data))


def test_coff_parser_rejects_comdat_section_symbol_after_section_member() -> None:
    data = bytearray(_build_auxiliary_coff())
    symbol_table_offset = struct.unpack_from("<I", data, 8)[0]
    early_section_member = struct.pack("<8sIhHBB", b"_early", 0, 1, 0, 2, 0)
    data[symbol_table_offset:symbol_table_offset] = early_section_member
    struct.pack_into("<I", data, 12, 6)
    weak_aux_offset = symbol_table_offset + 5 * 18
    struct.pack_into("<I", data, weak_aux_offset, 3)

    with pytest.raises(ValueError, match="definition symbol must be first"):
        matchlib.parse_coff_object(bytes(data))


def _build_overflow_relocation_coff(actual_count: int = 0x10000) -> bytes:
    code = b"\xc3\x00\x00\x00"
    code_offset = 20 + 40
    relocation_offset = code_offset + len(code)
    relocation_table_count = actual_count + 1
    relocations = struct.pack("<IIH", relocation_table_count, 0, 0) + (
        struct.pack("<IIH", 0, 0, matchlib.IMAGE_REL_I386_REL32) * actual_count
    )
    symbol_table_offset = relocation_offset + len(relocations)
    symbol = struct.pack("<8sIhHBB", b"_foo", 0, 1, 0x20, 2, 0)
    header = struct.pack(
        "<HHIIIHH",
        matchlib.IMAGE_FILE_MACHINE_I386,
        1,
        0,
        symbol_table_offset,
        1,
        0,
        0,
    )
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        0,
        0,
        len(code),
        code_offset,
        relocation_offset,
        0,
        0xFFFF,
        0,
        0x60000020 | matchlib.IMAGE_SCN_LNK_NRELOC_OVFL,
    )
    return header + section + code + relocations + symbol + struct.pack("<I", 4)


def test_coff_parser_reads_extended_relocation_table() -> None:
    obj = matchlib.parse_coff_object(_build_overflow_relocation_coff())

    assert len(obj.sections[0].relocations) == 0x10000


def test_coff_parser_preserves_bss_logical_size() -> None:
    symbol_table_offset = 20 + 40
    symbol = struct.pack("<8sIhHBB", b"_value", 8, 1, 0, 2, 0)
    header = struct.pack(
        "<HHIIIHH",
        matchlib.IMAGE_FILE_MACHINE_I386,
        1,
        0,
        symbol_table_offset,
        1,
        0,
        0,
    )
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".bss",
        0,
        0,
        16,
        0,
        0,
        0,
        0,
        0,
        matchlib.IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    )

    obj = matchlib.parse_coff_object(header + section + symbol + struct.pack("<I", 4))

    assert obj.sections[0].data == b""
    assert obj.sections[0].logical_size == 16
