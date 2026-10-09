from __future__ import annotations

import json
import struct
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from crimson_re import match as matchlib
from crimson_re.match_toolchain import resolve_wibo_path
from crimson_re.native_link import (
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
    _select_unique_statuses,
    _validate_cluster_match,
    _validate_loaded_configs,
    _vc6_linker_internal_name,
    data_manifest_payload,
    load_native_data_definitions,
    load_native_provider_config,
    load_native_translation_unit_config,
    native_data_object_bytes,
    native_linker_alias_object_bytes,
    native_pe_imports,
    native_pe_summary,
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


@pytest.mark.parametrize("clustered_body_exact", [False, None])
def test_cluster_rejects_encoded_body_regression_at_equal_normalized_score(
    tmp_path: Path, clustered_body_exact: bool | None,
) -> None:
    baseline = replace(_status(tmp_path, "probe", 0x401000), body_byte_exact=True)
    clustered = replace(baseline, body_byte_exact=clustered_body_exact)
    with pytest.raises(ValueError, match="lost relocation-aware encoded-body identity"):
        _validate_cluster_match(baseline, clustered, translation_unit="probe-island")


def test_cluster_preserves_an_existing_encoding_residual(tmp_path: Path) -> None:
    baseline = replace(_status(tmp_path, "probe", 0x401000), body_byte_exact=False)
    _validate_cluster_match(baseline, baseline, translation_unit="probe-island")
    _validate_cluster_match(baseline, replace(baseline, body_byte_exact=True), translation_unit="probe-island")


RECOVERED_LAYOUTS = sorted((matchlib.REPO_ROOT / "decomp").glob("*/*/layout.json"))


@pytest.mark.parametrize(
    "layout_path",
    RECOVERED_LAYOUTS,
    ids=[path.parent.relative_to(matchlib.REPO_ROOT).as_posix() for path in RECOVERED_LAYOUTS],
)
def test_recovered_source_layout_preserves_evidence_boundaries(layout_path: Path) -> None:
    payload = json.loads(layout_path.read_text(encoding="utf-8"))
    image = payload["image"]
    root = (matchlib.REPO_ROOT / payload["root"]).resolve()
    translation_units = load_native_translation_unit_config(
        DEFAULT_TRANSLATION_UNIT_CONFIGS[image],
        image=image,
    )
    clusters = {cluster.name: cluster for cluster in translation_units.clusters}
    analysis = matchlib.REPO_ROOT / "analysis/ida/raw" / image
    functions = matchlib.load_function_manifest(
        analysis / "functions.json",
        metadata_path=analysis / "metadata.json",
        scope="all",
    ).by_name

    assert payload["schema"] == 1
    assert payload["kind"] == "crimson-recovered-source-layout"
    assert root == layout_path.parent.resolve()

    seen_sources: set[Path] = set()
    seen_configs: set[Path] = set()
    proven_clusters: set[str] = set()
    previous_end = 0
    for module in payload["modules"]:
        evidence = module["layout_evidence"]
        assert evidence in {"inferred-subsystem", "inferred-translation-unit"}
        # A translation-unit claim is a contiguous native code range.
        if evidence == "inferred-translation-unit":
            start, end = (int(bound, 16) for bound in module["range"])
            assert previous_end <= start < end
            previous_end = end
        for source_row in module["sources"]:
            source = (matchlib.REPO_ROOT / source_row["path"]).resolve()
            assert source.is_relative_to(root)
            assert source.is_file()
            assert source not in seen_sources
            seen_sources.add(source)

            members: list[str] = []
            for config_name in source_row["configs"]:
                config_dir = (matchlib.REPO_ROOT / config_name).resolve()
                assert config_dir not in seen_configs
                seen_configs.add(config_dir)
                config = matchlib.load_scratch_config(config_dir)
                assert config.image == image
                assert (config.directory / config.source).resolve() == source
                if evidence == "inferred-translation-unit":
                    function = functions[config.function]
                    assert start <= function.address < function.end <= end
                members.append(config.function)

            ownership = source_row["physical_ownership"]
            if ownership["kind"] == "native-translation-unit":
                cluster_name = ownership["cluster"]
                cluster = clusters[cluster_name]
                assert members == [
                    member.function for member in cluster.members
                ]
                proven_clusters.add(cluster_name)
            else:
                assert ownership == {"kind": "unproven-isolated-object"}
                assert len(members) == 1

    assert seen_sources == {
        path for path in root.glob("*/*") if path.suffix in {".c", ".cpp"}
    }
    object_manifest = json.loads(
        (
            matchlib.REPO_ROOT / "analysis/native" / image / "objects.json"
        ).read_text(encoding="utf-8"),
    )
    canonical_rows = [
        function
        for object_row in object_manifest["objects"]
        for function in object_row["functions"]
    ]
    assert canonical_rows
    assert {
        (matchlib.REPO_ROOT / row["canonical_source"]).resolve()
        for row in canonical_rows
    } <= seen_sources
    assert {
        (matchlib.REPO_ROOT / row["canonical_config"]).resolve().parent
        for row in canonical_rows
    } <= seen_configs
    assert proven_clusters == set(clusters)


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
        for alias in providers["msvcrt-strdup-link-dependency"].aliases
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
    assert "_D3DXVec2Normalize@8" not in symbols
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

    assert resolve_wibo_path(match_root) == path_wibo.resolve()


def test_normalized_coff_hash_ignores_only_header_timestamp() -> None:
    first = bytearray(20)
    struct.pack_into("<H", first, 0, matchlib.IMAGE_FILE_MACHINE_I386)
    struct.pack_into("<I", first, 4, 1)
    second = bytearray(first)
    struct.pack_into("<I", second, 4, 2)

    assert matchlib.coff_sha256(bytes(first)) == matchlib.coff_sha256(bytes(second))
    second[12] = 1
    assert matchlib.coff_sha256(bytes(first)) != matchlib.coff_sha256(bytes(second))


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


def test_coff_parser_rejects_relocation_past_section_end() -> None:
    data = bytearray(_build_auxiliary_coff(relocation_symbol_index=2))
    relocation_offset = struct.unpack_from("<I", data, 20 + 24)[0]
    struct.pack_into("<I", data, relocation_offset, 1)

    with pytest.raises(ValueError, match="exceeds section size"):
        matchlib.parse_coff_object(bytes(data))


@pytest.mark.parametrize("relocation_type", (0x01,))
def test_coff_parser_rejects_non_i386_relocation_type(relocation_type: int) -> None:
    data = bytearray(_build_auxiliary_coff(relocation_symbol_index=2))
    relocation_offset = struct.unpack_from("<I", data, 20 + 24)[0]
    struct.pack_into("<H", data, relocation_offset + 8, relocation_type)

    with pytest.raises(
        ValueError,
        match=f"unsupported i386 relocation type 0x{relocation_type:x}",
    ):
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
