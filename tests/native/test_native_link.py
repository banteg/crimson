from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from crimson import match as matchlib
from crimson.native_link import (
    DEFAULT_TRANSLATION_UNIT_CONFIGS,
    IMAGE_SCN_LNK_COMDAT,
    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    NativeCompilerBundleSnapshot,
    NativeFunctionBinding,
    NativeObjectRecord,
    NativeObjectSet,
    NativeSymbolCatalog,
    NativeToolchainSnapshot,
    _normalized_coff_sha256,
    _resolve_wibo_path,
    _select_unique_statuses,
    _validate_loaded_configs,
    _vc6_linker_internal_name,
    data_manifest_payload,
    load_native_data_definitions,
    load_native_translation_unit_config,
    object_manifest_payload,
    render_export_definition,
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
    ]
    assert [member.function for member in config.clusters[0].members] == [
        "grim_get_slot_float",
        "grim_get_slot_int",
        "grim_set_slot_float",
        "grim_set_slot_int",
    ]


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


def test_grim_data_manifest_applies_only_explicit_data_definitions() -> None:
    payload = data_manifest_payload("grim.dll")

    assert payload["summary"]["entry_count"] == 273
    assert payload["summary"]["typed_entries"] == 182
    assert payload["summary"]["explicit_size_entries"] == 8
    assert payload["summary"]["explicit_alignment_entries"] == 8
    assert payload["summary"]["explicit_initializer_entries"] == 8
    assert payload["summary"]["fully_specified_entries"] == 8
    assert payload["source"]["definitions"] == (
        "tools/native/data_definitions/grim.dll.json"
    )
    defined = {
        entry["name"]: entry
        for entry in payload["entries"]
        if entry["definition_state"] == "fully-specified"
    }
    assert defined["grim_d3d_device"]["size"] == 4
    assert defined["grim_d3d_device"]["initializer_hex"] == "00000000"
    assert defined["grim_render_disabled"]["size"] == 1
    assert defined["grim_render_disabled"]["initializer_hex"] == "00"
    assert next(
        entry
        for entry in payload["entries"]
        if entry["name"] == "grim_texture_slots"
    )["size"] is None


def test_crimsonland_data_manifest_applies_high_fan_in_definitions() -> None:
    payload = data_manifest_payload("crimsonland.exe")

    assert payload["summary"]["entry_count"] == 1547
    assert payload["summary"]["explicit_size_entries"] == 35
    assert payload["summary"]["explicit_alignment_entries"] == 35
    assert payload["summary"]["explicit_initializer_entries"] == 35
    assert payload["summary"]["fully_specified_entries"] == 35
    assert payload["source"]["definitions"] == (
        "tools/native/data_definitions/crimsonland.exe.json"
    )
    defined = {
        entry["name"]: entry
        for entry in payload["entries"]
        if entry["definition_state"] == "fully-specified"
    }
    assert defined["console_log_queue"]["size"] == 0x2C
    assert defined["grim_interface_ptr"]["size"] == 4
    assert defined["sfx_unmuted_flag"]["size"] == 1
    assert next(
        entry
        for entry in payload["entries"]
        if entry["name"] == "quest_unlock_index"
    )["size"] is None


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
