from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import match as matchlib

NATIVE_OBJECT_MANIFEST_SCHEMA = 1
NATIVE_SYMBOL_CLOSURE_SCHEMA = 1
NATIVE_DATA_MANIFEST_SCHEMA = 1

NATIVE_OBJECT_MANIFEST_KIND = "crimson-native-object-manifest"
NATIVE_SYMBOL_CLOSURE_KIND = "crimson-native-symbol-closure"
NATIVE_DATA_MANIFEST_KIND = "crimson-native-data-manifest"

IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105
IMAGE_WEAK_EXTERN_SEARCH_ALIAS = 3

KNOWN_MSVC_TOOLCHAIN_EXTERNALS = frozenset(
    {
        "__except_list",
        "__fltused",
    },
)

DEFAULT_NATIVE_ANALYSIS_ROOT = matchlib.REPO_ROOT / "analysis" / "native"
DEFAULT_ABI_CONFIGS = {
    "grim.dll": matchlib.REPO_ROOT / "tools" / "native" / "abi" / "grim.dll",
}


@dataclass(frozen=True, slots=True)
class NativeObjectRecord:
    function: matchlib.FunctionSymbol
    status: matchlib.ScratchStatus
    object_path: Path
    object_symbol: str
    coff: matchlib.CoffObject
    compile_inputs: tuple[tuple[Path, str], ...] = ()
    config_sha256: str | None = None
    object_sha256: str | None = None
    source_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class NativeCompilerBundleSnapshot:
    compiler: str
    root: Path
    included_trees: tuple[str, ...]
    sha256: str


@dataclass(frozen=True, slots=True)
class NativeToolchainSnapshot:
    cl_wrapper: Path
    cl_wrapper_mode: int
    cl_wrapper_sha256: str
    compiler_bundles: tuple[NativeCompilerBundleSnapshot, ...]
    wibo: Path
    wibo_mode: int
    wibo_sha256: str


@dataclass(frozen=True, slots=True)
class NativeObjectSet:
    image: str
    scope: str
    manifest: matchlib.FunctionManifest
    image_path: Path
    records: tuple[NativeObjectRecord, ...]
    abi_object_path: Path | None = None
    abi_config: matchlib.ScratchConfig | None = None
    abi_compile_inputs: tuple[tuple[Path, str], ...] = ()
    abi_object_sha256: str | None = None
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT
    toolchain: NativeToolchainSnapshot | None = None


@dataclass(frozen=True, slots=True)
class NativeSymbolCatalog:
    port_functions: dict[str, tuple[dict[str, Any], ...]]
    excluded_functions: dict[str, tuple[dict[str, Any], ...]]
    data: dict[str, tuple[dict[str, Any], ...]]
    imports: dict[str, tuple[dict[str, Any], ...]]
    exports: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class NativeAudit:
    objects: NativeObjectSet
    object_manifest: dict[str, Any]
    symbol_closure: dict[str, Any]
    data_manifest: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NativeAuditArtifacts:
    object_manifest: Path
    object_list: Path
    export_definition: Path
    symbol_closure: Path
    data_manifest: Path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalized_coff_sha256(data: bytes) -> str:
    if len(data) < 20:
        raise ValueError("truncated COFF object while hashing")
    machine = struct.unpack_from("<H", data, 0)[0]
    if machine != matchlib.IMAGE_FILE_MACHINE_I386:
        raise ValueError(f"expected i386 COFF object while hashing, got machine 0x{machine:x}")
    normalized = bytearray(data)
    normalized[4:8] = b"\x00\x00\x00\x00"
    return hashlib.sha256(normalized).hexdigest()


def _path_label(path: Path, *, repo_root: Path) -> tuple[str, bool]:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix(), True
    except ValueError:
        return path.name, False


def _file_payload(path: Path, *, repo_root: Path) -> dict[str, Any]:
    label, repository_relative = _path_label(path, repo_root=repo_root)
    return {
        "path": label,
        "repository_relative": repository_relative,
        "sha256": _sha256(path),
    }


def _snapshotted_file_payload(
    path: Path,
    sha256: str,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    label, repository_relative = _path_label(path, repo_root=repo_root)
    return {
        "path": label,
        "repository_relative": repository_relative,
        "sha256": sha256,
    }


def _tree_set_sha256(root: Path, trees: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    files: list[Path] = []
    for tree_name in trees:
        tree = root / tree_name
        if not tree.is_dir():
            raise ValueError(f"compiler bundle is missing {tree}")
        files.extend(candidate for candidate in tree.rglob("*") if candidate.is_file())
    for path in sorted(files):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        contents = path.read_bytes()
        digest.update(len(contents).to_bytes(8, "little"))
        digest.update(contents)
    return digest.hexdigest()


def _resolve_wibo_path(match_root: Path) -> Path:
    configured = os.environ.get("WIBO")
    if configured:
        candidate = Path(configured)
        if candidate.is_absolute() or candidate.parent != Path("."):
            resolved = candidate.resolve()
            if resolved.is_file() and os.access(resolved, os.X_OK):
                return resolved
            raise ValueError(f"WIBO={configured!r} is not executable")
        if resolved := shutil.which(configured):
            return Path(resolved).resolve()
        raise ValueError(f"WIBO={configured!r} cannot be resolved")
    repository_wibo = match_root / "bin" / "wibo"
    if repository_wibo.is_file() and os.access(repository_wibo, os.X_OK):
        return repository_wibo.resolve()
    if resolved := shutil.which("wibo"):
        return Path(resolved).resolve()
    raise ValueError("wibo cannot be resolved")


def _compile_input_snapshot(
    config: matchlib.ScratchConfig,
    match_root: Path,
) -> tuple[tuple[Path, str], ...]:
    return tuple(
        (path.resolve(), _sha256(path))
        for path in matchlib._scratch_build_dependencies(config, match_root)
    )


def _compile_input_union_snapshot(
    configs: tuple[matchlib.ScratchConfig, ...],
    match_root: Path,
) -> tuple[tuple[Path, str], ...]:
    paths = {
        path.resolve()
        for config in configs
        for path in matchlib._scratch_build_dependencies(config, match_root)
    }
    return tuple((path, _sha256(path)) for path in sorted(paths))


def _validate_loaded_configs(
    configs: tuple[matchlib.ScratchConfig, ...],
) -> None:
    for expected in configs:
        current = matchlib.load_scratch_config(expected.directory)
        if current != expected:
            raise ValueError(
                f"{expected.directory.name}: scratch.conf changed after canonical selection",
            )


def _capture_toolchain_snapshot(
    configs: tuple[matchlib.ScratchConfig, ...],
    match_root: Path,
) -> NativeToolchainSnapshot:
    compiler_bundles: list[NativeCompilerBundleSnapshot] = []
    configs_by_compiler = {config.compiler: config for config in configs}
    included_trees = ("Bin", "Include")
    for compiler, config in sorted(configs_by_compiler.items()):
        executable = matchlib._compiler_executable_path(config, match_root).resolve()
        compiler_root = executable.parent.parent
        compiler_bundles.append(
            NativeCompilerBundleSnapshot(
                compiler=compiler,
                root=compiler_root,
                included_trees=included_trees,
                sha256=_tree_set_sha256(compiler_root, included_trees),
            ),
        )
    cl_wrapper = (match_root / "cl.sh").resolve()
    wibo = _resolve_wibo_path(match_root)
    return NativeToolchainSnapshot(
        cl_wrapper=cl_wrapper,
        cl_wrapper_mode=cl_wrapper.stat().st_mode & 0o7777,
        cl_wrapper_sha256=_sha256(cl_wrapper),
        compiler_bundles=tuple(compiler_bundles),
        wibo=wibo,
        wibo_mode=wibo.stat().st_mode & 0o7777,
        wibo_sha256=_sha256(wibo),
    )


def _toolchain_payload(
    objects: NativeObjectSet,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    configs = tuple(record.status.config for record in objects.records)
    if objects.abi_config is not None:
        configs = (*configs, objects.abi_config)
    snapshot = objects.toolchain or _capture_toolchain_snapshot(configs, objects.match_root)
    compiler_rows = [
        {
            "bundle_sha256": bundle.sha256,
            "compiler": bundle.compiler,
            "included_trees": list(bundle.included_trees),
            "root": _path_label(bundle.root, repo_root=repo_root)[0],
        }
        for bundle in snapshot.compiler_bundles
    ]
    cl_wrapper = _snapshotted_file_payload(
        snapshot.cl_wrapper,
        snapshot.cl_wrapper_sha256,
        repo_root=repo_root,
    )
    cl_wrapper["mode"] = snapshot.cl_wrapper_mode
    wibo = _snapshotted_file_payload(
        snapshot.wibo,
        snapshot.wibo_sha256,
        repo_root=repo_root,
    )
    wibo["mode"] = snapshot.wibo_mode
    return {
        "cl_wrapper": cl_wrapper,
        "compiler_bundles": compiler_rows,
        "wibo": wibo,
    }


def _repo_relative(path: Path, *, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"{path} is outside repository root {repo_root}") from exc


def _image_paths(image: str) -> tuple[Path, Path, Path]:
    return (
        matchlib.default_image_path(image),
        matchlib.default_functions_path(image),
        matchlib.default_metadata_path(image),
    )


def _analysis_input_snapshot(
    image: str,
    scope: str,
) -> tuple[tuple[Path, str], ...]:
    image_path, functions_path, metadata_path = _image_paths(image)
    paths = [
        image_path,
        functions_path,
        metadata_path,
        functions_path.with_name("imports.json"),
        functions_path.with_name("segments.json"),
        matchlib.DEFAULT_DATA_MAP_PATH,
        matchlib.DEFAULT_NAME_MAP_PATH,
    ]
    if scope != "all":
        paths.append(matchlib.DEFAULT_MATCHING_SCOPE_PATH)
    return tuple((path.resolve(), _sha256(path)) for path in paths)


def _discover_image_scratch_directories(image: str, match_root: Path) -> tuple[Path, ...]:
    directories: list[Path] = []
    for config_path in sorted(match_root.resolve().glob("scratches/*/scratch.conf")):
        config = matchlib.load_scratch_config(config_path.parent)
        if config.image == image:
            directories.append(config.directory)
    return tuple(directories)


def _select_unique_statuses(
    statuses: list[matchlib.ScratchStatus],
    manifest: matchlib.FunctionManifest,
    *,
    native_manifest: matchlib.FunctionManifest | None = None,
) -> tuple[matchlib.ScratchStatus, ...]:
    by_address: dict[int, list[matchlib.ScratchStatus]] = defaultdict(list)
    for status in statuses:
        by_address[status.address].append(status)

    manifest_addresses = {function.address for function in manifest.functions}
    missing = [
        function
        for function in manifest.functions
        if function.address not in by_address
    ]
    duplicates = {
        address: rows
        for address, rows in by_address.items()
        if address in manifest_addresses and len(rows) != 1
    }
    extras = {
        address: rows
        for address, rows in by_address.items()
        if address not in manifest_addresses
    }
    errors = [status for status in statuses if status.state == "error"]

    problems: list[str] = []
    if missing:
        names = ", ".join(function.name for function in missing[:8])
        suffix = "" if len(missing) <= 8 else ", ..."
        problems.append(f"missing canonical scratches: {names}{suffix}")
    for address, rows in sorted(duplicates.items()):
        scratches = ", ".join(sorted(row.config.directory.name for row in rows))
        problems.append(f"duplicate canonical target 0x{address:08x}: {scratches}")
    for address, rows in sorted(extras.items()):
        scratches = ", ".join(sorted(row.config.directory.name for row in rows))
        problems.append(f"scratch target outside manifest 0x{address:08x}: {scratches}")
    for status in errors[:8]:
        problems.append(f"{status.config.directory.name}: {status.error or 'evaluation failed'}")
    if len(errors) > 8:
        problems.append(f"... and {len(errors) - 8} more evaluation errors")
    native_manifest = native_manifest or manifest
    native_starts = tuple(function.address for function in native_manifest.functions)
    next_native_start = {
        address: native_starts[index + 1] if index + 1 < len(native_starts) else None
        for index, address in enumerate(native_starts)
    }
    for function in manifest.functions:
        rows = by_address.get(function.address, [])
        if len(rows) != 1:
            continue
        status = rows[0]
        if status.config.function != function.name:
            problems.append(
                f"{status.config.directory.name}: FUNCTION={status.config.function!r} "
                f"must use canonical name {function.name!r}",
            )
        effective_end = (
            status.config.end_va
            if status.config.end_va is not None
            else function.end
        )
        next_start = next_native_start.get(function.address)
        if effective_end <= function.address:
            problems.append(
                f"{status.config.directory.name}: invalid effective extent "
                f"0x{function.address:08x}..0x{effective_end:08x}",
            )
        elif next_start is not None and effective_end > next_start:
            problems.append(
                f"{status.config.directory.name}: effective end 0x{effective_end:08x} "
                f"overlaps next function at 0x{next_start:08x}",
            )
    if problems:
        raise ValueError("; ".join(problems))

    return tuple(by_address[function.address][0] for function in manifest.functions)


def build_native_object_set(
    image: str,
    *,
    scope: str = matchlib.DEFAULT_MATCH_SCOPE,
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT,
    jobs: int = matchlib.DEFAULT_MATCH_JOBS,
    abi_configs: dict[str, Path] | None = None,
) -> NativeObjectSet:
    """Compile exactly one canonical scratch object for each scoped function."""

    if image not in matchlib.matching_scope_images(scope):
        supported = ", ".join(sorted(matchlib.matching_scope_images(scope)))
        raise ValueError(f"image {image!r} is not tracked by scope {scope!r}; use one of: {supported}")

    workspace_errors = matchlib.validate_matching_workspace(match_root, scope=scope)
    if workspace_errors:
        raise ValueError("; ".join(workspace_errors))

    image_path, functions_path, metadata_path = _image_paths(image)
    manifest = matchlib.load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image,
        scope=scope,
    )
    native_manifest = matchlib.load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image,
        scope="all",
    )
    directories = _discover_image_scratch_directories(image, match_root)
    statuses = matchlib.collect_scratch_statuses(
        match_root,
        jobs=jobs,
        scope=scope,
        directories=directories,
    )
    selected = _select_unique_statuses(
        statuses,
        manifest,
        native_manifest=native_manifest,
    )

    resolved_abi_configs = DEFAULT_ABI_CONFIGS if abi_configs is None else abi_configs
    abi_directory = resolved_abi_configs.get(image)
    abi_config = (
        matchlib.load_scratch_config(abi_directory)
        if abi_directory is not None
        else None
    )
    if abi_config is not None and abi_config.image != image:
        raise ValueError(
            f"{abi_directory}/scratch.conf targets {abi_config.image}, expected {image}",
        )
    toolchain_configs = tuple(status.config for status in selected)
    if abi_config is not None:
        toolchain_configs = (*toolchain_configs, abi_config)
    compile_inputs_before = _compile_input_union_snapshot(
        toolchain_configs,
        match_root,
    )
    _validate_loaded_configs(toolchain_configs)
    if compile_inputs_before != _compile_input_union_snapshot(
        toolchain_configs,
        match_root,
    ):
        raise ValueError("compile inputs changed while binding canonical configs")
    toolchain_before = _capture_toolchain_snapshot(toolchain_configs, match_root)

    records: list[NativeObjectRecord] = []
    for function, status in zip(manifest.functions, selected, strict=True):
        inputs_before = _compile_input_snapshot(status.config, match_root)
        object_path = matchlib.compile_scratch(status.config, match_root, force=True)
        object_data = object_path.read_bytes()
        result = matchlib.run_match(
            obj_path=object_path,
            function=status.config.function,
            image_path=image_path,
            functions_path=functions_path,
            metadata_path=metadata_path,
            symbol_name=status.config.symbol,
            end_va=status.config.end_va,
            reference_aliases=status.config.reference_aliases,
            scope=scope,
        )
        if object_path.read_bytes() != object_data:
            raise ValueError(
                f"{status.config.directory.name}: object changed during native audit",
            )
        refreshed_status = replace(
            status,
            ratio=result.ratio,
            prefix_instructions=result.prefix_instructions,
            target_instructions=len(result.target_lines),
            candidate_instructions=len(result.candidate_lines),
            error=None,
            masked_ok=result.masked_operand_audit.ok_count,
            masked_unresolved=result.masked_operand_audit.unresolved_count,
            masked_mismatches=result.masked_operand_audit.mismatch_count,
            audit=result.masked_operand_audit,
            first_target_mismatch_offset=(
                result.target_disassembly[result.prefix_instructions].offset
                if result.prefix_instructions < len(result.target_disassembly)
                else None
            ),
            first_candidate_mismatch_offset=(
                result.candidate_disassembly[result.prefix_instructions].offset
                if result.prefix_instructions < len(result.candidate_disassembly)
                else None
            ),
        )
        inputs_after = _compile_input_snapshot(status.config, match_root)
        if inputs_before != inputs_after:
            raise ValueError(
                f"{status.config.directory.name}: compile inputs changed during native audit",
            )
        coff = matchlib.parse_coff_object(object_data)
        object_function = matchlib.extract_object_function(coff, status.config.symbol)
        input_hashes = dict(inputs_after)
        config_path = (status.config.directory / "scratch.conf").resolve()
        source_path = (status.config.directory / status.config.source).resolve()
        records.append(
            NativeObjectRecord(
                function=function,
                status=refreshed_status,
                object_path=object_path,
                object_symbol=object_function.name,
                coff=coff,
                compile_inputs=inputs_after,
                config_sha256=input_hashes[config_path],
                object_sha256=_normalized_coff_sha256(object_data),
                source_sha256=input_hashes[source_path],
            ),
        )

    abi_object_path: Path | None = None
    abi_compile_inputs: tuple[tuple[Path, str], ...] = ()
    abi_object_sha256: str | None = None
    if abi_config is not None:
        abi_inputs_before = _compile_input_snapshot(abi_config, match_root)
        abi_object_path = matchlib.compile_scratch(abi_config, match_root, force=True)
        abi_data = abi_object_path.read_bytes()
        abi_compile_inputs = _compile_input_snapshot(abi_config, match_root)
        if abi_inputs_before != abi_compile_inputs:
            raise ValueError(
                f"{abi_config.directory.name}: compile inputs changed during native audit",
            )
        matchlib.parse_coff_object(abi_data)
        abi_object_sha256 = _normalized_coff_sha256(abi_data)

    compile_inputs_after = _compile_input_union_snapshot(
        toolchain_configs,
        match_root,
    )
    if compile_inputs_before != compile_inputs_after:
        raise ValueError("compile inputs changed across native object-set build")
    toolchain_after = _capture_toolchain_snapshot(toolchain_configs, match_root)
    if toolchain_before != toolchain_after:
        raise ValueError("compiler toolchain changed during native audit")

    return NativeObjectSet(
        image=image,
        scope=scope,
        manifest=manifest,
        image_path=image_path,
        records=tuple(records),
        abi_object_path=abi_object_path,
        abi_config=abi_config,
        abi_compile_inputs=abi_compile_inputs,
        abi_object_sha256=abi_object_sha256,
        match_root=match_root.resolve(),
        toolchain=toolchain_after,
    )


def object_manifest_payload(
    objects: NativeObjectSet,
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> dict[str, Any]:
    state_counts = Counter(record.status.state for record in objects.records)
    records: list[dict[str, Any]] = []
    for record in objects.records:
        config = record.status.config
        source_path = config.directory / config.source
        config_path = config.directory / "scratch.conf"
        records.append(
            {
                "address": record.function.address,
                "cflags": shlex.split(config.cflags),
                "compile_argv": [
                    "/nologo",
                    "/c",
                    *shlex.split(config.cflags),
                    Path(config.source).name,
                ],
                "compile_inputs": [
                    _snapshotted_file_payload(path, sha256, repo_root=repo_root)
                    for path, sha256 in record.compile_inputs
                ],
                "compiler": config.compiler,
                "config": _repo_relative(config_path, repo_root=repo_root),
                "config_sha256": record.config_sha256 or _sha256(config_path),
                "end": record.function.end,
                "effective_end": (
                    config.end_va
                    if config.end_va is not None
                    else record.function.end
                ),
                "function": record.function.name,
                "match": {
                    "candidate_instructions": record.status.candidate_instructions,
                    "masked_mismatches": record.status.masked_mismatches,
                    "masked_ok": record.status.masked_ok,
                    "masked_unresolved": record.status.masked_unresolved,
                    "prefix_instructions": record.status.prefix_instructions,
                    "ratio": record.status.ratio,
                    "state": record.status.state,
                    "target_instructions": record.status.target_instructions,
                },
                "object": _repo_relative(record.object_path, repo_root=repo_root),
                "object_function_symbol": record.object_symbol,
                "object_sha256": (
                    record.object_sha256
                    or _normalized_coff_sha256(record.object_path.read_bytes())
                ),
                "scratch": _repo_relative(config.directory, repo_root=repo_root),
                "source": _repo_relative(source_path, repo_root=repo_root),
                "source_sha256": record.source_sha256 or _sha256(source_path),
                "target_size": record.function.size,
            },
        )

    abi: dict[str, Any] | None = None
    if objects.abi_object_path is not None:
        if objects.abi_config is None:
            raise ValueError("ABI object is missing its source configuration")
        abi_source = objects.abi_config.directory / objects.abi_config.source
        abi_config_path = objects.abi_config.directory / "scratch.conf"
        abi_input_hashes = dict(objects.abi_compile_inputs)
        abi_config_sha256 = abi_input_hashes.get(abi_config_path.resolve())
        if abi_config_sha256 is None:
            abi_config_sha256 = _sha256(abi_config_path)
        abi_source_sha256 = abi_input_hashes.get(abi_source.resolve())
        if abi_source_sha256 is None:
            abi_source_sha256 = _sha256(abi_source)
        abi = {
            "compile_argv": [
                "/nologo",
                "/c",
                *shlex.split(objects.abi_config.cflags),
                Path(objects.abi_config.source).name,
            ],
            "compile_inputs": [
                _snapshotted_file_payload(path, sha256, repo_root=repo_root)
                for path, sha256 in objects.abi_compile_inputs
            ],
            "config": _repo_relative(abi_config_path, repo_root=repo_root),
            "config_sha256": abi_config_sha256,
            "object": _repo_relative(objects.abi_object_path, repo_root=repo_root),
            "object_sha256": (
                objects.abi_object_sha256
                or _normalized_coff_sha256(objects.abi_object_path.read_bytes())
            ),
            "source": _repo_relative(abi_source, repo_root=repo_root),
            "source_sha256": abi_source_sha256,
            "status": "passed",
        }

    _, functions_path, metadata_path = _image_paths(objects.image)
    selection_input_paths = [
        functions_path,
        metadata_path,
        matchlib.DEFAULT_NAME_MAP_PATH,
    ]
    if objects.scope != "all":
        selection_input_paths.append(matchlib.DEFAULT_MATCHING_SCOPE_PATH)

    return {
        "abi_assertions": abi,
        "image": objects.image,
        "kind": NATIVE_OBJECT_MANIFEST_KIND,
        "object_count": len(records),
        "object_order": "ascending-reference-address",
        "object_hash": {
            "algorithm": "sha256",
            "normalization": ["zero COFF TimeDateStamp bytes 4..7"],
        },
        "objects": records,
        "provenance": {
            "build_policy": "forced-isolated-recompile",
            "selection_inputs": [
                _file_payload(path, repo_root=repo_root)
                for path in selection_input_paths
            ],
            "toolchain": _toolchain_payload(objects, repo_root=repo_root),
        },
        "reference_image": _repo_relative(objects.image_path, repo_root=repo_root),
        "reference_image_sha256": _sha256(objects.image_path),
        "schema": NATIVE_OBJECT_MANIFEST_SCHEMA,
        "scope": objects.scope,
        "selection": {
            "duplicate_policy": "error",
            "extent_policy": "start < effective_end <= next native start",
            "function_name_policy": "exact canonical manifest name",
            "key": ["image", "resolved_address"],
            "missing_policy": "error",
            "source": "active scratch.conf files",
        },
        "states": dict(sorted(state_counts.items())),
    }


def render_object_list(
    objects: NativeObjectSet,
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> str:
    lines = [
        _repo_relative(record.object_path, repo_root=repo_root)
        for record in objects.records
    ]
    return "".join(f"{line}\n" for line in lines)


def render_export_definition(
    image: str,
    symbol_closure: dict[str, Any],
) -> str:
    lines = [f"LIBRARY {image}", "EXPORTS"]
    for export in symbol_closure["exports"]:
        mapping = export["definition_mapping"]
        if mapping is None:
            lines.append(
                f"    ; unresolved reference export {export['name']} @{export['ordinal']}",
            )
            continue
        lines.append(
            f"    {mapping['external_name']}={mapping['linker_internal_name']} "
            f"@{mapping['ordinal']}",
        )
    return "".join(f"{line}\n" for line in lines)


def _vc6_linker_internal_name(coff_symbol: str) -> str:
    # VC6 LINK decorates C identifiers named in a .def file. Remove exactly
    # the COFF-added cdecl/stdcall prefix while retaining any @N suffix.
    return coff_symbol.removeprefix("_")


def _add_catalog_name(
    catalog: dict[str, list[dict[str, Any]]],
    name: str,
    detail: dict[str, Any],
) -> None:
    lookup_name = matchlib._symbol_lookup_name(name)
    if not lookup_name:
        return
    rows = catalog.setdefault(lookup_name, [])
    if detail not in rows:
        rows.append(detail)


def _freeze_catalog(
    catalog: dict[str, list[dict[str, Any]]],
) -> dict[str, tuple[dict[str, Any], ...]]:
    return {
        name: tuple(sorted(rows, key=lambda row: json.dumps(row, sort_keys=True)))
        for name, rows in sorted(catalog.items())
    }


def _load_pe_exports(image_path: Path) -> tuple[dict[str, Any], ...]:
    import pefile

    pe = pefile.PE(str(image_path), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]],
        )
        export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_directory is None:
            return ()
        exports: list[dict[str, Any]] = []
        for symbol in export_directory.symbols:
            raw_name = symbol.name
            name = (
                raw_name.decode("latin1")
                if isinstance(raw_name, bytes)
                else f"ordinal_{int(symbol.ordinal)}"
            )
            exports.append(
                {
                    "address": int(pe.OPTIONAL_HEADER.ImageBase) + int(symbol.address),
                    "name": name,
                    "noname": raw_name is None,
                    "ordinal": int(symbol.ordinal),
                },
            )
        return tuple(sorted(exports, key=lambda row: (row["ordinal"], row["name"])))
    finally:
        pe.close()


def load_native_symbol_catalog(
    image: str,
    *,
    scope: str = matchlib.DEFAULT_MATCH_SCOPE,
    data_map_path: Path = matchlib.DEFAULT_DATA_MAP_PATH,
    name_map_path: Path = matchlib.DEFAULT_NAME_MAP_PATH,
) -> NativeSymbolCatalog:
    image_path, functions_path, metadata_path = _image_paths(image)
    port_manifest = matchlib.load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image,
        scope=scope,
    )
    all_manifest = matchlib.load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image,
        scope="all",
    )
    port_addresses = {function.address for function in port_manifest.functions}
    disposition_by_address = {
        row.address: row.disposition
        for row in matchlib.load_matching_scope_function_dispositions(scope).get(image, ())
    }

    aliases_by_address: dict[int, list[str]] = defaultdict(list)
    if name_map_path.exists():
        for row in json.loads(name_map_path.read_text(encoding="utf-8")):
            if row.get("program") != image:
                continue
            address = matchlib.parse_int(row["address"])
            aliases_by_address[address].extend(
                [str(row["name"]), *(str(alias) for alias in row.get("aliases", []))],
            )

    port_functions: dict[str, list[dict[str, Any]]] = {}
    excluded_functions: dict[str, list[dict[str, Any]]] = {}
    for function in all_manifest.functions:
        detail: dict[str, Any] = {
            "address": function.address,
            "function": function.name,
        }
        target = port_functions if function.address in port_addresses else excluded_functions
        if function.address not in port_addresses:
            detail["disposition"] = disposition_by_address.get(
                function.address,
                "outside-port-scope",
            )
        names = [function.name, *aliases_by_address.get(function.address, [])]
        for name in names:
            _add_catalog_name(target, name, detail)

    data: dict[str, list[dict[str, Any]]] = {}
    if data_map_path.exists():
        payload = json.loads(data_map_path.read_text(encoding="utf-8"))
        for row in payload.get("entries", []):
            if row.get("program") != image:
                continue
            detail = {
                "address": matchlib.parse_int(row["address"]),
                "name": str(row["name"]),
            }
            for name in [str(row["name"]), *(str(alias) for alias in row.get("aliases", []))]:
                _add_catalog_name(data, name, detail)

    imports: dict[str, list[dict[str, Any]]] = {}
    imports_path = functions_path.with_name("imports.json")
    if imports_path.exists():
        for module in json.loads(imports_path.read_text(encoding="utf-8")):
            module_name = str(module.get("module") or "")
            for row in module.get("entries", []):
                name = str(row.get("name") or "")
                if not name:
                    continue
                _add_catalog_name(
                    imports,
                    name,
                    {
                        "address": matchlib.parse_int(row["address"]),
                        "module": module_name,
                        "name": name,
                    },
                )

    return NativeSymbolCatalog(
        port_functions=_freeze_catalog(port_functions),
        excluded_functions=_freeze_catalog(excluded_functions),
        data=_freeze_catalog(data),
        imports=_freeze_catalog(imports),
        exports=_load_pe_exports(image_path),
    )


def _symbol_occurrence(
    record: NativeObjectRecord,
    symbol: matchlib.CoffSymbol,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    section: matchlib.CoffSection | None = None
    if 0 < symbol.section_number <= len(record.coff.sections):
        section = record.coff.sections[symbol.section_number - 1]
    kind = "common" if symbol.section_number == 0 and symbol.value > 0 else "section"
    return {
        "comdat": bool(section and section.characteristics & IMAGE_SCN_LNK_COMDAT),
        "comdat_associative_section": (
            section.comdat_associative_section
            if section is not None
            else None
        ),
        "comdat_key": section.comdat_key if section is not None else None,
        "comdat_selection": section.comdat_selection if section is not None else None,
        "function": record.function.name,
        "kind": kind,
        "logical_section_size": section.logical_size if section is not None else None,
        "object": _repo_relative(record.object_path, repo_root=repo_root),
        "section": section.name if section is not None else None,
        "size": symbol.value if kind == "common" else None,
        "weak": symbol.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    }


def _coff_directives(record: NativeObjectRecord) -> tuple[str, ...]:
    directives: list[str] = []
    for section in record.coff.sections:
        if section.name != ".drectve":
            continue
        directives.extend(shlex.split(section.data.decode("latin1", errors="replace")))
    return tuple(directives)


def symbol_closure_payload(
    objects: NativeObjectSet,
    *,
    catalog: NativeSymbolCatalog | None = None,
    repo_root: Path = matchlib.REPO_ROOT,
) -> dict[str, Any]:
    catalog_supplied = catalog is not None
    catalog = catalog or load_native_symbol_catalog(objects.image, scope=objects.scope)
    definitions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    undefined: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pending_undefined: list[tuple[str, str | None, dict[str, Any]]] = []
    directives_by_object: dict[str, tuple[str, ...]] = {}

    for record in objects.records:
        object_name = _repo_relative(record.object_path, repo_root=repo_root)
        directives_by_object[object_name] = _coff_directives(record)
        symbols_by_raw_index = {symbol.raw_index: symbol for symbol in record.coff.symbols}
        for symbol in record.coff.symbols:
            if symbol.storage_class not in (
                matchlib.IMAGE_SYM_CLASS_EXTERNAL,
                IMAGE_SYM_CLASS_WEAK_EXTERNAL,
            ):
                continue
            occurrence = _symbol_occurrence(record, symbol, repo_root=repo_root)
            if symbol.section_number > 0 or (symbol.section_number == 0 and symbol.value > 0):
                definitions[symbol.name].append(occurrence)
            elif symbol.section_number == 0:
                alias_fallback: str | None = None
                reference: dict[str, Any] = {
                    "function": record.function.name,
                    "object": object_name,
                    "weak": symbol.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                }
                if (
                    symbol.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL
                    and symbol.weak_default_symbol_index is not None
                ):
                    fallback = symbols_by_raw_index[symbol.weak_default_symbol_index]
                    reference["weak_fallback"] = fallback.name
                    reference["weak_search"] = symbol.weak_search
                    if symbol.weak_search == IMAGE_WEAK_EXTERN_SEARCH_ALIAS:
                        alias_fallback = fallback.name
                pending_undefined.append((symbol.name, alias_fallback, reference))

    for primary_name, alias_fallback, reference in pending_undefined:
        reference_name = primary_name
        if primary_name not in definitions and alias_fallback is not None:
            reference["weak_alias"] = primary_name
            reference_name = alias_fallback
        undefined[reference_name].append(reference)

    definition_rows: list[dict[str, Any]] = []
    duplicate_rows: list[dict[str, Any]] = []
    coalescible_rows: list[dict[str, Any]] = []
    for name, occurrences in sorted(definitions.items()):
        ordered = sorted(occurrences, key=lambda row: (row["object"], row["function"]))
        row = {"definitions": ordered, "name": name}
        definition_rows.append(row)
        if len(ordered) > 1:
            common = all(occurrence["kind"] == "common" for occurrence in ordered)
            select_any = all(
                occurrence["kind"] == "section"
                and occurrence["comdat"]
                and occurrence["comdat_selection"] == 2
                and occurrence["comdat_key"] == name
                for occurrence in ordered
            )
            if common or select_any:
                coalescible_rows.append(row)
            else:
                duplicate_rows.append(row)

    definitions_by_lookup: dict[str, list[str]] = defaultdict(list)
    for name in definitions:
        definitions_by_lookup[matchlib._symbol_lookup_name(name)].append(name)

    resolved_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    unresolved_counts: Counter[str] = Counter()
    for name, references in sorted(undefined.items()):
        ordered_references = sorted(
            references,
            key=lambda row: (row["object"], row["function"]),
        )
        if name in definitions:
            resolved_rows.append(
                {
                    "definitions": sorted(
                        definitions[name],
                        key=lambda row: (row["object"], row["function"]),
                    ),
                    "name": name,
                    "referenced_by": ordered_references,
                },
            )
            continue

        lookup_name = matchlib._symbol_lookup_name(name)
        detail: tuple[dict[str, Any], ...] = ()
        if lookup_name in catalog.port_functions:
            category = "game_function"
            detail = catalog.port_functions[lookup_name]
        elif lookup_name in catalog.excluded_functions:
            category = "excluded_function"
            detail = catalog.excluded_functions[lookup_name]
        elif lookup_name in catalog.data:
            category = "game_data"
            detail = catalog.data[lookup_name]
        elif lookup_name in catalog.imports:
            category = "import"
            detail = catalog.imports[lookup_name]
        elif name in KNOWN_MSVC_TOOLCHAIN_EXTERNALS:
            category = "toolchain"
        else:
            category = "external"
        unresolved_counts[category] += 1
        unresolved_rows.append(
            {
                "candidate_definitions": sorted(definitions_by_lookup.get(lookup_name, [])),
                "catalog": list(detail),
                "category": category,
                "lookup_name": lookup_name,
                "name": name,
                "referenced_by": ordered_references,
            },
        )

    default_libraries: dict[str, set[str]] = defaultdict(set)
    directive_rows: list[dict[str, Any]] = []
    for object_name, directives in sorted(directives_by_object.items()):
        if directives:
            directive_rows.append({"directives": list(directives), "object": object_name})
        for directive in directives:
            if match := re.match(r"(?i)^[-/]defaultlib:(.+)$", directive):
                default_libraries[match.group(1)].add(object_name)
    default_library_rows = [
        {
            "name": name,
            "object_count": len(object_names),
            "objects": sorted(object_names),
        }
        for name, object_names in sorted(default_libraries.items(), key=lambda item: item[0].lower())
    ]

    export_rows: list[dict[str, Any]] = []
    for export in catalog.exports:
        lookup_name = matchlib._symbol_lookup_name(str(export["name"]))
        candidate_definitions = sorted(definitions_by_lookup.get(lookup_name, []))
        mapping = (
            {
                "external_name": export["name"],
                "internal_symbol": candidate_definitions[0],
                "linker_internal_name": _vc6_linker_internal_name(
                    candidate_definitions[0],
                ),
                "ordinal": export["ordinal"],
            }
            if len(candidate_definitions) == 1 and not export.get("noname")
            else None
        )
        export_rows.append(
            {
                **export,
                "candidate_definition_available": bool(candidate_definitions),
                "candidate_definitions": candidate_definitions,
                "definition_mapping": mapping,
            },
        )

    reference_imports = sorted(
        (
            detail
            for details in catalog.imports.values()
            for detail in details
        ),
        key=lambda row: (str(row["module"]).lower(), str(row["name"]), int(row["address"])),
    )
    unresolved_game_functions = unresolved_counts["game_function"]
    unresolved_game_data = unresolved_counts["game_data"]
    unresolved_external = unresolved_counts["external"]
    hard_duplicates = len(duplicate_rows)
    reference_exports_closed = all(
        export["definition_mapping"] is not None
        for export in export_rows
    )

    source: dict[str, Any] | None = None
    if not catalog_supplied:
        image_path, functions_path, metadata_path = _image_paths(objects.image)
        input_paths = [
            image_path,
            functions_path,
            metadata_path,
            functions_path.with_name("imports.json"),
            matchlib.DEFAULT_DATA_MAP_PATH,
            matchlib.DEFAULT_NAME_MAP_PATH,
        ]
        if objects.scope != "all":
            input_paths.append(matchlib.DEFAULT_MATCHING_SCOPE_PATH)
        source = {
            "catalog_inputs": [
                _file_payload(path, repo_root=repo_root)
                for path in input_paths
            ],
        }

    return {
        "coalescible_definitions": coalescible_rows,
        "default_libraries": default_library_rows,
        "definitions": definition_rows,
        "directives": directive_rows,
        "duplicate_definitions": duplicate_rows,
        "exports": export_rows,
        "image": objects.image,
        "kind": NATIVE_SYMBOL_CLOSURE_KIND,
        "reference_imports": reference_imports,
        "resolved": resolved_rows,
        "schema": NATIVE_SYMBOL_CLOSURE_SCHEMA,
        "scope": objects.scope,
        "source": source,
        "summary": {
            "coalescible_definition_symbols": len(coalescible_rows),
            "defined_symbols": len(definition_rows),
            "all_references_closed": (
                len(unresolved_rows) == 0
                and hard_duplicates == 0
                and reference_exports_closed
            ),
            "function_closure": (
                unresolved_game_functions == 0
                and hard_duplicates == 0
                and reference_exports_closed
            ),
            "game_owned_closure": (
                unresolved_game_functions == 0
                and unresolved_game_data == 0
                and unresolved_external == 0
                and hard_duplicates == 0
                and reference_exports_closed
            ),
            "hard_duplicate_symbols": hard_duplicates,
            "object_count": len(objects.records),
            "reference_exports_closed": reference_exports_closed,
            "resolved_symbols": len(resolved_rows),
            "unresolved_by_category": dict(sorted(unresolved_counts.items())),
            "unresolved_symbols": len(unresolved_rows),
        },
        "unresolved": unresolved_rows,
    }


def data_manifest_payload(
    image: str,
    *,
    data_map_path: Path = matchlib.DEFAULT_DATA_MAP_PATH,
    segments_path: Path | None = None,
) -> dict[str, Any]:
    if segments_path is None:
        segments_path = matchlib.default_functions_path(image).with_name("segments.json")
    payload = json.loads(data_map_path.read_text(encoding="utf-8"))
    segments: list[tuple[str, int, int]] = [
        (
            str(row["name"]),
            matchlib.parse_int(row["start"]),
            matchlib.parse_int(row["end"]),
        )
        for row in json.loads(segments_path.read_text(encoding="utf-8"))
    ]
    source_rows = [
        row
        for row in payload.get("entries", [])
        if row.get("program") == image
    ]

    entries: list[dict[str, Any]] = []
    addresses: Counter[int] = Counter()
    section_counts: Counter[str] = Counter()
    alias_rows = 0
    alias_names = 0
    fixed_arrays = 0
    incomplete_arrays = 0
    multidimensional_arrays = 0
    for row in sorted(
        source_rows,
        key=lambda item: (matchlib.parse_int(item["address"]), str(item["name"])),
    ):
        address = matchlib.parse_int(row["address"])
        addresses[address] += 1
        segment = next(
            (
                segment
                for segment in segments
                if segment[1] <= address < segment[2]
            ),
            None,
        )
        section = segment[0] if segment is not None else None
        if section is not None:
            section_counts[section] += 1
        aliases = [str(alias) for alias in row.get("aliases", [])]
        if aliases:
            alias_rows += 1
            alias_names += len(aliases)
        type_name = str(row["type"]) if row.get("type") else None
        if type_name and "[" in type_name:
            if re.search(r"\[\s*\]", type_name):
                incomplete_arrays += 1
            else:
                fixed_arrays += 1
            if type_name.count("[") > 1:
                multidimensional_arrays += 1
        entries.append(
            {
                "address": address,
                "aliases": aliases,
                "alignment": None,
                "alignment_source": None,
                "comment": str(row["comment"]),
                "initializer_hex": None,
                "initializer_source": None,
                "name": str(row["name"]),
                "section": section,
                "section_offset": address - segment[1] if segment is not None else None,
                "section_source": _repo_relative(segments_path, repo_root=matchlib.REPO_ROOT),
                "size": None,
                "size_source": None,
                "type": type_name,
            },
        )

    overlays = [
        {
            "address": address,
            "names": [entry["name"] for entry in entries if entry["address"] == address],
        }
        for address, count in sorted(addresses.items())
        if count > 1
    ]
    typed = sum(entry["type"] is not None for entry in entries)

    return {
        "entries": entries,
        "image": image,
        "kind": NATIVE_DATA_MANIFEST_KIND,
        "notes": str(payload.get("notes") or ""),
        "overlays": overlays,
        "schema": NATIVE_DATA_MANIFEST_SCHEMA,
        "source": {
            "data_map": _repo_relative(data_map_path, repo_root=matchlib.REPO_ROOT),
            "data_map_sha256": _sha256(data_map_path),
            "segments": _repo_relative(segments_path, repo_root=matchlib.REPO_ROOT),
            "segments_sha256": _sha256(segments_path),
        },
        "summary": {
            "alias_names": alias_names,
            "alias_rows": alias_rows,
            "entry_count": len(entries),
            "explicit_alignment_entries": 0,
            "explicit_initializer_entries": 0,
            "explicit_size_entries": 0,
            "fixed_array_types": fixed_arrays,
            "incomplete_array_types": incomplete_arrays,
            "multidimensional_array_types": multidimensional_arrays,
            "overlay_addresses": len(overlays),
            "section_counts": dict(sorted(section_counts.items())),
            "typed_entries": typed,
            "unique_addresses": len(addresses),
            "untyped_entries": len(entries) - typed,
        },
    }


def build_native_audit(
    image: str,
    *,
    scope: str = matchlib.DEFAULT_MATCH_SCOPE,
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT,
    jobs: int = matchlib.DEFAULT_MATCH_JOBS,
    repo_root: Path = matchlib.REPO_ROOT,
) -> NativeAudit:
    analysis_inputs_before = _analysis_input_snapshot(image, scope)
    objects = build_native_object_set(
        image,
        scope=scope,
        match_root=match_root,
        jobs=jobs,
    )
    object_manifest = object_manifest_payload(objects, repo_root=repo_root)
    symbol_closure = symbol_closure_payload(objects, repo_root=repo_root)
    data_manifest = data_manifest_payload(image)
    object_list = render_object_list(objects, repo_root=repo_root)
    export_definition = render_export_definition(image, symbol_closure)
    object_manifest["object_list_sha256"] = hashlib.sha256(object_list.encode()).hexdigest()
    symbol_closure["export_definition_sha256"] = hashlib.sha256(
        export_definition.encode(),
    ).hexdigest()
    if analysis_inputs_before != _analysis_input_snapshot(image, scope):
        raise ValueError("analysis inputs changed during native audit")
    digest_payload = {
        "data_manifest": data_manifest,
        "object_manifest": object_manifest,
        "symbol_closure": symbol_closure,
    }
    audit_digest = hashlib.sha256(
        json.dumps(
            digest_payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    ).hexdigest()
    for payload in (object_manifest, symbol_closure, data_manifest):
        payload["audit_digest"] = audit_digest
    return NativeAudit(
        objects=objects,
        object_manifest=object_manifest,
        symbol_closure=symbol_closure,
        data_manifest=data_manifest,
    )


def write_native_audit(
    audit: NativeAudit,
    output_directory: Path,
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> NativeAuditArtifacts:
    output_directory.mkdir(parents=True, exist_ok=True)
    object_manifest_path = output_directory / "objects.json"
    object_list_path = output_directory / "objects.txt"
    export_definition_path = output_directory / "exports.def"
    symbol_closure_path = output_directory / "closure.json"
    data_manifest_path = output_directory / "data.json"
    matchlib.write_match_json(object_manifest_path, audit.object_manifest)
    matchlib._write_text_atomic(
        object_list_path,
        render_object_list(audit.objects, repo_root=repo_root),
    )
    matchlib._write_text_atomic(
        export_definition_path,
        render_export_definition(audit.objects.image, audit.symbol_closure),
    )
    matchlib.write_match_json(symbol_closure_path, audit.symbol_closure)
    matchlib.write_match_json(data_manifest_path, audit.data_manifest)
    return NativeAuditArtifacts(
        object_manifest=object_manifest_path,
        object_list=object_list_path,
        export_definition=export_definition_path,
        symbol_closure=symbol_closure_path,
        data_manifest=data_manifest_path,
    )
