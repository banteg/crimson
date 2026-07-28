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
from typing import Any, cast

from . import match as matchlib

NATIVE_OBJECT_MANIFEST_SCHEMA = 2
NATIVE_SYMBOL_CLOSURE_SCHEMA = 2
NATIVE_DATA_MANIFEST_SCHEMA = 1
NATIVE_DATA_DEFINITION_SCHEMA = 1
NATIVE_TRANSLATION_UNIT_SCHEMA = 1

NATIVE_OBJECT_MANIFEST_KIND = "crimson-native-object-manifest"
NATIVE_SYMBOL_CLOSURE_KIND = "crimson-native-symbol-closure"
NATIVE_DATA_MANIFEST_KIND = "crimson-native-data-manifest"
NATIVE_DATA_DEFINITION_KIND = "crimson-native-data-definitions"

IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_REL_I386_DIR32 = 0x0006
IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105
IMAGE_WEAK_EXTERN_SEARCH_ALIAS = 3

KNOWN_MSVC_TOOLCHAIN_EXTERNALS = frozenset(
    {
        "__except_list",
        "__fltused",
    },
)

DEFAULT_NATIVE_ANALYSIS_ROOT = matchlib.REPO_ROOT / "analysis" / "native"
DEFAULT_DATA_DEFINITION_ROOT = (
    matchlib.REPO_ROOT / "tools" / "native" / "data_definitions"
)
DEFAULT_DATA_OBJECT_BUILD_ROOT = DEFAULT_DATA_DEFINITION_ROOT / "build"
DEFAULT_ABI_CONFIGS = {
    "crimsonland.exe": matchlib.REPO_ROOT / "tools" / "native" / "abi" / "crimsonland.exe",
    "grim.dll": matchlib.REPO_ROOT / "tools" / "native" / "abi" / "grim.dll",
}
DEFAULT_TRANSLATION_UNIT_CONFIGS = {
    "crimsonland.exe": (
        matchlib.REPO_ROOT
        / "tools"
        / "native"
        / "translation_units"
        / "crimsonland.exe.json"
    ),
    "grim.dll": (
        matchlib.REPO_ROOT
        / "tools"
        / "native"
        / "translation_units"
        / "grim.dll.json"
    ),
}


def default_native_data_definitions_path(image: str) -> Path:
    return DEFAULT_DATA_DEFINITION_ROOT / f"{image}.json"


def default_native_data_object_path(image: str) -> Path:
    return DEFAULT_DATA_OBJECT_BUILD_ROOT / image / "definitions.obj"


@dataclass(frozen=True, slots=True)
class NativeFunctionBinding:
    function: matchlib.FunctionSymbol
    status: matchlib.ScratchStatus
    object_symbol: str
    config_sha256: str | None = None
    source_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class NativeTranslationUnitMember:
    function: str
    symbol: str


@dataclass(frozen=True, slots=True)
class NativeTranslationUnitSpec:
    name: str
    scratch: str
    members: tuple[NativeTranslationUnitMember, ...]


@dataclass(frozen=True, slots=True)
class NativeTranslationUnitConfig:
    image: str
    path: Path
    sha256: str
    clusters: tuple[NativeTranslationUnitSpec, ...]


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
    compile_config: matchlib.ScratchConfig | None = None
    members: tuple[NativeFunctionBinding, ...] = ()
    translation_unit: str | None = None
    translation_unit_config: Path | None = None
    translation_unit_config_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class NativeDataBinding:
    address: int
    name: str
    size: int | None
    alignment: int | None
    initializer: bytes | None
    initializer_target: tuple[int, str] | None
    kind: str
    storage_address: int
    storage_name: str
    symbols: tuple[str, ...]
    section_number: int
    section_offset: int


@dataclass(frozen=True, slots=True)
class NativeDataRelocation:
    section_offset: int
    target_address: int
    target_name: str


@dataclass(frozen=True, slots=True)
class NativeDataRegion:
    address: int
    alignment: int
    data: bytes
    section_number: int
    entries: tuple[tuple[int, str], ...]
    relocations: tuple[NativeDataRelocation, ...]


@dataclass(frozen=True, slots=True)
class NativeDataObjectRecord:
    object_path: Path
    coff: matchlib.CoffObject
    definitions_path: Path
    definitions_sha256: str
    object_sha256: str
    bindings: tuple[NativeDataBinding, ...]
    regions: tuple[NativeDataRegion, ...]


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
    data_records: tuple[NativeDataObjectRecord, ...] = ()
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


def load_native_translation_unit_config(
    path: Path,
    *,
    image: str,
) -> NativeTranslationUnitConfig:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != NATIVE_TRANSLATION_UNIT_SCHEMA:
        raise ValueError(
            f"{path}: expected schema {NATIVE_TRANSLATION_UNIT_SCHEMA}",
        )
    if payload.get("image") != image:
        raise ValueError(f"{path}: targets {payload.get('image')!r}, expected {image!r}")

    raw_clusters = payload.get("clusters")
    if not isinstance(raw_clusters, list):
        raise TypeError(f"{path}: clusters must be a list")
    clusters: list[NativeTranslationUnitSpec] = []
    cluster_names: set[str] = set()
    member_functions: set[str] = set()
    for index, raw_cluster in enumerate(raw_clusters):
        if not isinstance(raw_cluster, dict):
            raise TypeError(f"{path}: clusters[{index}] must be an object")
        name = raw_cluster.get("name")
        scratch = raw_cluster.get("scratch")
        raw_members = raw_cluster.get("members")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{path}: clusters[{index}].name must be non-empty")
        if name in cluster_names:
            raise ValueError(f"{path}: duplicate translation-unit name {name!r}")
        cluster_names.add(name)
        if (
            not isinstance(scratch, str)
            or not scratch
            or Path(scratch).name != scratch
            or scratch in {".", ".."}
        ):
            raise ValueError(
                f"{path}: clusters[{index}].scratch must name one scratch directory",
            )
        if not isinstance(raw_members, list) or len(raw_members) < 2:
            raise ValueError(
                f"{path}: translation unit {name!r} must contain at least two members",
            )
        members: list[NativeTranslationUnitMember] = []
        symbols: set[str] = set()
        for member_index, raw_member in enumerate(raw_members):
            if not isinstance(raw_member, dict):
                raise TypeError(
                    f"{path}: clusters[{index}].members[{member_index}] must be an object",
                )
            function = raw_member.get("function")
            symbol = raw_member.get("symbol")
            if not isinstance(function, str) or not function:
                raise ValueError(
                    f"{path}: clusters[{index}].members[{member_index}].function "
                    "must be non-empty",
                )
            if not isinstance(symbol, str) or not symbol:
                raise ValueError(
                    f"{path}: clusters[{index}].members[{member_index}].symbol "
                    "must be non-empty",
                )
            if function in member_functions:
                raise ValueError(
                    f"{path}: function {function!r} belongs to multiple translation units",
                )
            if symbol in symbols:
                raise ValueError(
                    f"{path}: translation unit {name!r} reuses symbol {symbol!r}",
                )
            member_functions.add(function)
            symbols.add(symbol)
            members.append(NativeTranslationUnitMember(function=function, symbol=symbol))
        clusters.append(
            NativeTranslationUnitSpec(
                name=name,
                scratch=scratch,
                members=tuple(members),
            ),
        )
    return NativeTranslationUnitConfig(
        image=image,
        path=path.resolve(),
        sha256=_sha256(path),
        clusters=tuple(clusters),
    )


def _record_bindings(record: NativeObjectRecord) -> tuple[NativeFunctionBinding, ...]:
    if record.members:
        return record.members
    return (
        NativeFunctionBinding(
            function=record.function,
            status=record.status,
            object_symbol=record.object_symbol,
            config_sha256=record.config_sha256,
            source_sha256=record.source_sha256,
        ),
    )


def _record_compile_config(record: NativeObjectRecord) -> matchlib.ScratchConfig:
    return record.compile_config or record.status.config


def _record_min_address(record: NativeObjectRecord) -> int:
    return min(binding.function.address for binding in _record_bindings(record))


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
    configs = tuple(_record_compile_config(record) for record in objects.records)
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
    *,
    translation_unit_configs: dict[str, Path] | None = None,
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
    data_definitions_path = default_native_data_definitions_path(image)
    if data_definitions_path.exists():
        paths.append(data_definitions_path)
    resolved_translation_unit_configs = (
        DEFAULT_TRANSLATION_UNIT_CONFIGS
        if translation_unit_configs is None
        else translation_unit_configs
    )
    if translation_unit_config := resolved_translation_unit_configs.get(image):
        paths.append(translation_unit_config)
    return tuple((path.resolve(), _sha256(path)) for path in paths)


def _load_image_translation_unit_config(
    image: str,
    *,
    translation_unit_configs: dict[str, Path] | None,
) -> NativeTranslationUnitConfig | None:
    resolved_configs = (
        DEFAULT_TRANSLATION_UNIT_CONFIGS
        if translation_unit_configs is None
        else translation_unit_configs
    )
    path = resolved_configs.get(image)
    if path is None:
        return None
    return load_native_translation_unit_config(path, image=image)


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


def _refresh_status(
    status: matchlib.ScratchStatus,
    result: matchlib.MatchResult,
) -> matchlib.ScratchStatus:
    return replace(
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


def _validate_cluster_match(
    baseline: matchlib.ScratchStatus,
    clustered: matchlib.ScratchStatus,
    *,
    translation_unit: str,
) -> None:
    if baseline.ratio is None or clustered.ratio is None:
        raise ValueError(
            f"{translation_unit}:{baseline.config.function}: cluster evaluation failed",
        )
    regressions: list[str] = []
    if clustered.ratio < baseline.ratio:
        regressions.append(f"ratio {baseline.ratio} -> {clustered.ratio}")
    if clustered.masked_unresolved > baseline.masked_unresolved:
        regressions.append(
            f"unresolved references {baseline.masked_unresolved} "
            f"-> {clustered.masked_unresolved}",
        )
    if clustered.masked_mismatches > baseline.masked_mismatches:
        regressions.append(
            f"mismatched references {baseline.masked_mismatches} "
            f"-> {clustered.masked_mismatches}",
        )
    if regressions:
        raise ValueError(
            f"{translation_unit}:{baseline.config.function}: clustered object regresses "
            + ", ".join(regressions),
        )


def _binding_from_status(
    function: matchlib.FunctionSymbol,
    status: matchlib.ScratchStatus,
    object_symbol: str,
) -> NativeFunctionBinding:
    config = status.config
    return NativeFunctionBinding(
        function=function,
        status=status,
        object_symbol=object_symbol,
        config_sha256=_sha256(config.directory / "scratch.conf"),
        source_sha256=_sha256(config.directory / config.source),
    )


def build_native_object_set(
    image: str,
    *,
    scope: str = matchlib.DEFAULT_MATCH_SCOPE,
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT,
    jobs: int = matchlib.DEFAULT_MATCH_JOBS,
    abi_configs: dict[str, Path] | None = None,
    translation_unit_configs: dict[str, Path] | None = None,
) -> NativeObjectSet:
    """Compile canonical functions as isolated or explicitly clustered objects."""

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
    function_by_name = {function.name: function for function in manifest.functions}
    status_by_name = {
        function.name: status
        for function, status in zip(manifest.functions, selected, strict=True)
    }
    translation_units = _load_image_translation_unit_config(
        image,
        translation_unit_configs=translation_unit_configs,
    )
    prepared_clusters: list[
        tuple[
            NativeTranslationUnitSpec,
            matchlib.ScratchConfig,
            tuple[NativeTranslationUnitMember, ...],
        ]
    ] = []
    clustered_functions: set[str] = set()
    if translation_units is not None:
        scratch_root = (match_root / "scratches").resolve()
        for cluster in translation_units.clusters:
            scratch_directory = (scratch_root / cluster.scratch).resolve()
            if scratch_directory.parent != scratch_root:
                raise ValueError(
                    f"{translation_units.path}: cluster {cluster.name!r} escapes scratch root",
                )
            provider = matchlib.load_scratch_config(scratch_directory)
            if provider.image != image:
                raise ValueError(
                    f"{translation_units.path}: cluster {cluster.name!r} provider targets "
                    f"{provider.image!r}, expected {image!r}",
                )
            ordered_members = tuple(
                sorted(
                    cluster.members,
                    key=lambda member: function_by_name[member.function].address
                    if member.function in function_by_name
                    else 0,
                ),
            )
            missing_members = [
                member.function
                for member in ordered_members
                if member.function not in function_by_name
            ]
            if missing_members:
                raise ValueError(
                    f"{translation_units.path}: cluster {cluster.name!r} contains "
                    f"out-of-scope functions {', '.join(missing_members)}",
                )
            provider_members = [
                member
                for member in ordered_members
                if member.function == provider.function
            ]
            if len(provider_members) != 1:
                raise ValueError(
                    f"{translation_units.path}: cluster {cluster.name!r} provider "
                    f"FUNCTION={provider.function!r} must be one member",
                )
            if provider.symbol != provider_members[0].symbol:
                raise ValueError(
                    f"{translation_units.path}: cluster {cluster.name!r} provider "
                    f"SYMBOL={provider.symbol!r} does not match member symbol "
                    f"{provider_members[0].symbol!r}",
                )
            canonical_provider = status_by_name[provider.function].config.directory.resolve()
            if provider.directory.resolve() != canonical_provider:
                raise ValueError(
                    f"{translation_units.path}: cluster {cluster.name!r} provider "
                    "must be the selected canonical scratch",
                )
            clustered_functions.update(member.function for member in ordered_members)
            prepared_clusters.append((cluster, provider, ordered_members))

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
        if function.name in clustered_functions:
            continue
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
        refreshed_status = _refresh_status(status, result)
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

    for cluster, provider, members in prepared_clusters:
        inputs_before = _compile_input_snapshot(provider, match_root)
        object_path = matchlib.compile_scratch(provider, match_root, force=True)
        object_data = object_path.read_bytes()
        coff = matchlib.parse_coff_object(object_data)
        aliases = tuple((member.symbol, member.function) for member in members)
        bindings: list[NativeFunctionBinding] = []
        for member in members:
            function = function_by_name[member.function]
            baseline_status = status_by_name[member.function]
            result = matchlib.run_match(
                obj_path=object_path,
                function=member.function,
                image_path=image_path,
                functions_path=functions_path,
                metadata_path=metadata_path,
                symbol_name=member.symbol,
                end_va=baseline_status.config.end_va,
                reference_aliases=(*provider.reference_aliases, *aliases),
                scope=scope,
            )
            clustered_status = _refresh_status(baseline_status, result)
            _validate_cluster_match(
                baseline_status,
                clustered_status,
                translation_unit=cluster.name,
            )
            object_function = matchlib.extract_object_function(coff, member.symbol)
            bindings.append(
                _binding_from_status(
                    function,
                    clustered_status,
                    object_function.name,
                ),
            )
        if object_path.read_bytes() != object_data:
            raise ValueError(
                f"{cluster.name}: object changed during native audit",
            )
        inputs_after = _compile_input_snapshot(provider, match_root)
        if inputs_before != inputs_after:
            raise ValueError(
                f"{cluster.name}: compile inputs changed during native audit",
            )
        input_hashes = dict(inputs_after)
        config_path = (provider.directory / "scratch.conf").resolve()
        source_path = (provider.directory / provider.source).resolve()
        first_binding = bindings[0]
        records.append(
            NativeObjectRecord(
                function=first_binding.function,
                status=first_binding.status,
                object_path=object_path,
                object_symbol=first_binding.object_symbol,
                coff=coff,
                compile_inputs=inputs_after,
                config_sha256=input_hashes[config_path],
                object_sha256=_normalized_coff_sha256(object_data),
                source_sha256=input_hashes[source_path],
                compile_config=provider,
                members=tuple(bindings),
                translation_unit=cluster.name,
                translation_unit_config=translation_units.path
                if translation_units is not None
                else None,
                translation_unit_config_sha256=translation_units.sha256
                if translation_units is not None
                else None,
            ),
        )

    records.sort(key=_record_min_address)
    bound_functions = [
        binding.function.name
        for record in records
        for binding in _record_bindings(record)
    ]
    expected_functions = [function.name for function in manifest.functions]
    if sorted(bound_functions) != sorted(expected_functions):
        missing = sorted(set(expected_functions) - set(bound_functions))
        duplicates = sorted(
            name
            for name, count in Counter(bound_functions).items()
            if count > 1
        )
        raise ValueError(
            "translation-unit binding mismatch: "
            f"missing={missing}, duplicates={duplicates}",
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

    if (
        translation_units is not None
        and _sha256(translation_units.path) != translation_units.sha256
    ):
        raise ValueError("translation-unit config changed during native audit")
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


def _match_status_payload(status: matchlib.ScratchStatus) -> dict[str, Any]:
    return {
        "candidate_instructions": status.candidate_instructions,
        "masked_mismatches": status.masked_mismatches,
        "masked_ok": status.masked_ok,
        "masked_unresolved": status.masked_unresolved,
        "prefix_instructions": status.prefix_instructions,
        "ratio": status.ratio,
        "state": status.state,
        "target_instructions": status.target_instructions,
    }


def _function_binding_payload(
    binding: NativeFunctionBinding,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    config = binding.status.config
    config_path = config.directory / "scratch.conf"
    source_path = config.directory / config.source
    return {
        "address": binding.function.address,
        "canonical_config": _repo_relative(config_path, repo_root=repo_root),
        "canonical_config_sha256": binding.config_sha256 or _sha256(config_path),
        "canonical_scratch": _repo_relative(config.directory, repo_root=repo_root),
        "canonical_source": _repo_relative(source_path, repo_root=repo_root),
        "canonical_source_sha256": binding.source_sha256 or _sha256(source_path),
        "effective_end": (
            config.end_va
            if config.end_va is not None
            else binding.function.end
        ),
        "end": binding.function.end,
        "function": binding.function.name,
        "match": _match_status_payload(binding.status),
        "object_function_symbol": binding.object_symbol,
        "target_size": binding.function.size,
    }


def object_manifest_payload(
    objects: NativeObjectSet,
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> dict[str, Any]:
    bindings = [
        binding
        for record in objects.records
        for binding in _record_bindings(record)
    ]
    state_counts = Counter(binding.status.state for binding in bindings)
    records: list[dict[str, Any]] = []
    for record in objects.records:
        compile_config = _record_compile_config(record)
        source_path = compile_config.directory / compile_config.source
        config_path = compile_config.directory / "scratch.conf"
        record_bindings = _record_bindings(record)
        first_binding = record_bindings[0]
        row: dict[str, Any] = {
            "address": first_binding.function.address,
            "cflags": shlex.split(compile_config.cflags),
            "compile_argv": [
                "/nologo",
                "/c",
                *shlex.split(compile_config.cflags),
                Path(compile_config.source).name,
            ],
            "compile_inputs": [
                _snapshotted_file_payload(path, sha256, repo_root=repo_root)
                for path, sha256 in record.compile_inputs
            ],
            "compiler": compile_config.compiler,
            "config": _repo_relative(config_path, repo_root=repo_root),
            "config_sha256": record.config_sha256 or _sha256(config_path),
            "end": first_binding.function.end,
            "effective_end": (
                first_binding.status.config.end_va
                if first_binding.status.config.end_va is not None
                else first_binding.function.end
            ),
            "function": first_binding.function.name,
            "functions": [
                _function_binding_payload(binding, repo_root=repo_root)
                for binding in record_bindings
            ],
            "match": _match_status_payload(first_binding.status),
            "object": _repo_relative(record.object_path, repo_root=repo_root),
            "object_function_symbol": first_binding.object_symbol,
            "object_sha256": (
                record.object_sha256
                or _normalized_coff_sha256(record.object_path.read_bytes())
            ),
            "scratch": _repo_relative(compile_config.directory, repo_root=repo_root),
            "source": _repo_relative(source_path, repo_root=repo_root),
            "source_sha256": record.source_sha256 or _sha256(source_path),
            "target_size": first_binding.function.size,
            "translation_unit": {
                "kind": "cluster" if record.translation_unit is not None else "isolated",
                "name": record.translation_unit or first_binding.function.name,
            },
        }
        if record.translation_unit_config is not None:
            row["translation_unit"]["config"] = _repo_relative(
                record.translation_unit_config,
                repo_root=repo_root,
            )
            row["translation_unit"]["config_sha256"] = (
                record.translation_unit_config_sha256
                or _sha256(record.translation_unit_config)
            )
        records.append(row)

    data_records = [
        {
            "bindings": [
                {
                    "address": binding.address,
                    "alignment": binding.alignment,
                    "initializer_target": (
                        {
                            "address": binding.initializer_target[0],
                            "name": binding.initializer_target[1],
                        }
                        if binding.initializer_target is not None
                        else None
                    ),
                    "kind": binding.kind,
                    "name": binding.name,
                    "section_number": binding.section_number,
                    "section_offset": binding.section_offset,
                    "size": binding.size,
                    "storage_address": binding.storage_address,
                    "storage_name": binding.storage_name,
                    "symbols": list(binding.symbols),
                }
                for binding in record.bindings
            ],
            "definitions": _snapshotted_file_payload(
                record.definitions_path,
                record.definitions_sha256,
                repo_root=repo_root,
            ),
            "emitted_symbol_count": sum(
                len(binding.symbols)
                for binding in record.bindings
            ),
            "object": _repo_relative(record.object_path, repo_root=repo_root),
            "object_sha256": record.object_sha256,
            "regions": [
                {
                    "address": region.address,
                    "alignment": region.alignment,
                    "entries": [
                        {"address": address, "name": name}
                        for address, name in region.entries
                    ],
                    "relocations": [
                        {
                            "offset": relocation.section_offset,
                            "target_address": relocation.target_address,
                            "target_name": relocation.target_name,
                        }
                        for relocation in region.relocations
                    ],
                    "section_number": region.section_number,
                    "size": len(region.data),
                }
                for region in record.regions
            ],
        }
        for record in objects.data_records
    ]

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
    translation_unit_config_paths = sorted(
        {
            record.translation_unit_config
            for record in objects.records
            if record.translation_unit_config is not None
        },
    )
    selection_input_paths.extend(translation_unit_config_paths)
    selection_input_paths.extend(
        sorted(
            {
                record.definitions_path
                for record in objects.data_records
            },
        ),
    )
    cluster_count = sum(
        record.translation_unit is not None
        for record in objects.records
    )
    base_build_policy = (
        "forced-explicit-translation-unit-recompile"
        if cluster_count
        else "forced-isolated-recompile"
    )
    build_policy = (
        f"{base_build_policy}-with-generated-data-definitions"
        if data_records
        else base_build_policy
    )

    return {
        "abi_assertions": abi,
        "data_object_count": len(data_records),
        "data_objects": data_records,
        "function_count": len(bindings),
        "image": objects.image,
        "kind": NATIVE_OBJECT_MANIFEST_KIND,
        "object_count": len(records) + len(data_records),
        "object_order": "ascending-minimum-reference-address-then-generated-data",
        "object_hash": {
            "algorithm": "sha256",
            "normalization": ["zero COFF TimeDateStamp bytes 4..7"],
        },
        "objects": records,
        "provenance": {
            "build_policy": build_policy,
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
            "source": "active scratch.conf files plus explicit translation-unit config",
            "translation_unit_policy": (
                "one object per function unless an explicit cluster binds every "
                "member symbol and preserves its canonical match"
            ),
        },
        "states": dict(sorted(state_counts.items())),
        "translation_units": {
            "cluster_count": cluster_count,
            "isolated_count": len(records) - cluster_count,
        },
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
    lines.extend(
        _repo_relative(record.object_path, repo_root=repo_root)
        for record in objects.data_records
    )
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
    bindings = _record_bindings(record)
    matching_binding = next(
        (
            binding
            for binding in bindings
            if binding.object_symbol == symbol.name
        ),
        None,
    )
    occurrence: dict[str, Any] = {
        "comdat": bool(section and section.characteristics & IMAGE_SCN_LNK_COMDAT),
        "comdat_associative_section": (
            section.comdat_associative_section
            if section is not None
            else None
        ),
        "comdat_key": section.comdat_key if section is not None else None,
        "comdat_selection": section.comdat_selection if section is not None else None,
        "function": (
            matching_binding.function.name
            if matching_binding is not None
            else bindings[0].function.name
            if len(bindings) == 1
            else None
        ),
        "kind": kind,
        "logical_section_size": section.logical_size if section is not None else None,
        "object": _repo_relative(record.object_path, repo_root=repo_root),
        "section": section.name if section is not None else None,
        "size": symbol.value if kind == "common" else None,
        "weak": symbol.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    }
    if record.translation_unit is not None:
        occurrence["functions"] = [
            binding.function.name
            for binding in bindings
        ]
        occurrence["translation_unit"] = record.translation_unit
    return occurrence


def _data_symbol_occurrence(
    record: NativeDataObjectRecord,
    symbol: matchlib.CoffSymbol,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    binding = next(
        (
            candidate
            for candidate in record.bindings
            if symbol.name in candidate.symbols
        ),
        None,
    )
    if binding is None:
        raise ValueError(
            f"{record.object_path}: emitted data symbol {symbol.name!r} has no binding",
        )
    if not 0 < symbol.section_number <= len(record.coff.sections):
        raise ValueError(
            f"{record.object_path}: data symbol {symbol.name!r} is not section-defined",
        )
    section = record.coff.sections[symbol.section_number - 1]
    return {
        "alignment": binding.alignment,
        "comdat": False,
        "comdat_associative_section": None,
        "comdat_key": None,
        "comdat_selection": None,
        "data_address": binding.address,
        "data_binding_kind": binding.kind,
        "data_name": binding.name,
        "data_storage_address": binding.storage_address,
        "data_storage_name": binding.storage_name,
        "function": None,
        "kind": "section",
        "logical_section_size": section.logical_size,
        "object": _repo_relative(record.object_path, repo_root=repo_root),
        "section": section.name,
        "size": binding.size,
        "weak": False,
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
        bindings = _record_bindings(record)
        record_context: dict[str, Any] = {
            "function": bindings[0].function.name if len(bindings) == 1 else None,
        }
        if record.translation_unit is not None:
            record_context["functions"] = [
                binding.function.name
                for binding in bindings
            ]
            record_context["translation_unit"] = record.translation_unit
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
                    **record_context,
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

    for record in objects.data_records:
        object_name = _repo_relative(record.object_path, repo_root=repo_root)
        directives_by_object[object_name] = ()
        for symbol in record.coff.symbols:
            if symbol.storage_class != matchlib.IMAGE_SYM_CLASS_EXTERNAL:
                continue
            if symbol.section_number <= 0:
                raise ValueError(
                    f"{record.object_path}: generated data object contains "
                    f"undefined symbol {symbol.name!r}",
                )
            definitions[symbol.name].append(
                _data_symbol_occurrence(
                    record,
                    symbol,
                    repo_root=repo_root,
                ),
            )

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
        ordered = sorted(
            occurrences,
            key=lambda row: (row["object"], str(row.get("function") or "")),
        )
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
    game_function_debt: Counter[str] = Counter()
    for name, references in sorted(undefined.items()):
        ordered_references = sorted(
            references,
            key=lambda row: (row["object"], str(row.get("function") or "")),
        )
        if name in definitions:
            resolved_rows.append(
                {
                    "definitions": sorted(
                        definitions[name],
                        key=lambda row: (row["object"], str(row.get("function") or "")),
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
        candidate_definitions = sorted(definitions_by_lookup.get(lookup_name, []))
        unresolved_counts[category] += 1
        if category == "game_function":
            game_function_debt[
                "emitted_name_mismatch"
                if candidate_definitions
                else "missing_definition"
            ] += 1
        unresolved_rows.append(
            {
                "candidate_definitions": candidate_definitions,
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
    hard_duplicate_sections: Counter[str] = Counter()
    for row in duplicate_rows:
        sections = {
            str(definition["section"])
            for definition in row["definitions"]
        }
        section = next(iter(sections)) if len(sections) == 1 else "mixed"
        hard_duplicate_sections[section] += 1
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
            "game_function_debt": dict(sorted(game_function_debt.items())),
            "hard_duplicate_by_section": dict(sorted(hard_duplicate_sections.items())),
            "hard_duplicate_symbols": hard_duplicates,
            "function_count": sum(
                len(_record_bindings(record))
                for record in objects.records
            ),
            "object_count": len(objects.records) + len(objects.data_records),
            "reference_exports_closed": reference_exports_closed,
            "resolved_symbols": len(resolved_rows),
            "unresolved_by_category": dict(sorted(unresolved_counts.items())),
            "unresolved_symbols": len(unresolved_rows),
        },
        "unresolved": unresolved_rows,
    }


def load_native_data_definitions(
    image: str,
    *,
    path: Path | None = None,
    reference_image_path: Path | None = None,
    data_map_path: Path = matchlib.DEFAULT_DATA_MAP_PATH,
) -> dict[str, Any] | None:
    path = path or default_native_data_definitions_path(image)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{path}: data definitions must be an object")
    if payload.get("schema") != NATIVE_DATA_DEFINITION_SCHEMA:
        raise ValueError(
            f"{path}: expected schema {NATIVE_DATA_DEFINITION_SCHEMA}",
        )
    if payload.get("kind") != NATIVE_DATA_DEFINITION_KIND:
        raise ValueError(f"{path}: expected kind {NATIVE_DATA_DEFINITION_KIND!r}")
    if payload.get("image") != image:
        raise ValueError(f"{path}: targets {payload.get('image')!r}, expected {image!r}")

    reference_image = payload.get("reference_image")
    if not isinstance(reference_image, dict):
        raise TypeError(f"{path}: reference_image must be an object")
    reference_path = reference_image.get("path")
    reference_sha256 = reference_image.get("sha256")
    if (
        not isinstance(reference_path, str)
        or not reference_path
        or Path(reference_path).name != image
    ):
        raise ValueError(f"{path}: reference_image.path must identify {image}")
    if (
        not isinstance(reference_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", reference_sha256) is None
    ):
        raise ValueError(f"{path}: reference_image.sha256 must be a lowercase SHA-256")
    if (
        reference_image_path is not None
        and _sha256(reference_image_path) != reference_sha256
    ):
        raise ValueError(
            f"{path}: reference image digest does not match {reference_image_path}",
        )
    loaded_reference_image = (
        matchlib.load_image(reference_image_path)
        if reference_image_path is not None
        else None
    )

    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise TypeError(f"{path}: entries must be an array")
    explicit_entry_keys: list[tuple[int, str]] = []
    labeled_entries: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(raw_entries):
        label = f"{path}: entries[{index}]"
        if not isinstance(raw_entry, dict):
            raise TypeError(f"{label} must be an object")
        raw_entry = cast(dict[str, Any], raw_entry)
        raw_address = raw_entry.get("address")
        name = raw_entry.get("name")
        if not isinstance(raw_address, (str, int)):
            raise TypeError(f"{label}.address must be an integer or hex string")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{label}.name must be non-empty")
        try:
            key = (matchlib.parse_int(raw_address), name)
        except ValueError as exc:
            raise ValueError(
                f"{label}.address must be an integer or hex string",
            ) from exc
        explicit_entry_keys.append(key)
        labeled_entries.append({**raw_entry, "__label": label})
    if explicit_entry_keys != sorted(explicit_entry_keys):
        raise ValueError(f"{path}: entries must be sorted by address and name")

    raw_groups = payload.get("groups", [])
    if not isinstance(raw_groups, list):
        raise TypeError(f"{path}: groups must be an array")
    data_map_types: dict[tuple[int, str], str | None] = {}
    if raw_groups:
        data_map_payload = json.loads(data_map_path.read_text(encoding="utf-8"))
        data_map_types = {
            (
                matchlib.parse_int(row["address"]),
                str(row["name"]),
            ): str(row["type"]) if row.get("type") else None
            for row in data_map_payload.get("entries", [])
            if row.get("program") == image
        }
    group_names: set[str] = set()
    group_fields = (
        "alignment",
        "alignment_source",
        "initializer_fill",
        "initializer_hex",
        "initializer_source",
        "initializer_target",
        "note",
        "size",
        "size_source",
    )
    for group_index, raw_group in enumerate(raw_groups):
        group_label = f"{path}: groups[{group_index}]"
        if not isinstance(raw_group, dict):
            raise TypeError(f"{group_label} must be an object")
        raw_group = cast(dict[str, Any], raw_group)
        group_name = raw_group.get("name")
        if not isinstance(group_name, str) or not group_name:
            raise ValueError(f"{group_label}.name must be non-empty")
        if group_name in group_names:
            raise ValueError(f"{group_label}: duplicate group name {group_name!r}")
        group_names.add(group_name)
        expected_types = raw_group.get("types")
        if (
            not isinstance(expected_types, list)
            or not expected_types
            or any(
                type_name is not None
                and (not isinstance(type_name, str) or not type_name)
                for type_name in expected_types
            )
        ):
            raise ValueError(
                f"{group_label}.types must contain non-empty strings or null",
            )
        members = raw_group.get("members")
        if not isinstance(members, list) or not members:
            raise ValueError(f"{group_label}.members must be a non-empty array")
        member_initializer_hex = raw_group.get("member_initializer_hex", False)
        if not isinstance(member_initializer_hex, bool):
            raise TypeError(f"{group_label}.member_initializer_hex must be a boolean")
        if member_initializer_hex:
            if (
                raw_group.get("initializer_hex") is not None
                or raw_group.get("initializer_fill") is not None
            ):
                raise ValueError(
                    f"{group_label}: member_initializer_hex cannot be combined "
                    "with a group initializer",
                )
            if not isinstance(raw_group.get("initializer_source"), str):
                raise ValueError(
                    f"{group_label}: member_initializer_hex requires "
                    "initializer_source",
                )
        member_keys: list[tuple[int, str]] = []
        for member_index, member in enumerate(members):
            member_label = f"{group_label}.members[{member_index}]"
            expected_member_length = 3 if member_initializer_hex else 2
            if (
                not isinstance(member, list)
                or len(member) != expected_member_length
                or not isinstance(member[0], (str, int))
                or not isinstance(member[1], str)
                or not member[1]
                or (
                    member_initializer_hex
                    and (
                        not isinstance(member[2], str)
                        or re.fullmatch(r"(?:[0-9a-f]{2})+", member[2]) is None
                    )
                )
            ):
                member_shape = (
                    "[address, non-empty name, lowercase byte hex]"
                    if member_initializer_hex
                    else "[address, non-empty name]"
                )
                raise ValueError(
                    f"{member_label} must be {member_shape}",
                )
            try:
                key = (matchlib.parse_int(member[0]), member[1])
            except ValueError as exc:
                raise ValueError(
                    f"{member_label} has an invalid address",
                ) from exc
            actual_type = data_map_types.get(key)
            if key not in data_map_types:
                raise ValueError(
                    f"{member_label}: {key[1]}@0x{key[0]:08x} "
                    "is absent from the data map",
                )
            if actual_type not in expected_types:
                raise ValueError(
                    f"{member_label}: data-map type {actual_type!r} is not one of "
                    f"{expected_types!r}",
                )
            member_keys.append(key)
            expanded = {
                field: raw_group[field]
                for field in group_fields
                if field in raw_group
            }
            expanded.update(
                {
                    "__definition_group": group_name,
                    "__label": member_label,
                    "address": member[0],
                    "name": member[1],
                },
            )
            if member_initializer_hex:
                expanded["initializer_hex"] = member[2]
            labeled_entries.append(expanded)
        if member_keys != sorted(member_keys):
            raise ValueError(f"{group_label}.members must be sorted by address and name")

    raw_entries = sorted(
        labeled_entries,
        key=lambda raw_entry: (
            matchlib.parse_int(raw_entry["address"]),
            str(raw_entry["name"]),
        ),
    )
    entries: list[dict[str, Any]] = []
    keys: set[tuple[int, str]] = set()
    for index, raw_entry in enumerate(raw_entries):
        label = str(raw_entry.get("__label") or f"{path}: entries[{index}]")
        name = raw_entry.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{label}.name must be non-empty")
        raw_address = raw_entry.get("address")
        if not isinstance(raw_address, (str, int)):
            raise TypeError(f"{label}.address must be an integer or hex string")
        try:
            address = matchlib.parse_int(raw_address)
        except ValueError as exc:
            raise ValueError(f"{label}.address must be an integer or hex string") from exc
        key = (address, name)
        if key in keys:
            raise ValueError(f"{label}: duplicate definition for {name} at 0x{address:08x}")
        keys.add(key)

        normalized: dict[str, Any] = {
            "address": address,
            "definition_group": str(raw_entry.get("__definition_group") or ""),
            "name": name,
            "note": str(raw_entry.get("note") or ""),
        }
        explicit_fields = 0
        field_sources = {
            "size": "size_source",
            "alignment": "alignment_source",
        }
        for field, source_field in field_sources.items():
            value = raw_entry.get(field)
            source = raw_entry.get(source_field)
            if value is None and source is None:
                normalized[field] = None
                normalized[source_field] = None
                continue
            if value is None or not isinstance(source, str) or not source.strip():
                raise ValueError(
                    f"{label}: {field} and {source_field} must be provided together",
                )
            explicit_fields += 1
            normalized[field] = value
            normalized[source_field] = source.strip()

        initializer_hex = raw_entry.get("initializer_hex")
        initializer_fill = raw_entry.get("initializer_fill")
        initializer_target = raw_entry.get("initializer_target")
        initializer_source = raw_entry.get("initializer_source")
        initializer_forms = sum(
            value is not None
            for value in (initializer_hex, initializer_fill, initializer_target)
        )
        if initializer_forms > 1:
            raise ValueError(
                f"{label}: initializer_hex, initializer_fill, and "
                "initializer_target are mutually exclusive",
            )
        if initializer_forms == 0:
            if initializer_source is not None:
                raise ValueError(
                    f"{label}: initializer_source requires an initializer",
                )
            normalized["initializer_fill"] = None
            normalized["initializer_hex"] = None
            normalized["initializer_source"] = None
            normalized["initializer_target"] = None
        else:
            if (
                not isinstance(initializer_source, str)
                or not initializer_source.strip()
            ):
                raise ValueError(
                    f"{label}: initializer and initializer_source "
                    "must be provided together",
                )
            explicit_fields += 1
            normalized["initializer_fill"] = initializer_fill
            normalized["initializer_hex"] = initializer_hex
            normalized["initializer_source"] = initializer_source.strip()
            if initializer_target is None:
                normalized["initializer_target"] = None
            else:
                if (
                    not isinstance(initializer_target, list)
                    or len(initializer_target) != 2
                    or not isinstance(initializer_target[0], (str, int))
                    or not isinstance(initializer_target[1], str)
                    or not initializer_target[1]
                ):
                    raise ValueError(
                        f"{label}.initializer_target must be "
                        "[address, non-empty name]",
                    )
                try:
                    target_address = matchlib.parse_int(initializer_target[0])
                except ValueError as exc:
                    raise ValueError(
                        f"{label}.initializer_target has an invalid address",
                    ) from exc
                normalized["initializer_target"] = {
                    "address": target_address,
                    "name": initializer_target[1],
                }
        if explicit_fields == 0:
            raise ValueError(f"{label}: at least one explicit data fact is required")

        size = normalized["size"]
        if size is not None and (
            not isinstance(size, int) or isinstance(size, bool) or size <= 0
        ):
            raise ValueError(f"{label}.size must be a positive integer")
        alignment = normalized["alignment"]
        if alignment is not None and (
            not isinstance(alignment, int)
            or isinstance(alignment, bool)
            or alignment <= 0
            or alignment & (alignment - 1)
        ):
            raise ValueError(f"{label}.alignment must be a positive power of two")
        if alignment is not None and address % alignment:
            raise ValueError(
                f"{label}.address 0x{address:08x} is not aligned to {alignment}",
            )
        initializer_fill = normalized["initializer_fill"]
        if initializer_fill is not None and (
            not isinstance(initializer_fill, str)
            or re.fullmatch(r"[0-9a-f]{2}", initializer_fill) is None
        ):
            raise ValueError(
                f"{label}.initializer_fill must be one lowercase hex byte",
            )
        initializer_hex = normalized["initializer_hex"]
        if initializer_hex is not None:
            if (
                not isinstance(initializer_hex, str)
                or not initializer_hex
                or re.fullmatch(r"(?:[0-9a-f]{2})+", initializer_hex) is None
            ):
                raise ValueError(
                    f"{label}.initializer_hex must be non-empty lowercase byte hex",
                )
            if size is None:
                raise ValueError(f"{label}: initializer_hex requires an explicit size")
            if len(initializer_hex) // 2 != size:
                raise ValueError(
                    f"{label}: initializer has {len(initializer_hex) // 2} bytes, "
                    f"expected size {size}",
                )
        if initializer_fill is not None and size is None:
            raise ValueError(f"{label}: initializer_fill requires an explicit size")
        normalized_target = normalized["initializer_target"]
        if normalized_target is not None and size != 4:
            raise ValueError(f"{label}: initializer_target requires size 4")
        initializer = (
            bytes.fromhex(initializer_hex)
            if initializer_hex is not None
            else bytes.fromhex(initializer_fill) * size
            if initializer_fill is not None and size is not None
            else struct.pack("<I", int(normalized_target["address"]))
            if normalized_target is not None
            else None
        )
        if initializer is not None and loaded_reference_image is not None:
            start = address - loaded_reference_image.image_base
            end = start + len(initializer)
            if start < 0 or end > len(loaded_reference_image.mapped):
                raise ValueError(
                    f"{label}: initializer range is outside the reference image",
                )
            reference_bytes = loaded_reference_image.mapped[start:end]
            if initializer != reference_bytes:
                raise ValueError(
                    f"{label}: initializer does not match reference image bytes",
                )
        entries.append(normalized)

    ordered = sorted(entries, key=lambda row: (row["address"], row["name"]))
    if entries != ordered:
        raise ValueError(f"{path}: entries must be sorted by address and name")
    entries_by_key = {
        (int(entry["address"]), str(entry["name"])): entry
        for entry in entries
    }
    for entry in entries:
        target = entry["initializer_target"]
        if target is None:
            continue
        target_key = (int(target["address"]), str(target["name"]))
        target_entry = entries_by_key.get(target_key)
        if target_entry is None:
            raise ValueError(
                f"{path}: initializer target {target_key[1]}@"
                f"0x{target_key[0]:08x} has no definition",
            )
        if (
            target_entry["size"] is None
            or target_entry["alignment"] is None
            or (
                target_entry["initializer_hex"] is None
                and target_entry["initializer_fill"] is None
                and target_entry["initializer_target"] is None
            )
        ):
            raise ValueError(
                f"{path}: initializer target {target_key[1]}@"
                f"0x{target_key[0]:08x} is not fully specified",
            )
    return {
        "entries": entries,
        "image": image,
        "kind": NATIVE_DATA_DEFINITION_KIND,
        "notes": str(payload.get("notes") or ""),
        "groups": sorted(group_names),
        "reference_image": {
            "path": reference_path,
            "sha256": reference_sha256,
        },
        "schema": NATIVE_DATA_DEFINITION_SCHEMA,
    }


def _data_closure_references(
    symbol_closure: dict[str, Any] | None,
) -> dict[tuple[int, str], list[dict[str, Any]]]:
    if symbol_closure is None:
        return {}
    raw_unresolved = symbol_closure.get("unresolved")
    if not isinstance(raw_unresolved, list):
        raise TypeError("symbol closure unresolved entries must be an array")
    references: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for index, raw_row in enumerate(raw_unresolved):
        if not isinstance(raw_row, dict):
            raise TypeError(f"symbol closure unresolved[{index}] must be an object")
        if raw_row.get("category") != "game_data":
            continue
        name = raw_row.get("name")
        lookup_name = raw_row.get("lookup_name")
        referenced_by = raw_row.get("referenced_by")
        catalog = raw_row.get("catalog")
        if not isinstance(name, str) or not isinstance(lookup_name, str):
            raise TypeError(f"symbol closure unresolved[{index}] has invalid names")
        if not isinstance(referenced_by, list) or not isinstance(catalog, list):
            raise TypeError(
                f"symbol closure unresolved[{index}] requires catalog and referenced_by arrays",
            )
        symbol = {
            "lookup_name": lookup_name,
            "name": name,
            "reference_count": len(referenced_by),
        }
        seen_keys: set[tuple[int, str]] = set()
        for raw_catalog in catalog:
            if not isinstance(raw_catalog, dict):
                raise TypeError(
                    f"symbol closure unresolved[{index}] catalog entries must be objects",
                )
            raw_address = raw_catalog.get("address")
            raw_name = raw_catalog.get("name")
            if not isinstance(raw_address, (str, int)) or not isinstance(
                raw_name,
                str,
            ):
                raise TypeError(
                    f"symbol closure unresolved[{index}] has invalid catalog data",
                )
            try:
                key = (
                    matchlib.parse_int(raw_address),
                    raw_name,
                )
            except ValueError as exc:
                raise ValueError(
                    f"symbol closure unresolved[{index}] has invalid catalog data",
                ) from exc
            if key not in seen_keys:
                references[key].append(symbol)
                seen_keys.add(key)
    return references


def _native_data_layout(
    definitions: dict[str, Any],
    symbol_closure: dict[str, Any],
) -> tuple[tuple[NativeDataBinding, ...], tuple[NativeDataRegion, ...]]:
    references = _data_closure_references(symbol_closure)
    definition_rows: list[dict[str, Any]] = []
    definitions_by_key: dict[tuple[int, str], dict[str, Any]] = {}
    for entry in definitions["entries"]:
        size = entry["size"]
        alignment = entry["alignment"]
        initializer_hex = entry.get("initializer_hex")
        initializer_fill = entry.get("initializer_fill")
        initializer_target = entry.get("initializer_target")
        if (
            size is None
            or alignment is None
            or (
                initializer_hex is None
                and initializer_fill is None
                and initializer_target is None
            )
        ):
            continue
        key = (int(entry["address"]), str(entry["name"]))
        initializer = (
            bytes.fromhex(str(initializer_hex))
            if initializer_hex is not None
            else bytes.fromhex(str(initializer_fill)) * int(size)
            if initializer_fill is not None
            else bytes(int(size))
        )
        target_key = (
            (
                int(initializer_target["address"]),
                str(initializer_target["name"]),
            )
            if initializer_target is not None
            else None
        )
        row = {
            "address": key[0],
            "alignment": int(alignment),
            "initializer": initializer,
            "initializer_target": target_key,
            "key": key,
            "name": key[1],
            "size": int(size),
        }
        definition_rows.append(row)
        definitions_by_key[key] = row

    symbol_candidates: dict[
        str,
        list[tuple[tuple[int, str], dict[str, Any]]],
    ] = defaultdict(list)
    for key, rows in references.items():
        for reference in rows:
            symbol_candidates[str(reference["name"])].append((key, reference))

    assignments: dict[
        tuple[tuple[int, str], tuple[int, str]],
        list[str],
    ] = defaultdict(list)
    for symbol, candidates in sorted(symbol_candidates.items()):
        candidate_keys = sorted({key for key, _ in candidates})
        candidate_addresses = {key[0] for key in candidate_keys}
        if len(candidate_addresses) != 1:
            continue
        lookup_names = {
            str(reference["lookup_name"])
            for _, reference in candidates
        }
        target_key = min(
            candidate_keys,
            key=lambda key: (
                key[1] not in lookup_names,
                key not in definitions_by_key,
                key[1],
            ),
        )
        owner = definitions_by_key.get(target_key)
        if owner is None:
            address = target_key[0]
            containers = [
                row
                for row in definition_rows
                if (
                    int(row["address"])
                    <= address
                    < int(row["address"]) + int(row["size"])
                )
            ]
            if not containers:
                continue
            owner = min(
                containers,
                key=lambda row: (
                    int(row["size"]),
                    int(row["address"]),
                    str(row["name"]),
                ),
            )
        owner_key = (int(owner["address"]), str(owner["name"]))
        assignments[(owner_key, target_key)].append(symbol)

    selected_owner_keys = {
        owner_key
        for owner_key, _ in assignments
    }
    while True:
        dependency_keys = {
            target_key
            for owner_key in selected_owner_keys
            if (
                target_key := definitions_by_key[owner_key][
                    "initializer_target"
                ]
            )
            is not None
        }
        missing_dependencies = dependency_keys - selected_owner_keys
        if not missing_dependencies:
            break
        selected_owner_keys.update(missing_dependencies)
    pending: list[dict[str, Any]] = [
        {
            **row,
            "symbols": tuple(
                sorted(assignments.get((row["key"], row["key"]), [])),
            ),
        }
        for row in definition_rows
        if row["key"] in selected_owner_keys
    ]

    if not pending:
        return (), ()
    pending.sort(key=lambda row: (int(row["address"]), str(row["name"])))

    groups: list[list[dict[str, Any]]] = []
    for row in pending:
        start = int(row["address"])
        if groups:
            group_end = max(
                int(candidate["address"]) + int(candidate["size"])
                for candidate in groups[-1]
            )
            if start < group_end:
                groups[-1].append(row)
                continue
        groups.append([row])

    while True:
        merged: list[list[dict[str, Any]]] = []
        changed = False
        for group in groups:
            alignment = max(int(row["alignment"]) for row in group)
            start = min(int(row["address"]) for row in group)
            storage_start = start - start % alignment
            if merged:
                previous = merged[-1]
                previous_end = max(
                    int(row["address"]) + int(row["size"])
                    for row in previous
                )
                if storage_start < previous_end:
                    previous.extend(group)
                    changed = True
                    continue
            merged.append(group)
        groups = merged
        if not changed:
            break

    bindings: list[NativeDataBinding] = []
    regions: list[NativeDataRegion] = []
    owner_locations: dict[tuple[int, str], tuple[int, int]] = {}
    for section_number, group in enumerate(groups, start=1):
        alignment = max(int(row["alignment"]) for row in group)
        first_address = min(int(row["address"]) for row in group)
        storage_address = first_address - first_address % alignment
        storage_end = max(
            int(row["address"]) + int(row["size"])
            for row in group
        )
        data = bytearray(storage_end - storage_address)
        written = bytearray(len(data))
        relocations: list[NativeDataRelocation] = []
        for row in group:
            offset = int(row["address"]) - storage_address
            initializer = bytes(row["initializer"])
            for byte_index, value in enumerate(initializer, start=offset):
                if written[byte_index] and data[byte_index] != value:
                    raise ValueError(
                        f"overlapping data definitions disagree at "
                        f"0x{storage_address + byte_index:08x}",
                    )
                data[byte_index] = value
                written[byte_index] = 1
            bindings.append(
                NativeDataBinding(
                    address=int(row["address"]),
                    name=str(row["name"]),
                    size=int(row["size"]),
                    alignment=int(row["alignment"]),
                    initializer=initializer,
                    initializer_target=cast(
                        tuple[int, str] | None,
                        row["initializer_target"],
                    ),
                    kind="definition",
                    storage_address=int(row["address"]),
                    storage_name=str(row["name"]),
                    symbols=tuple(str(symbol) for symbol in row["symbols"]),
                    section_number=section_number,
                    section_offset=offset,
                ),
            )
            owner_locations[row["key"]] = (section_number, offset)
            target_key = cast(
                tuple[int, str] | None,
                row["initializer_target"],
            )
            if target_key is not None:
                relocations.append(
                    NativeDataRelocation(
                        section_offset=offset,
                        target_address=target_key[0],
                        target_name=target_key[1],
                    ),
                )
        regions.append(
            NativeDataRegion(
                address=storage_address,
                alignment=alignment,
                data=bytes(data),
                section_number=section_number,
                entries=tuple(
                    sorted(
                        (
                            (int(row["address"]), str(row["name"]))
                            for row in group
                        ),
                    ),
                ),
                relocations=tuple(
                    sorted(
                        relocations,
                        key=lambda relocation: relocation.section_offset,
                    ),
                ),
            ),
        )
    for (owner_key, target_key), symbols in sorted(assignments.items()):
        if owner_key == target_key:
            continue
        owner = definitions_by_key[owner_key]
        section_number, owner_offset = owner_locations[owner_key]
        bindings.append(
            NativeDataBinding(
                address=target_key[0],
                name=target_key[1],
                size=None,
                alignment=None,
                initializer=None,
                initializer_target=None,
                kind="interior-alias",
                storage_address=owner_key[0],
                storage_name=owner_key[1],
                symbols=tuple(sorted(symbols)),
                section_number=section_number,
                section_offset=owner_offset + target_key[0] - int(owner["address"]),
            ),
        )
    bindings.sort(
        key=lambda binding: (
            binding.section_number,
            binding.section_offset,
            binding.kind,
            binding.name,
        ),
    )
    return tuple(bindings), tuple(regions)


def _coff_alignment_characteristic(alignment: int) -> int:
    if alignment > 8192:
        raise ValueError(f"COFF section alignment {alignment} exceeds 8192")
    return alignment.bit_length() << 20


def native_data_object_bytes(
    definitions: dict[str, Any],
    symbol_closure: dict[str, Any],
) -> tuple[
    bytes,
    tuple[NativeDataBinding, ...],
    tuple[NativeDataRegion, ...],
]:
    bindings, regions = _native_data_layout(definitions, symbol_closure)
    if not bindings:
        return b"", (), ()

    external_symbols: list[tuple[str, NativeDataBinding, int]] = sorted(
        (
            (symbol, binding, matchlib.IMAGE_SYM_CLASS_EXTERNAL)
            for binding in bindings
            for symbol in binding.symbols
        ),
        key=lambda item: item[0],
    )
    bindings_by_key = {
        (binding.address, binding.name): binding
        for binding in bindings
        if binding.kind == "definition"
    }
    relocation_target_keys = {
        (relocation.target_address, relocation.target_name)
        for region in regions
        for relocation in region.relocations
    }
    local_symbol_by_key = {
        key: f"$data${key[0]:08x}"
        for key in sorted(relocation_target_keys)
    }
    local_symbols = [
        (
            local_symbol_by_key[key],
            bindings_by_key[key],
            matchlib.IMAGE_SYM_CLASS_STATIC,
        )
        for key in sorted(relocation_target_keys)
    ]
    symbols = sorted(external_symbols + local_symbols, key=lambda item: item[0])
    if len({symbol for symbol, _, _ in symbols}) != len(symbols):
        raise ValueError("generated data object contains duplicate symbol names")
    symbol_index_by_name = {
        symbol: index
        for index, (symbol, _, _) in enumerate(symbols)
    }

    string_offsets: dict[str, int] = {}
    string_payload = bytearray()
    for symbol, _, _ in symbols:
        encoded = symbol.encode("latin1")
        if len(encoded) <= 8:
            continue
        string_offsets[symbol] = 4 + len(string_payload)
        string_payload.extend(encoded)
        string_payload.append(0)
    string_table = struct.pack("<I", 4 + len(string_payload)) + string_payload

    section_table_end = 20 + len(regions) * 40
    cursor = section_table_end
    raw_offsets: list[int] = []
    relocation_offsets: list[int] = []
    for region in regions:
        cursor = (cursor + 3) & ~3
        raw_offsets.append(cursor)
        cursor += len(region.data)
        if region.relocations:
            cursor = (cursor + 3) & ~3
            relocation_offsets.append(cursor)
            cursor += len(region.relocations) * 10
        else:
            relocation_offsets.append(0)
    symbol_table_offset = (cursor + 3) & ~3

    payload = bytearray(symbol_table_offset)
    struct.pack_into(
        "<HHIIIHH",
        payload,
        0,
        matchlib.IMAGE_FILE_MACHINE_I386,
        len(regions),
        0,
        symbol_table_offset,
        len(symbols),
        0,
        0,
    )
    for index, (region, raw_offset, relocation_offset) in enumerate(
        zip(regions, raw_offsets, relocation_offsets, strict=True),
    ):
        header_offset = 20 + index * 40
        payload[header_offset : header_offset + 8] = b".data\x00\x00\x00"
        struct.pack_into(
            "<IIIIIIHHI",
            payload,
            header_offset + 8,
            0,
            0,
            len(region.data),
            raw_offset,
            relocation_offset,
            0,
            len(region.relocations),
            0,
            (
                IMAGE_SCN_CNT_INITIALIZED_DATA
                | _coff_alignment_characteristic(region.alignment)
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE
            ),
        )
        payload[raw_offset : raw_offset + len(region.data)] = region.data
        for relocation_index, relocation in enumerate(region.relocations):
            target_key = (
                relocation.target_address,
                relocation.target_name,
            )
            struct.pack_into(
                "<IIH",
                payload,
                relocation_offset + relocation_index * 10,
                relocation.section_offset,
                symbol_index_by_name[local_symbol_by_key[target_key]],
                IMAGE_REL_I386_DIR32,
            )

    for symbol, binding, storage_class in symbols:
        encoded = symbol.encode("latin1")
        if len(encoded) <= 8:
            name_field = encoded.ljust(8, b"\x00")
        else:
            name_field = struct.pack("<II", 0, string_offsets[symbol])
        payload.extend(name_field)
        payload.extend(
            struct.pack(
                "<IhHBB",
                binding.section_offset,
                binding.section_number,
                0,
                storage_class,
                0,
            ),
        )
    payload.extend(string_table)

    object_data = bytes(payload)
    coff = matchlib.parse_coff_object(object_data)
    parsed_external_symbols = {
        symbol.name: symbol
        for symbol in coff.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
    }
    if set(parsed_external_symbols) != {
        symbol
        for symbol, _, _ in external_symbols
    }:
        raise ValueError("generated data object symbol table did not round-trip")
    parsed_symbols = {symbol.name: symbol for symbol in coff.symbols}
    for symbol, binding, storage_class in symbols:
        parsed = parsed_symbols[symbol]
        if (
            parsed.section_number != binding.section_number
            or parsed.value != binding.section_offset
            or parsed.storage_class != storage_class
        ):
            raise ValueError(
                f"generated data symbol {symbol!r} did not retain its section offset",
            )
    for region, parsed_section in zip(regions, coff.sections, strict=True):
        if len(parsed_section.relocations) != len(region.relocations):
            raise ValueError("generated data relocations did not round-trip")
        for expected, parsed in zip(
            region.relocations,
            parsed_section.relocations,
            strict=True,
        ):
            target_key = (expected.target_address, expected.target_name)
            target_symbol = parsed_symbols[
                local_symbol_by_key[target_key]
            ]
            if (
                parsed.virtual_address != expected.section_offset
                or parsed.symbol_index != target_symbol.raw_index
                or parsed.relocation_type != IMAGE_REL_I386_DIR32
            ):
                raise ValueError("generated data relocation did not round-trip")
    return object_data, bindings, regions


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def build_native_data_object(
    image: str,
    *,
    symbol_closure: dict[str, Any],
    reference_image_path: Path,
    definitions_path: Path | None = None,
    output_path: Path | None = None,
) -> NativeDataObjectRecord | None:
    resolved_definitions_path = (
        definitions_path
        if definitions_path is not None
        else default_native_data_definitions_path(image)
    )
    definitions = load_native_data_definitions(
        image,
        path=resolved_definitions_path,
        reference_image_path=reference_image_path,
    )
    if definitions is None:
        return None
    object_data, bindings, regions = native_data_object_bytes(
        definitions,
        symbol_closure,
    )
    if not bindings:
        return None
    resolved_output_path = (
        output_path
        if output_path is not None
        else default_native_data_object_path(image)
    )
    _write_bytes_atomic(resolved_output_path, object_data)
    return NativeDataObjectRecord(
        object_path=resolved_output_path.resolve(),
        coff=matchlib.parse_coff_object(object_data),
        definitions_path=resolved_definitions_path.resolve(),
        definitions_sha256=_sha256(resolved_definitions_path),
        object_sha256=_normalized_coff_sha256(object_data),
        bindings=bindings,
        regions=regions,
    )


def _data_definition_state(entry: dict[str, Any]) -> str:
    initializer_present = (
        entry.get("initializer_hex") is not None
        or entry.get("initializer_fill") is not None
        or entry.get("initializer_target") is not None
    )
    present = sum(
        (
            entry["size"] is not None,
            entry["alignment"] is not None,
            initializer_present,
        ),
    )
    if present == 3:
        return "fully-specified"
    if present:
        return "partial"
    return "unknown"


def data_manifest_payload(
    image: str,
    *,
    data_map_path: Path = matchlib.DEFAULT_DATA_MAP_PATH,
    segments_path: Path | None = None,
    definitions_path: Path | None = None,
    reference_image_path: Path | None = None,
    symbol_closure: dict[str, Any] | None = None,
    repo_root: Path = matchlib.REPO_ROOT,
) -> dict[str, Any]:
    if segments_path is None:
        segments_path = matchlib.default_functions_path(image).with_name("segments.json")
    resolved_definitions_path = (
        definitions_path
        if definitions_path is not None
        else default_native_data_definitions_path(image)
    )
    definitions = load_native_data_definitions(
        image,
        path=resolved_definitions_path,
        reference_image_path=reference_image_path,
        data_map_path=data_map_path,
    )
    definitions_by_key = {
        (int(entry["address"]), str(entry["name"])): entry
        for entry in definitions["entries"]
    } if definitions is not None else {}
    closure_references = _data_closure_references(symbol_closure)
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
    matched_definition_keys: set[tuple[int, str]] = set()
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
        key = (address, str(row["name"]))
        definition = definitions_by_key.get(key)
        if definition is not None:
            matched_definition_keys.add(key)
        requested_symbols = sorted(
            closure_references.get(key, []),
            key=lambda item: (-int(item["reference_count"]), str(item["name"])),
        )
        linker_reference_count = sum(
            int(symbol["reference_count"])
            for symbol in requested_symbols
        )
        entry = {
            "address": address,
            "aliases": aliases,
            "alignment": definition["alignment"] if definition is not None else None,
            "alignment_source": (
                definition["alignment_source"]
                if definition is not None
                else None
            ),
            "comment": str(row["comment"]),
            "definition_state": (
                _data_definition_state(definition)
                if definition is not None
                else "unknown"
            ),
            "initializer_hex": (
                definition["initializer_hex"]
                if definition is not None
                else None
            ),
            "initializer_source": (
                definition["initializer_source"]
                if definition is not None
                else None
            ),
            "initializer_target": (
                definition["initializer_target"]
                if definition is not None
                else None
            ),
            "linker_reference_count": linker_reference_count,
            "name": str(row["name"]),
            "section": section,
            "section_offset": address - segment[1] if segment is not None else None,
            "section_source": _repo_relative(segments_path, repo_root=repo_root),
            "size": definition["size"] if definition is not None else None,
            "size_source": (
                definition["size_source"]
                if definition is not None
                else None
            ),
            "type": type_name,
        }
        if definition is not None and definition["definition_group"]:
            entry["definition_group"] = definition["definition_group"]
        if definition is not None and definition["initializer_fill"] is not None:
            entry["initializer_fill"] = definition["initializer_fill"]
        entries.append(entry)
    unmatched_definition_keys = set(definitions_by_key) - matched_definition_keys
    if unmatched_definition_keys:
        rendered = ", ".join(
            f"{name}@0x{address:08x}"
            for address, name in sorted(unmatched_definition_keys)
        )
        raise ValueError(
            f"{resolved_definitions_path}: definitions absent from data map: {rendered}",
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
    priorities = [
        {
            "address": entry["address"],
            "definition_state": entry["definition_state"],
            "name": entry["name"],
            "reference_count": entry["linker_reference_count"],
            "requested_symbols": sorted(
                closure_references[
                    (int(entry["address"]), str(entry["name"]))
                ],
                key=lambda item: (
                    -int(item["reference_count"]),
                    str(item["name"]),
                ),
            ),
        }
        for entry in sorted(
            (
                entry
                for entry in entries
                if entry["linker_reference_count"]
            ),
            key=lambda item: (
                -int(item["linker_reference_count"]),
                int(item["address"]),
                str(item["name"]),
            ),
        )[:50]
    ]
    source = {
        "data_map": _repo_relative(data_map_path, repo_root=repo_root),
        "data_map_sha256": _sha256(data_map_path),
        "segments": _repo_relative(segments_path, repo_root=repo_root),
        "segments_sha256": _sha256(segments_path),
    }
    if definitions is not None:
        source["definitions"] = _repo_relative(
            resolved_definitions_path,
            repo_root=repo_root,
        )
        source["definitions_sha256"] = _sha256(resolved_definitions_path)
        source["reference_image"] = definitions["reference_image"]

    return {
        "entries": entries,
        "image": image,
        "kind": NATIVE_DATA_MANIFEST_KIND,
        "notes": str(payload.get("notes") or ""),
        "overlays": overlays,
        "priorities": priorities,
        "schema": NATIVE_DATA_MANIFEST_SCHEMA,
        "source": source,
        "summary": {
            "alias_names": alias_names,
            "alias_rows": alias_rows,
            "entry_count": len(entries),
            "explicit_alignment_entries": sum(
                entry["alignment"] is not None
                for entry in entries
            ),
            "definition_group_entries": sum(
                bool(entry.get("definition_group"))
                for entry in entries
            ),
            "definition_groups": len(
                {
                    str(entry["definition_group"])
                    for entry in entries
                    if entry.get("definition_group")
                },
            ),
            "explicit_initializer_entries": sum(
                entry["initializer_hex"] is not None
                or entry.get("initializer_fill") is not None
                or entry.get("initializer_target") is not None
                for entry in entries
            ),
            "explicit_size_entries": sum(
                entry["size"] is not None
                for entry in entries
            ),
            "fixed_array_types": fixed_arrays,
            "fully_specified_entries": sum(
                entry["definition_state"] == "fully-specified"
                for entry in entries
            ),
            "game_data_reference_count": sum(
                int(entry["linker_reference_count"])
                for entry in entries
            ),
            "incomplete_array_types": incomplete_arrays,
            "multidimensional_array_types": multidimensional_arrays,
            "overlay_addresses": len(overlays),
            "priority_entries": len(priorities),
            "referenced_entries": sum(
                bool(entry["linker_reference_count"])
                for entry in entries
            ),
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
    translation_unit_configs: dict[str, Path] | None = None,
) -> NativeAudit:
    analysis_inputs_before = _analysis_input_snapshot(
        image,
        scope,
        translation_unit_configs=translation_unit_configs,
    )
    objects = build_native_object_set(
        image,
        scope=scope,
        match_root=match_root,
        jobs=jobs,
        translation_unit_configs=translation_unit_configs,
    )
    preliminary_symbol_closure = symbol_closure_payload(
        objects,
        repo_root=repo_root,
    )
    data_object = build_native_data_object(
        image,
        symbol_closure=preliminary_symbol_closure,
        reference_image_path=objects.image_path,
    )
    if data_object is not None:
        objects = replace(objects, data_records=(data_object,))
    object_manifest = object_manifest_payload(objects, repo_root=repo_root)
    symbol_closure = symbol_closure_payload(objects, repo_root=repo_root)
    data_manifest = data_manifest_payload(
        image,
        reference_image_path=objects.image_path,
        symbol_closure=symbol_closure,
        repo_root=repo_root,
    )
    object_list = render_object_list(objects, repo_root=repo_root)
    export_definition = render_export_definition(image, symbol_closure)
    object_manifest["object_list_sha256"] = hashlib.sha256(object_list.encode()).hexdigest()
    symbol_closure["export_definition_sha256"] = hashlib.sha256(
        export_definition.encode(),
    ).hexdigest()
    if analysis_inputs_before != _analysis_input_snapshot(
        image,
        scope,
        translation_unit_configs=translation_unit_configs,
    ):
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
