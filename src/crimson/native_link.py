from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import struct
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

from . import match as matchlib
from . import match_toolchain

NATIVE_OBJECT_MANIFEST_SCHEMA = 2
NATIVE_SYMBOL_CLOSURE_SCHEMA = 2
NATIVE_DATA_MANIFEST_SCHEMA = 1
NATIVE_DATA_DEFINITION_SCHEMA = 1
NATIVE_TRANSLATION_UNIT_SCHEMA = 1
NATIVE_LINKER_ALIAS_SCHEMA = 1
NATIVE_PROVIDER_SCHEMA = 3
NATIVE_LINK_MANIFEST_SCHEMA = 3

NATIVE_OBJECT_MANIFEST_KIND = "crimson-native-object-manifest"
NATIVE_SYMBOL_CLOSURE_KIND = "crimson-native-symbol-closure"
NATIVE_DATA_MANIFEST_KIND = "crimson-native-data-manifest"
NATIVE_DATA_DEFINITION_KIND = "crimson-native-data-definitions"
NATIVE_LINKER_ALIAS_KIND = "crimson-native-linker-aliases"
NATIVE_LINK_MANIFEST_KIND = "crimson-native-linked-image"

IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
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
KNOWN_MSVC_CRT_EXTERNALS = frozenset(
    {
        "_sscanf",
    },
)
KNOWN_MSVC_CRT_DEFAULT_LIBRARIES = frozenset(
    {
        "libc",
        "libcd",
        "libcmt",
        "libcmtd",
        "msvcrt",
        "msvcrtd",
    },
)

DEFAULT_NATIVE_ANALYSIS_ROOT = matchlib.REPO_ROOT / "analysis" / "native"
DEFAULT_DATA_DEFINITION_ROOT = (
    matchlib.REPO_ROOT / "tools" / "native" / "data_definitions"
)
DEFAULT_DATA_OBJECT_BUILD_ROOT = DEFAULT_DATA_DEFINITION_ROOT / "build"
DEFAULT_LINKER_ALIAS_ROOT = (
    matchlib.REPO_ROOT / "tools" / "native" / "linker_aliases"
)
DEFAULT_LINKER_ALIAS_OBJECT_BUILD_ROOT = DEFAULT_LINKER_ALIAS_ROOT / "build"
DEFAULT_PROVIDER_ROOT = matchlib.REPO_ROOT / "tools" / "native" / "providers"
DEFAULT_PROVIDER_BUILD_ROOT = DEFAULT_PROVIDER_ROOT / "build"
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
DEFAULT_LINKER_ALIAS_CONFIGS = {
    "grim.dll": DEFAULT_LINKER_ALIAS_ROOT / "grim.dll.json",
}
DEFAULT_PROVIDER_CONFIGS = {
    "crimsonland.exe": DEFAULT_PROVIDER_ROOT / "crimsonland.exe.json",
    "grim.dll": DEFAULT_PROVIDER_ROOT / "grim.dll.json",
}


def default_native_data_definitions_path(image: str) -> Path:
    return DEFAULT_DATA_DEFINITION_ROOT / f"{image}.json"


def default_native_data_object_path(image: str) -> Path:
    return DEFAULT_DATA_OBJECT_BUILD_ROOT / image / "definitions.obj"


def default_native_linker_alias_object_path(image: str) -> Path:
    return DEFAULT_LINKER_ALIAS_OBJECT_BUILD_ROOT / image / "aliases.obj"


def default_native_provider_placeholder_object_path(image: str) -> Path:
    return DEFAULT_PROVIDER_BUILD_ROOT / image / "placeholders.obj"


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
class NativeLinkerAliasSpec:
    alias: str
    target: str
    target_address: int
    reference_function: str
    reference_callsites: tuple[int, ...]
    evidence: str


@dataclass(frozen=True, slots=True)
class NativeLinkerAliasConfig:
    image: str
    path: Path
    sha256: str
    aliases: tuple[NativeLinkerAliasSpec, ...]


@dataclass(frozen=True, slots=True)
class NativeProviderEvidence:
    path: Path
    note: str


@dataclass(frozen=True, slots=True)
class NativeProviderArchiveProvenance:
    path: Path
    source_artifact: str | None = None
    member: str | None = None
    derived_artifact: str | None = None


@dataclass(frozen=True, slots=True)
class NativeProviderArchiveSpec:
    id: str
    path: Path
    sha256: str
    size: int
    provenance: NativeProviderArchiveProvenance


@dataclass(frozen=True, slots=True)
class NativeProviderAliasSpec:
    alias: str
    target: str


@dataclass(frozen=True, slots=True)
class NativeProviderSymbol:
    name: str
    binding: str | None = None
    link_name: str | None = None
    export: str | None = None
    ordinal: int | None = None


@dataclass(frozen=True, slots=True)
class NativeProviderSpec:
    name: str
    scope: str
    kind: str
    resolution: str
    module: str | None
    archive: NativeProviderArchiveSpec | None
    aliases: tuple[NativeProviderAliasSpec, ...]
    evidence: tuple[NativeProviderEvidence, ...]
    symbols: tuple[NativeProviderSymbol, ...]


@dataclass(frozen=True, slots=True)
class NativeProviderConfig:
    image: str
    path: Path
    sha256: str
    entry: str
    entry_aliases: tuple[NativeProviderAliasSpec, ...]
    image_base: int
    mode: str
    archives: tuple[NativeProviderArchiveSpec, ...]
    providers: tuple[NativeProviderSpec, ...]


def _native_provider_import_identity(symbol: NativeProviderSymbol) -> str:
    if symbol.ordinal is not None:
        return f"#{symbol.ordinal}"
    assert symbol.export is not None
    return symbol.export


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
    initializer_symbols: tuple[tuple[int, int, str], ...]
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
    target_name: str | None
    target_symbol: str | None


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
class NativeLinkerAliasObjectRecord:
    object_path: Path
    coff: matchlib.CoffObject
    config_path: Path
    config_sha256: str
    object_sha256: str
    aliases: tuple[NativeLinkerAliasSpec, ...]


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
    linker_alias_records: tuple[NativeLinkerAliasObjectRecord, ...] = ()
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


@dataclass(frozen=True, slots=True)
class NativeLinkedImageArtifacts:
    image: Path
    import_library: Path
    map_file: Path
    response_file: Path
    log: Path
    manifest: Path


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


def load_native_linker_alias_config(
    path: Path,
    *,
    image: str,
) -> NativeLinkerAliasConfig:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != NATIVE_LINKER_ALIAS_SCHEMA:
        raise ValueError(
            f"{path}: expected schema {NATIVE_LINKER_ALIAS_SCHEMA}",
        )
    if payload.get("kind") != NATIVE_LINKER_ALIAS_KIND:
        raise ValueError(
            f"{path}: expected kind {NATIVE_LINKER_ALIAS_KIND!r}",
        )
    if payload.get("image") != image:
        raise ValueError(f"{path}: targets {payload.get('image')!r}, expected {image!r}")

    raw_aliases = payload.get("aliases")
    if not isinstance(raw_aliases, list) or not raw_aliases:
        raise ValueError(f"{path}: aliases must be a non-empty list")
    aliases: list[NativeLinkerAliasSpec] = []
    alias_names: set[str] = set()
    for index, raw_alias in enumerate(raw_aliases):
        if not isinstance(raw_alias, dict):
            raise TypeError(f"{path}: aliases[{index}] must be an object")
        alias = raw_alias.get("alias")
        target = raw_alias.get("target")
        reference_function = raw_alias.get("reference_function")
        evidence = raw_alias.get("evidence")
        if not isinstance(alias, str) or not alias or "\x00" in alias:
            raise ValueError(f"{path}: aliases[{index}].alias must be a COFF symbol")
        if alias in alias_names:
            raise ValueError(f"{path}: duplicate linker alias {alias!r}")
        alias_names.add(alias)
        if not isinstance(target, str) or not target or "\x00" in target:
            raise ValueError(f"{path}: aliases[{index}].target must be a COFF symbol")
        if alias == target:
            raise ValueError(f"{path}: linker alias {alias!r} targets itself")
        if not isinstance(reference_function, str) or not reference_function:
            raise ValueError(
                f"{path}: aliases[{index}].reference_function must be non-empty",
            )
        if not isinstance(evidence, str) or not evidence:
            raise ValueError(f"{path}: aliases[{index}].evidence must be non-empty")
        raw_target_address = raw_alias.get("target_address")
        if not isinstance(raw_target_address, (str, int)):
            raise TypeError(
                f"{path}: aliases[{index}].target_address must be an integer",
            )
        try:
            target_address = matchlib.parse_int(raw_target_address)
        except ValueError as error:
            raise ValueError(
                f"{path}: aliases[{index}].target_address must be an integer",
            ) from error
        raw_callsites = raw_alias.get("reference_callsites")
        if not isinstance(raw_callsites, list) or not raw_callsites:
            raise ValueError(
                f"{path}: aliases[{index}].reference_callsites must be non-empty",
            )
        parsed_callsites: list[int] = []
        for callsite in raw_callsites:
            if not isinstance(callsite, (str, int)):
                raise TypeError(
                    f"{path}: aliases[{index}].reference_callsites "
                    "must contain integers",
                )
            try:
                parsed_callsites.append(matchlib.parse_int(callsite))
            except ValueError as error:
                raise ValueError(
                    f"{path}: aliases[{index}].reference_callsites "
                    "must contain integers",
                ) from error
        reference_callsites = tuple(parsed_callsites)
        if tuple(sorted(set(reference_callsites))) != reference_callsites:
            raise ValueError(
                f"{path}: aliases[{index}].reference_callsites must be sorted and unique",
            )
        aliases.append(
            NativeLinkerAliasSpec(
                alias=alias,
                target=target,
                target_address=target_address,
                reference_function=reference_function,
                reference_callsites=reference_callsites,
                evidence=evidence,
            ),
        )
    if tuple(sorted(alias.alias for alias in aliases)) != tuple(
        alias.alias
        for alias in aliases
    ):
        raise ValueError(f"{path}: aliases must be sorted by alias")
    return NativeLinkerAliasConfig(
        image=image,
        path=path.resolve(),
        sha256=_sha256(path),
        aliases=tuple(aliases),
    )


def load_native_provider_config(
    path: Path,
    *,
    image: str,
    repo_root: Path = matchlib.REPO_ROOT,
) -> NativeProviderConfig:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != NATIVE_PROVIDER_SCHEMA:
        raise ValueError(
            f"{path}: expected schema {NATIVE_PROVIDER_SCHEMA}",
        )
    if payload.get("image") != image:
        raise ValueError(f"{path}: targets {payload.get('image')!r}, expected {image!r}")
    entry = payload.get("entry")
    if not isinstance(entry, str) or not entry:
        raise ValueError(f"{path}: entry must be a non-empty string")
    raw_entry_aliases = payload.get("entry_aliases", [])
    if not isinstance(raw_entry_aliases, list):
        raise TypeError(f"{path}: entry_aliases must be a list")
    entry_aliases: list[NativeProviderAliasSpec] = []
    entry_alias_names: set[str] = set()
    for alias_index, raw_alias in enumerate(raw_entry_aliases):
        label = f"{path}: entry_aliases[{alias_index}]"
        if not isinstance(raw_alias, dict):
            raise TypeError(f"{label} must be an object")
        alias = raw_alias.get("alias")
        target = raw_alias.get("target")
        if not isinstance(alias, str) or not alias:
            raise ValueError(f"{label}.alias must be non-empty")
        if not isinstance(target, str) or not target:
            raise ValueError(f"{label}.target must be non-empty")
        for field_name, value in (("alias", alias), ("target", target)):
            try:
                value.encode("latin1")
            except UnicodeEncodeError as error:
                raise ValueError(f"{label}.{field_name} must be Latin-1") from error
        if alias == target:
            raise ValueError(f"{label} must map distinct symbols")
        if alias in entry_alias_names:
            raise ValueError(f"{path}: duplicate entry alias {alias!r}")
        entry_alias_names.add(alias)
        entry_aliases.append(NativeProviderAliasSpec(alias=alias, target=target))
    if tuple(sorted(alias.alias for alias in entry_aliases)) != tuple(
        alias.alias
        for alias in entry_aliases
    ):
        raise ValueError(f"{path}: entry_aliases must be sorted by alias")
    raw_image_base = payload.get("image_base")
    try:
        image_base = (
            int(raw_image_base, 0)
            if isinstance(raw_image_base, str)
            else int(raw_image_base)
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"{path}: image_base must be an integer") from error
    if image_base <= 0 or image_base > 0xFFFFFFFF:
        raise ValueError(f"{path}: image_base must fit a positive 32-bit address")
    mode = payload.get("mode")
    if mode != "structural":
        raise ValueError(f"{path}: mode must be 'structural'")
    raw_archives = payload.get("archives", [])
    if not isinstance(raw_archives, list):
        raise TypeError(f"{path}: archives must be a list")

    def repository_path(raw_path: object, *, label: str) -> Path:
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(f"{label} must be non-empty")
        relative_path = Path(raw_path)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(f"{label} must be repository-relative")
        return (repo_root / relative_path).resolve()

    archives: list[NativeProviderArchiveSpec] = []
    archives_by_id: dict[str, NativeProviderArchiveSpec] = {}
    for archive_index, raw_archive in enumerate(raw_archives):
        label = f"{path}: archives[{archive_index}]"
        if not isinstance(raw_archive, dict):
            raise TypeError(f"{label} must be an object")
        archive_id = raw_archive.get("id")
        if not isinstance(archive_id, str) or not archive_id:
            raise ValueError(f"{label}.id must be non-empty")
        if archive_id in archives_by_id:
            raise ValueError(f"{path}: duplicate archive id {archive_id!r}")
        archive_path = repository_path(
            raw_archive.get("path"),
            label=f"{label}.path",
        )
        archive_sha256 = raw_archive.get("sha256")
        if (
            not isinstance(archive_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is None
        ):
            raise ValueError(f"{label}.sha256 must be a lowercase SHA-256")
        raw_provenance = raw_archive.get("provenance")
        if not isinstance(raw_provenance, dict):
            raise TypeError(f"{label}.provenance must be an object")
        provenance_path = repository_path(
            raw_provenance.get("path"),
            label=f"{label}.provenance.path",
        )
        if not provenance_path.is_file():
            raise ValueError(
                f"{label}.provenance.path does not exist: "
                f"{raw_provenance.get('path')}",
            )
        provenance_payload = json.loads(provenance_path.read_text(encoding="utf-8"))
        source_artifact = raw_provenance.get("source_artifact")
        member = raw_provenance.get("member")
        derived_artifact = raw_provenance.get("derived_artifact")
        provenance_kinds = sum(
            (
                source_artifact is not None or member is not None,
                derived_artifact is not None,
            ),
        )
        if provenance_kinds != 1:
            raise ValueError(
                f"{label}.provenance must select one source member or derived artifact",
            )
        provenance_row: dict[str, Any]
        if derived_artifact is not None:
            if not isinstance(derived_artifact, str) or not derived_artifact:
                raise ValueError(f"{label}.provenance.derived_artifact must be non-empty")
            derived_rows = provenance_payload.get("derived_artifacts")
            if not isinstance(derived_rows, list):
                raise TypeError(f"{label}.provenance.path lacks derived_artifacts")
            matched_rows = [
                row
                for row in derived_rows
                if isinstance(row, dict) and row.get("id") == derived_artifact
            ]
            if len(matched_rows) != 1:
                raise ValueError(
                    f"{label}: provenance lacks unique derived artifact {derived_artifact!r}",
                )
            provenance_row = matched_rows[0]
            derived_path = repository_path(
                provenance_row.get("path"),
                label=f"{label}.derived_artifact.path",
            )
            if derived_path != archive_path:
                raise ValueError(
                    f"{label}: archive path disagrees with derived artifact path",
                )
            source_artifact = None
            member = None
        else:
            if not isinstance(source_artifact, str) or not source_artifact:
                raise ValueError(f"{label}.provenance.source_artifact must be non-empty")
            if not isinstance(member, str) or not member:
                raise ValueError(f"{label}.provenance.member must be non-empty")
            source_rows = provenance_payload.get("source_artifacts")
            if not isinstance(source_rows, list):
                raise TypeError(
                    f"{label}.provenance.path lacks source_artifacts",
                )
            source_row = next(
                (
                    row
                    for row in source_rows
                    if isinstance(row, dict) and row.get("id") == source_artifact
                ),
                None,
            )
            if source_row is None:
                raise ValueError(
                    f"{label}: provenance lacks source artifact {source_artifact!r}",
                )
            member_row = next(
                (
                    row
                    for row in source_row.get("members", [])
                    if isinstance(row, dict) and row.get("path") == member
                ),
                None,
            )
            if member_row is None:
                raise ValueError(
                    f"{label}: provenance lacks member {member!r}",
                )
            provenance_row = member_row
            derived_artifact = None
        if provenance_row.get("sha256") != archive_sha256:
            raise ValueError(
                f"{label}: archive SHA-256 disagrees with provenance artifact",
            )
        try:
            archive_size = int(provenance_row.get("size"))
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"{label}: provenance artifact size must be an integer",
            ) from error
        if archive_size <= 0:
            raise ValueError(f"{label}: provenance artifact size must be positive")
        if archive_path.exists():
            if not archive_path.is_file():
                raise ValueError(f"{label}.path is not a file: {archive_path}")
            if archive_path.stat().st_size != archive_size:
                raise ValueError(
                    f"{label}.path size does not match provenance: "
                    f"{archive_path.stat().st_size}/{archive_size}",
                )
            actual_sha256 = _sha256(archive_path)
            if actual_sha256 != archive_sha256:
                raise ValueError(
                    f"{label}.path SHA-256 mismatch: "
                    f"{actual_sha256}/{archive_sha256}",
                )
        archive = NativeProviderArchiveSpec(
            id=archive_id,
            path=archive_path,
            sha256=archive_sha256,
            size=archive_size,
            provenance=NativeProviderArchiveProvenance(
                path=provenance_path,
                source_artifact=source_artifact,
                member=member,
                derived_artifact=derived_artifact,
            ),
        )
        archives.append(archive)
        archives_by_id[archive_id] = archive
    raw_providers = payload.get("providers")
    if not isinstance(raw_providers, list) or not raw_providers:
        raise ValueError(f"{path}: providers must be a non-empty list")

    providers: list[NativeProviderSpec] = []
    provider_names: set[str] = set()
    symbol_names: set[str] = set()
    for provider_index, raw_provider in enumerate(raw_providers):
        label = f"{path}: providers[{provider_index}]"
        if not isinstance(raw_provider, dict):
            raise TypeError(f"{label} must be an object")
        name = raw_provider.get("name")
        scope = raw_provider.get("scope", "closure")
        kind = raw_provider.get("kind")
        resolution = raw_provider.get("resolution")
        module = raw_provider.get("module")
        archive_id = raw_provider.get("archive")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{label}.name must be non-empty")
        if name in provider_names:
            raise ValueError(f"{path}: duplicate provider name {name!r}")
        provider_names.add(name)
        if scope not in {"closure", "link-dependency"}:
            raise ValueError(f"{label}.scope is unsupported: {scope!r}")
        if kind not in {
            "platform-replaced",
            "reference-import",
            "static-library",
            "toolchain",
        }:
            raise ValueError(f"{label}.kind is unsupported: {kind!r}")
        if resolution not in {
            "archive-library",
            "import-library",
            "placeholder-object",
        }:
            raise ValueError(f"{label}.resolution is unsupported: {resolution!r}")
        if resolution == "import-library" and kind != "reference-import":
            raise ValueError(
                f"{label}: import-library resolution requires reference-import kind",
            )
        valid_link_dependency = (
            kind == "reference-import" and resolution == "import-library"
        ) or (
            kind in {"static-library", "toolchain"}
            and resolution in {"archive-library", "placeholder-object"}
        )
        if scope == "link-dependency" and not valid_link_dependency:
            raise ValueError(
                f"{label}: link-dependency scope requires either a "
                "reference-import import-library provider or an explicit "
                "static/toolchain archive or placeholder provider",
            )
        if kind == "reference-import":
            if not isinstance(module, str) or not module:
                raise ValueError(f"{label}.module must be non-empty")
        elif module is not None:
            raise ValueError(
                f"{label}.module is only valid for reference-import providers",
            )
        archive: NativeProviderArchiveSpec | None = None
        if resolution == "archive-library":
            if not isinstance(archive_id, str) or not archive_id:
                raise ValueError(
                    f"{label}.archive must name a configured archive",
                )
            archive = archives_by_id.get(archive_id)
            if archive is None:
                raise ValueError(f"{label}.archive is unknown: {archive_id!r}")
        elif archive_id is not None:
            raise ValueError(
                f"{label}.archive is only valid for archive-library providers",
            )

        raw_evidence = raw_provider.get("evidence")
        if not isinstance(raw_evidence, list) or not raw_evidence:
            raise ValueError(f"{label}.evidence must be a non-empty list")
        evidence: list[NativeProviderEvidence] = []
        for evidence_index, raw_row in enumerate(raw_evidence):
            evidence_label = f"{label}.evidence[{evidence_index}]"
            if not isinstance(raw_row, dict):
                raise TypeError(f"{evidence_label} must be an object")
            raw_path = raw_row.get("path")
            note = raw_row.get("note")
            if not isinstance(raw_path, str) or not raw_path:
                raise ValueError(f"{evidence_label}.path must be non-empty")
            relative_path = Path(raw_path)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(f"{evidence_label}.path must be repository-relative")
            evidence_path = repo_root / relative_path
            if not evidence_path.is_file():
                raise ValueError(f"{evidence_label}.path does not exist: {raw_path}")
            if not isinstance(note, str) or not note:
                raise ValueError(f"{evidence_label}.note must be non-empty")
            evidence.append(
                NativeProviderEvidence(
                    path=evidence_path.resolve(),
                    note=note,
                ),
            )

        raw_symbols = raw_provider.get("symbols")
        if not isinstance(raw_symbols, list) or not raw_symbols:
            raise ValueError(f"{label}.symbols must be a non-empty list")
        symbols: list[NativeProviderSymbol] = []
        for symbol_index, raw_symbol in enumerate(raw_symbols):
            symbol_label = f"{label}.symbols[{symbol_index}]"
            if not isinstance(raw_symbol, dict):
                raise TypeError(f"{symbol_label} must be an object")
            symbol_name = raw_symbol.get("name")
            if not isinstance(symbol_name, str) or not symbol_name:
                raise ValueError(f"{symbol_label}.name must be non-empty")
            try:
                symbol_name.encode("latin1")
            except UnicodeEncodeError as error:
                raise ValueError(f"{symbol_label}.name must be Latin-1") from error
            if symbol_name in symbol_names:
                raise ValueError(f"{path}: duplicate provider symbol {symbol_name!r}")
            symbol_names.add(symbol_name)
            binding = raw_symbol.get("binding")
            link_name = raw_symbol.get("link_name")
            export = raw_symbol.get("export")
            raw_ordinal = raw_symbol.get("ordinal")
            ordinal: int | None = None
            if kind == "reference-import":
                if binding is not None:
                    raise ValueError(
                        f"{symbol_label}.binding is invalid for a reference import",
                    )
                if not isinstance(link_name, str) or not link_name:
                    raise ValueError(f"{symbol_label}.link_name must be non-empty")
                if not isinstance(export, str) or not export:
                    raise ValueError(f"{symbol_label}.export must be non-empty")
                if raw_ordinal is not None:
                    if (
                        not isinstance(raw_ordinal, int)
                        or isinstance(raw_ordinal, bool)
                        or not 1 <= raw_ordinal <= 0xFFFF
                    ):
                        raise ValueError(
                            f"{symbol_label}.ordinal must fit a positive 16-bit integer",
                        )
                    ordinal = raw_ordinal
            else:
                if binding not in {"data", "function"}:
                    raise ValueError(
                        f"{symbol_label}.binding must be 'data' or 'function'",
                    )
                if (
                    link_name is not None
                    or export is not None
                    or raw_ordinal is not None
                ):
                    raise ValueError(
                        f"{symbol_label}: non-import symbols cannot declare import names",
                    )
            symbols.append(
                NativeProviderSymbol(
                    name=symbol_name,
                    binding=cast(str | None, binding),
                    link_name=cast(str | None, link_name),
                    export=cast(str | None, export),
                    ordinal=ordinal,
                ),
            )
        raw_aliases = raw_provider.get("aliases", [])
        if not isinstance(raw_aliases, list):
            raise TypeError(f"{label}.aliases must be a list")
        if raw_aliases and resolution not in {
            "archive-library",
            "import-library",
        }:
            raise ValueError(
                f"{label}.aliases require a library-backed provider",
            )
        aliases: list[NativeProviderAliasSpec] = []
        alias_names: set[str] = set()
        provider_symbol_names = {symbol.name for symbol in symbols}
        for alias_index, raw_alias in enumerate(raw_aliases):
            alias_label = f"{label}.aliases[{alias_index}]"
            if not isinstance(raw_alias, dict):
                raise TypeError(f"{alias_label} must be an object")
            alias_name = raw_alias.get("alias")
            target = raw_alias.get("target")
            if not isinstance(alias_name, str) or not alias_name:
                raise ValueError(f"{alias_label}.alias must be non-empty")
            if not isinstance(target, str) or not target:
                raise ValueError(f"{alias_label}.target must be non-empty")
            for field_name, value in (("alias", alias_name), ("target", target)):
                try:
                    value.encode("latin1")
                except UnicodeEncodeError as error:
                    raise ValueError(
                        f"{alias_label}.{field_name} must be Latin-1",
                    ) from error
            if alias_name not in provider_symbol_names:
                raise ValueError(
                    f"{alias_label}.alias must name a provider symbol",
                )
            if alias_name in alias_names:
                raise ValueError(f"{label}: duplicate alias {alias_name!r}")
            alias_names.add(alias_name)
            aliases.append(
                NativeProviderAliasSpec(
                    alias=alias_name,
                    target=target,
                ),
            )
        if tuple(sorted(alias.alias for alias in aliases)) != tuple(
            alias.alias for alias in aliases
        ):
            raise ValueError(f"{label}.aliases must be sorted by alias")
        providers.append(
            NativeProviderSpec(
                name=name,
                scope=cast(str, scope),
                kind=cast(str, kind),
                resolution=cast(str, resolution),
                module=cast(str | None, module),
                archive=archive,
                aliases=tuple(aliases),
                evidence=tuple(evidence),
                symbols=tuple(symbols),
            ),
        )
    return NativeProviderConfig(
        image=image,
        path=path.resolve(),
        sha256=_sha256(path),
        entry=entry,
        entry_aliases=tuple(entry_aliases),
        image_base=image_base,
        mode=mode,
        archives=tuple(archives),
        providers=tuple(providers),
    )


def native_provider_coverage(
    config: NativeProviderConfig,
    symbol_closure: dict[str, Any],
) -> dict[str, Any]:
    if symbol_closure.get("image") != config.image:
        raise ValueError(
            f"provider config targets {config.image!r}, "
            f"closure targets {symbol_closure.get('image')!r}",
        )
    raw_unresolved = symbol_closure.get("unresolved")
    if not isinstance(raw_unresolved, list):
        raise TypeError("closure unresolved must be an array")
    unresolved_by_name: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(raw_unresolved):
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise TypeError(f"closure unresolved[{index}] must name a symbol")
        unresolved_row = cast(dict[str, Any], row)
        name = str(unresolved_row["name"])
        if name in unresolved_by_name:
            raise ValueError(f"closure contains duplicate unresolved symbol {name!r}")
        unresolved_by_name[name] = unresolved_row
    closure_providers = tuple(
        provider
        for provider in config.providers
        if provider.scope == "closure"
    )
    dependency_providers = tuple(
        provider
        for provider in config.providers
        if provider.scope == "link-dependency"
    )
    provider_symbols = {
        symbol.name
        for provider in closure_providers
        for symbol in provider.symbols
    }
    dependency_symbols = {
        symbol.name
        for provider in dependency_providers
        for symbol in provider.symbols
    }
    missing = sorted(set(unresolved_by_name) - provider_symbols)
    unexpected = sorted(provider_symbols - set(unresolved_by_name))
    if missing or unexpected:
        raise ValueError(
            "provider coverage does not equal unresolved closure: "
            f"missing={missing} unexpected={unexpected}",
        )

    reference_imports = symbol_closure.get("reference_imports")
    if not isinstance(reference_imports, list):
        raise TypeError("closure reference_imports must be an array")
    import_keys = {
        (str(row.get("module", "")).casefold(), str(row.get("name", "")))
        for row in reference_imports
        if isinstance(row, dict)
    }
    normalized_import_keys = {
        (module.removesuffix(".dll"), export)
        for module, export in import_keys
    }
    reference_modules = {module for module, _ in normalized_import_keys}
    provider_rows: list[dict[str, Any]] = []
    for provider in config.providers:
        if provider.kind == "reference-import":
            assert provider.module is not None
            module = provider.module.removesuffix(".dll").casefold()
            if (
                provider.scope == "link-dependency"
                and module not in reference_modules
            ):
                raise ValueError(
                    f"{provider.name}: link-dependency module "
                    f"{provider.module!r} is absent from reference imports",
                )
            for symbol in provider.symbols:
                assert symbol.export is not None
                key = (module, symbol.export)
                if (
                    provider.scope == "closure"
                    and key not in normalized_import_keys
                ):
                    raise ValueError(
                        f"{provider.name}: {symbol.name!r} lacks reference import "
                        f"{provider.module}!{symbol.export}",
                    )
        if provider.scope == "link-dependency":
            provider_rows.append(
                {
                    "kind": provider.kind,
                    "name": provider.name,
                    "resolution": provider.resolution,
                    "scope": provider.scope,
                    "symbol_count": len(provider.symbols),
                    **(
                        {"alias_count": len(provider.aliases)}
                        if provider.aliases
                        else {}
                    ),
                },
            )
            continue
        for symbol in provider.symbols:
            unresolved = unresolved_by_name[symbol.name]
            catalog = unresolved.get("catalog")
            if not isinstance(catalog, list):
                raise TypeError(f"closure catalog for {symbol.name!r} must be an array")
            dispositions = {
                row.get("disposition")
                for row in catalog
                if isinstance(row, dict)
            }
            if (
                provider.kind == "platform-replaced"
                and "platform-replaced" not in dispositions
            ):
                raise ValueError(
                    f"{provider.name}: {symbol.name!r} is not cataloged platform-replaced",
                )
            if (
                provider.kind == "toolchain"
                and unresolved.get("category") != "toolchain"
            ):
                raise ValueError(
                    f"{provider.name}: {symbol.name!r} is not categorized toolchain",
                )
        provider_rows.append(
            {
                "kind": provider.kind,
                "name": provider.name,
                "resolution": provider.resolution,
                "scope": provider.scope,
                "symbol_count": len(provider.symbols),
                **(
                    {"archive": provider.archive.id}
                    if provider.archive is not None
                    else {}
                ),
                **(
                    {"alias_count": len(provider.aliases)}
                    if provider.aliases
                    else {}
                ),
            },
        )
    import_count = sum(
        len(provider.symbols)
        for provider in closure_providers
        if provider.kind == "reference-import"
    )
    import_export_count = len(
        {
            (
                cast(str, provider.module).casefold().removesuffix(".dll"),
                _native_provider_import_identity(symbol),
            )
            for provider in closure_providers
            if provider.kind == "reference-import"
            for symbol in provider.symbols
        },
    )
    generated_import_count = sum(
        len(provider.symbols)
        for provider in closure_providers
        if provider.resolution == "import-library"
    )
    archive_count = sum(
        len(provider.symbols)
        for provider in closure_providers
        if provider.resolution == "archive-library"
    )
    closure_placeholder_count = sum(
        len(provider.symbols)
        for provider in closure_providers
        if provider.resolution == "placeholder-object"
    )
    link_dependency_placeholder_count = sum(
        len(provider.symbols)
        for provider in dependency_providers
        if provider.resolution == "placeholder-object"
    )
    placeholder_count = (
        closure_placeholder_count + link_dependency_placeholder_count
    )
    if generated_import_count + archive_count + closure_placeholder_count != len(
        provider_symbols,
    ):
        raise ValueError("provider resolution counts do not cover every symbol")
    return {
        "archive_symbols": archive_count,
        "closure_placeholder_symbols": closure_placeholder_count,
        "covered_symbols": len(provider_symbols),
        "generated_import_symbols": generated_import_count,
        "import_exports": import_export_count,
        "import_symbols": import_count,
        "link_dependency_placeholder_symbols": (
            link_dependency_placeholder_count
        ),
        "link_dependency_symbols": len(dependency_symbols),
        "placeholder_symbols": placeholder_count,
        "providers": provider_rows,
        "runnable": placeholder_count == 0,
    }


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


def _program_projected_file_payload(
    path: Path,
    image: str,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    payload = _file_payload(path, repo_root=repo_root)
    payload["sha256"] = matchlib.native_json_program_sha256(path, image)
    payload["projection"] = {
        "kind": matchlib.NATIVE_JSON_PROGRAM_PROJECTION,
        "program": image,
    }
    return payload


def _native_analysis_file_payload(
    path: Path,
    image: str,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    projected_paths = {
        matchlib.DEFAULT_DATA_MAP_PATH.resolve(),
        matchlib.DEFAULT_NAME_MAP_PATH.resolve(),
    }
    if path.resolve() in projected_paths:
        return _program_projected_file_payload(
            path,
            image,
            repo_root=repo_root,
        )
    return _file_payload(path, repo_root=repo_root)


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
                sha256=match_toolchain.tree_set_sha256(compiler_root, included_trees),
            ),
        )
    cl_wrapper = (match_root / "cl.sh").resolve()
    wibo = match_toolchain.resolve_wibo_path(match_root)
    assert wibo is not None
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
    linker_alias_configs: dict[str, Path] | None = None,
) -> tuple[tuple[Path, str], ...]:
    image_path, functions_path, metadata_path = _image_paths(image)
    paths = [
        Path(matchlib.__file__),
        Path(matchlib.match_process.__file__),
        Path(match_toolchain.__file__),
        Path(__file__),
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
    resolved_linker_alias_configs = (
        DEFAULT_LINKER_ALIAS_CONFIGS
        if linker_alias_configs is None
        else linker_alias_configs
    )
    if linker_alias_config := resolved_linker_alias_configs.get(image):
        paths.append(linker_alias_config)
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


def _load_image_linker_alias_config(
    image: str,
    *,
    linker_alias_configs: dict[str, Path] | None,
) -> NativeLinkerAliasConfig | None:
    resolved_configs = (
        DEFAULT_LINKER_ALIAS_CONFIGS
        if linker_alias_configs is None
        else linker_alias_configs
    )
    path = resolved_configs.get(image)
    if path is None:
        return None
    return load_native_linker_alias_config(path, image=image)


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
        body_byte_exact=result.body_byte_exact,
        target_padding_bytes=result.target_padding_bytes,
        candidate_padding_bytes=result.candidate_padding_bytes,
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
    linker_alias_configs: dict[str, Path] | None = None,
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
    linker_aliases = _load_image_linker_alias_config(
        image,
        linker_alias_configs=linker_alias_configs,
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
            object_extent=status.config.archive_extent,
            object_end_symbol=status.config.archive_end_symbol,
            object_size=status.config.archive_size,
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
        object_function = matchlib.extract_object_function(
            coff,
            status.config.symbol,
            extent=status.config.archive_extent,
            end_symbol=status.config.archive_end_symbol,
            size=status.config.archive_size,
        )
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
    linker_alias_records: tuple[NativeLinkerAliasObjectRecord, ...] = ()
    if linker_aliases is not None:
        linker_alias_records = (
            build_native_linker_alias_object(
                linker_aliases,
                records=tuple(records),
                manifest=manifest,
                reference_image_path=image_path,
            ),
        )
        if _sha256(linker_aliases.path) != linker_aliases.sha256:
            raise ValueError("linker-alias config changed during native audit")
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
        linker_alias_records=linker_alias_records,
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
        "body_byte_exact": status.body_byte_exact,
        "padding_bytes": {"target": status.target_padding_bytes, "candidate": status.candidate_padding_bytes},
        "ratio": status.ratio,
        "state": status.state,
        "target_instructions": status.target_instructions,
    }


def _function_binding_payload(
    binding: NativeFunctionBinding,
    *,
    repo_root: Path,
    match_root: Path,
) -> dict[str, Any]:
    config = binding.status.config
    config_path = config.directory / "scratch.conf"
    source_path = config.directory / config.source
    return {
        "address": binding.function.address,
        "experiment_epoch": matchlib.scratch_experiment_epoch(config, match_root),
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
                _function_binding_payload(binding, repo_root=repo_root, match_root=objects.match_root)
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
                    **(
                        {
                            "initializer_symbols": [
                                {
                                    "offset": offset,
                                    "address": address,
                                    "symbol": symbol,
                                }
                                for offset, address, symbol in (
                                    binding.initializer_symbols
                                )
                            ],
                        }
                        if binding.initializer_symbols
                        else {}
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
    linker_alias_records = [
        {
            "aliases": [
                {
                    "alias": alias.alias,
                    "evidence": alias.evidence,
                    "reference_callsites": list(alias.reference_callsites),
                    "reference_function": alias.reference_function,
                    "target": alias.target,
                    "target_address": alias.target_address,
                }
                for alias in record.aliases
            ],
            "config": _repo_relative(record.config_path, repo_root=repo_root),
            "config_sha256": record.config_sha256,
            "object": _repo_relative(record.object_path, repo_root=repo_root),
            "object_sha256": record.object_sha256,
        }
        for record in objects.linker_alias_records
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
        Path(matchlib.__file__),
        Path(matchlib.match_process.__file__),
        Path(match_toolchain.__file__),
        Path(__file__),
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
    selection_input_paths.extend(
        sorted(
            {
                record.config_path
                for record in objects.linker_alias_records
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
    if linker_alias_records:
        build_policy = f"{build_policy}-and-linker-aliases"

    return {
        "abi_assertions": abi,
        "data_object_count": len(data_records),
        "data_objects": data_records,
        "function_count": len(bindings),
        "image": objects.image,
        "kind": NATIVE_OBJECT_MANIFEST_KIND,
        "linker_alias_object_count": len(linker_alias_records),
        "linker_alias_objects": linker_alias_records,
        "object_count": (
            len(records)
            + len(data_records)
            + len(linker_alias_records)
        ),
        "object_order": (
            "ascending-minimum-reference-address-then-generated-data-"
            "then-linker-aliases"
        ),
        "object_hash": {
            "algorithm": "sha256",
            "normalization": ["zero COFF TimeDateStamp bytes 4..7"],
        },
        "objects": records,
        "provenance": {
            "build_policy": build_policy,
            "selection_inputs": [
                _native_analysis_file_payload(
                    path,
                    objects.image,
                    repo_root=repo_root,
                )
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
    lines.extend(
        _repo_relative(record.object_path, repo_root=repo_root)
        for record in objects.linker_alias_records
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


def _data_map_entry_kind(row: dict[str, Any]) -> str:
    kind = str(row.get("kind") or "data")
    if kind not in {"code_label", "data"}:
        raise ValueError(f"unsupported data-map entry kind: {kind!r}")
    return kind


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
        for row in matchlib.load_name_map_rows(name_map_path):
            if row.get("program") != image:
                continue
            if bool(row.get("exclude")):
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
            if _data_map_entry_kind(row) != "data":
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
                ordinal = int(row.get("ordinal") or 0)
                detail = {
                    "address": matchlib.parse_int(row["address"]),
                    "module": module_name,
                    "name": name,
                }
                if ordinal:
                    detail["ordinal"] = ordinal
                _add_catalog_name(
                    imports,
                    name,
                    detail,
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


def _default_library_name(directive: str) -> str | None:
    match = re.match(r"(?i)^[-/]defaultlib:(.+)$", directive)
    if match is None:
        return None
    return match.group(1).strip('"')


def _msvc_toolchain_classification(
    name: str,
    references: list[dict[str, Any]],
    *,
    directives_by_object: dict[str, tuple[str, ...]],
) -> dict[str, Any] | None:
    if name in KNOWN_MSVC_TOOLCHAIN_EXTERNALS:
        return {"kind": "msvc-compiler-helper"}
    if name not in KNOWN_MSVC_CRT_EXTERNALS:
        return None

    requested: set[str] = set()
    for reference in references:
        object_name = str(reference["object"])
        for directive in directives_by_object.get(object_name, ()):
            library = _default_library_name(directive)
            if library is None:
                continue
            normalized = library.casefold().removesuffix(".lib")
            if normalized in KNOWN_MSVC_CRT_DEFAULT_LIBRARIES:
                requested.add(library)
    if not requested:
        return None
    return {
        "default_libraries": sorted(requested, key=str.casefold),
        "kind": "msvc-crt-default-library",
    }


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
    weak_alias_fallbacks: dict[str, set[str]] = defaultdict(set)
    weak_alias_objects: dict[str, set[str]] = defaultdict(set)

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
                        weak_alias_fallbacks[symbol.name].add(fallback.name)
                        weak_alias_objects[symbol.name].add(object_name)
                pending_undefined.append((symbol.name, alias_fallback, reference))

    for record in objects.data_records:
        object_name = _repo_relative(record.object_path, repo_root=repo_root)
        directives_by_object[object_name] = ()
        for symbol in record.coff.symbols:
            if symbol.storage_class != matchlib.IMAGE_SYM_CLASS_EXTERNAL:
                continue
            if symbol.section_number > 0 or (
                symbol.section_number == 0 and symbol.value > 0
            ):
                definitions[symbol.name].append(
                    _data_symbol_occurrence(
                        record,
                        symbol,
                        repo_root=repo_root,
                    ),
                )
            elif symbol.section_number == 0:
                pending_undefined.append(
                    (
                        symbol.name,
                        None,
                        {
                            "function": None,
                            "object": object_name,
                            "weak": False,
                        },
                    ),
                )

    for record in objects.linker_alias_records:
        object_name = _repo_relative(record.object_path, repo_root=repo_root)
        directives_by_object[object_name] = ()
        symbols_by_raw_index = {
            symbol.raw_index: symbol
            for symbol in record.coff.symbols
        }
        for symbol in record.coff.symbols:
            if symbol.storage_class not in (
                matchlib.IMAGE_SYM_CLASS_EXTERNAL,
                IMAGE_SYM_CLASS_WEAK_EXTERNAL,
            ):
                continue
            if symbol.section_number != 0 or symbol.value != 0:
                raise ValueError(
                    f"{record.object_path}: linker-alias object defines "
                    f"unexpected symbol {symbol.name!r}",
                )
            alias_fallback: str | None = None
            reference: dict[str, Any] = {
                "function": None,
                "linker_alias_object": True,
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
                    weak_alias_fallbacks[symbol.name].add(fallback.name)
                    weak_alias_objects[symbol.name].add(object_name)
            pending_undefined.append((symbol.name, alias_fallback, reference))

    conflicting_aliases = {
        alias: sorted(fallbacks)
        for alias, fallbacks in weak_alias_fallbacks.items()
        if len(fallbacks) != 1
    }
    if conflicting_aliases:
        raise ValueError(f"conflicting COFF weak aliases: {conflicting_aliases}")

    for primary_name, alias_fallback, reference in pending_undefined:
        reference_name = primary_name
        if primary_name not in definitions:
            global_fallbacks = weak_alias_fallbacks.get(primary_name, set())
            global_fallback = next(iter(global_fallbacks)) if global_fallbacks else None
            if (
                alias_fallback is not None
                and global_fallback is not None
                and alias_fallback != global_fallback
            ):
                raise ValueError(
                    f"COFF weak alias {primary_name!r} has inconsistent fallbacks",
                )
            resolved_fallback = alias_fallback or global_fallback
            if resolved_fallback is not None:
                if alias_fallback is not None:
                    reference["weak_alias"] = primary_name
                else:
                    reference["linker_alias"] = primary_name
                reference_name = resolved_fallback
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
        toolchain_evidence: dict[str, Any] | None = None
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
        elif toolchain_evidence := _msvc_toolchain_classification(
            name,
            references,
            directives_by_object=directives_by_object,
        ):
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
        unresolved_row = {
            "candidate_definitions": candidate_definitions,
            "catalog": list(detail),
            "category": category,
            "lookup_name": lookup_name,
            "name": name,
            "referenced_by": ordered_references,
        }
        if toolchain_evidence is not None:
            unresolved_row["classification_evidence"] = toolchain_evidence
        unresolved_rows.append(unresolved_row)

    default_libraries: dict[str, set[str]] = defaultdict(set)
    directive_rows: list[dict[str, Any]] = []
    for object_name, directives in sorted(directives_by_object.items()):
        if directives:
            directive_rows.append({"directives": list(directives), "object": object_name})
        for directive in directives:
            if library := _default_library_name(directive):
                default_libraries[library].add(object_name)
    default_library_rows = [
        {
            "name": name,
            "object_count": len(object_names),
            "objects": sorted(object_names),
        }
        for name, object_names in sorted(default_libraries.items(), key=lambda item: item[0].lower())
    ]
    linker_alias_rows = [
        {
            "alias": alias,
            "objects": sorted(weak_alias_objects[alias]),
            "target": next(iter(fallbacks)),
        }
        for alias, fallbacks in sorted(weak_alias_fallbacks.items())
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
                _native_analysis_file_payload(
                    path,
                    objects.image,
                    repo_root=repo_root,
                )
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
        "linker_aliases": linker_alias_rows,
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
            "object_count": (
                len(objects.records)
                + len(objects.data_records)
                + len(objects.linker_alias_records)
            ),
            "reference_exports_closed": reference_exports_closed,
            "resolved_symbols": len(resolved_rows),
            "unresolved_by_category": dict(sorted(unresolved_counts.items())),
            "unresolved_symbols": len(unresolved_rows),
        },
        "unresolved": unresolved_rows,
    }


def _symbol_initializer_bytes(
    size: int,
    symbols: list[dict[str, Any]],
) -> bytes:
    initializer = bytearray(size)
    for symbol in symbols:
        struct.pack_into(
            "<I",
            initializer,
            int(symbol["offset"]),
            int(symbol["address"]),
        )
    return bytes(initializer)


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
        "initializer_symbols",
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
        initializer_symbols = raw_entry.get("initializer_symbols")
        initializer_source = raw_entry.get("initializer_source")
        initializer_forms = sum(
            value is not None
            for value in (
                initializer_hex,
                initializer_fill,
                initializer_target,
                initializer_symbols,
            )
        )
        if initializer_forms > 1:
            raise ValueError(
                f"{label}: initializer_hex, initializer_fill, initializer_target, "
                "and initializer_symbols are mutually exclusive",
            )
        if initializer_forms == 0:
            if initializer_source is not None:
                raise ValueError(
                    f"{label}: initializer_source requires an initializer",
                )
            normalized["initializer_fill"] = None
            normalized["initializer_hex"] = None
            normalized["initializer_source"] = None
            normalized["initializer_symbols"] = []
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
            normalized["initializer_symbols"] = []
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
            if initializer_symbols is not None:
                if not isinstance(initializer_symbols, list) or not initializer_symbols:
                    raise ValueError(
                        f"{label}.initializer_symbols must be a non-empty array",
                    )
                normalized_symbols: list[dict[str, Any]] = []
                for symbol_index, raw_symbol in enumerate(initializer_symbols):
                    symbol_label = f"{label}.initializer_symbols[{symbol_index}]"
                    if (
                        not isinstance(raw_symbol, list)
                        or len(raw_symbol) != 3
                        or not isinstance(raw_symbol[0], (str, int))
                        or not isinstance(raw_symbol[1], (str, int))
                        or not isinstance(raw_symbol[2], str)
                        or not raw_symbol[2]
                    ):
                        raise ValueError(
                            f"{symbol_label} must be "
                            "[offset, address, non-empty symbol]",
                        )
                    try:
                        symbol_offset = matchlib.parse_int(raw_symbol[0])
                        symbol_address = matchlib.parse_int(raw_symbol[1])
                    except ValueError as exc:
                        raise ValueError(
                            f"{symbol_label} has an invalid offset or address",
                        ) from exc
                    normalized_symbols.append(
                        {
                            "offset": symbol_offset,
                            "address": symbol_address,
                            "symbol": raw_symbol[2],
                        },
                    )
                ordered_symbols = sorted(
                    normalized_symbols,
                    key=lambda item: (
                        int(item["offset"]),
                        int(item["address"]),
                        str(item["symbol"]),
                    ),
                )
                if normalized_symbols != ordered_symbols:
                    raise ValueError(
                        f"{label}.initializer_symbols must be sorted by offset",
                    )
                offsets = [int(item["offset"]) for item in normalized_symbols]
                if len(offsets) != len(set(offsets)):
                    raise ValueError(
                        f"{label}.initializer_symbols contains duplicate offsets",
                    )
                normalized["initializer_symbols"] = normalized_symbols
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
        normalized_symbols = normalized["initializer_symbols"]
        if normalized_symbols and size is None:
            raise ValueError(f"{label}: initializer_symbols requires an explicit size")
        for symbol in normalized_symbols:
            symbol_offset = int(symbol["offset"])
            if (
                symbol_offset < 0
                or symbol_offset % 4
                or size is None
                or symbol_offset + 4 > size
            ):
                raise ValueError(
                    f"{label}: initializer symbol offset {symbol_offset} "
                    "must be four-byte aligned and fit inside the entry",
                )
        initializer = (
            bytes.fromhex(initializer_hex)
            if initializer_hex is not None
            else bytes.fromhex(initializer_fill) * size
            if initializer_fill is not None and size is not None
            else struct.pack("<I", int(normalized_target["address"]))
            if normalized_target is not None
            else _symbol_initializer_bytes(int(size), normalized_symbols)
            if normalized_symbols and size is not None
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
                and not target_entry["initializer_symbols"]
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
        initializer_symbols = entry.get("initializer_symbols", [])
        if (
            size is None
            or alignment is None
            or (
                initializer_hex is None
                and initializer_fill is None
                and initializer_target is None
                and not initializer_symbols
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
            "initializer_symbols": tuple(
                (
                    int(symbol["offset"]),
                    int(symbol["address"]),
                    str(symbol["symbol"]),
                )
                for symbol in initializer_symbols
            ),
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
                    initializer_symbols=cast(
                        tuple[tuple[int, int, str], ...],
                        row["initializer_symbols"],
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
                        target_symbol=None,
                    ),
                )
            for symbol_offset, target_address, target_symbol in cast(
                tuple[tuple[int, int, str], ...],
                row["initializer_symbols"],
            ):
                relocations.append(
                    NativeDataRelocation(
                        section_offset=offset + symbol_offset,
                        target_address=target_address,
                        target_name=None,
                        target_symbol=target_symbol,
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
                initializer_symbols=(),
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

    defined_symbols: list[tuple[str, NativeDataBinding | None, int]] = sorted(
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
        (relocation.target_address, str(relocation.target_name))
        for region in regions
        for relocation in region.relocations
        if relocation.target_name is not None
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
    undefined_relocation_symbols = [
        (symbol, None, matchlib.IMAGE_SYM_CLASS_EXTERNAL)
        for symbol in sorted(
            {
                str(relocation.target_symbol)
                for region in regions
                for relocation in region.relocations
                if relocation.target_symbol is not None
            },
        )
    ]
    symbols: list[tuple[str, NativeDataBinding | None, int]] = sorted(
        defined_symbols + local_symbols + undefined_relocation_symbols,
        key=lambda item: item[0],
    )
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
            relocation_symbol = (
                str(relocation.target_symbol)
                if relocation.target_symbol is not None
                else local_symbol_by_key[
                    (
                        relocation.target_address,
                        str(relocation.target_name),
                    )
                ]
            )
            struct.pack_into(
                "<IIH",
                payload,
                relocation_offset + relocation_index * 10,
                relocation.section_offset,
                symbol_index_by_name[relocation_symbol],
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
                binding.section_offset if binding is not None else 0,
                binding.section_number if binding is not None else 0,
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
        for symbol, _, storage_class in symbols
        if storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
    }:
        raise ValueError("generated data object symbol table did not round-trip")
    parsed_symbols = {symbol.name: symbol for symbol in coff.symbols}
    for symbol, binding, storage_class in symbols:
        parsed = parsed_symbols[symbol]
        expected_section_number = binding.section_number if binding is not None else 0
        expected_value = binding.section_offset if binding is not None else 0
        if (
            parsed.section_number != expected_section_number
            or parsed.value != expected_value
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
            relocation_symbol = (
                str(expected.target_symbol)
                if expected.target_symbol is not None
                else local_symbol_by_key[
                    (
                        expected.target_address,
                        str(expected.target_name),
                    )
                ]
            )
            target_symbol = parsed_symbols[relocation_symbol]
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


def render_native_import_definition(provider: NativeProviderSpec) -> str:
    if provider.resolution != "import-library" or provider.module is None:
        raise ValueError(f"{provider.name}: expected an import-library provider")
    lines = [f"LIBRARY {provider.module}", "EXPORTS"]
    for symbol in provider.symbols:
        assert symbol.link_name is not None
        assert symbol.export is not None
        if symbol.ordinal is not None:
            entry = f"{symbol.link_name} @{symbol.ordinal} NONAME"
        elif symbol.export != symbol.link_name:
            entry = f"{symbol.link_name}={symbol.export}"
        else:
            entry = symbol.link_name
        lines.append(f"    {entry}")
    return "".join(f"{line}\n" for line in lines)


def native_provider_placeholder_object_bytes(
    providers: tuple[NativeProviderSpec, ...],
) -> bytes:
    symbols = sorted(
        (
            symbol
            for provider in providers
            if provider.resolution == "placeholder-object"
            for symbol in provider.symbols
        ),
        key=lambda symbol: symbol.name,
    )
    if not symbols:
        raise ValueError("provider placeholder object requires at least one symbol")
    if len({symbol.name for symbol in symbols}) != len(symbols):
        raise ValueError("provider placeholder object contains duplicate symbols")
    if any(symbol.binding not in {"function", "data"} for symbol in symbols):
        raise ValueError("provider placeholder symbols require function or data binding")

    section_rows: list[tuple[NativeProviderSymbol, str, bytes, int]] = []
    for symbol in symbols:
        if symbol.binding == "data":
            section_rows.append(
                (
                    symbol,
                    ".data",
                    b"\x00" * 4,
                    (
                        IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_LNK_COMDAT
                        | _coff_alignment_characteristic(4)
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE
                    ),
                ),
            )
            continue

        code = bytearray(b"\x31\xc0")
        stack_match = re.search(r"@([0-9]+)$", symbol.name)
        stack_bytes = int(stack_match.group(1)) if stack_match else 0
        if stack_bytes:
            if stack_bytes > 0xFFFF:
                raise ValueError(
                    f"placeholder function {symbol.name!r} stack size exceeds 16 bits",
                )
            code.extend(b"\xc2")
            code.extend(struct.pack("<H", stack_bytes))
        else:
            code.extend(b"\xc3")
        while len(code) % 4:
            code.extend(b"\x90")
        section_rows.append(
            (
                symbol,
                ".text",
                bytes(code),
                (
                    IMAGE_SCN_CNT_CODE
                    | IMAGE_SCN_LNK_COMDAT
                    | _coff_alignment_characteristic(16)
                    | IMAGE_SCN_MEM_EXECUTE
                    | IMAGE_SCN_MEM_READ
                ),
            ),
        )

    string_offsets: dict[str, int] = {}
    string_payload = bytearray()
    for symbol in symbols:
        encoded = symbol.name.encode("latin1")
        if len(encoded) <= 8:
            continue
        string_offsets[symbol.name] = 4 + len(string_payload)
        string_payload.extend(encoded)
        string_payload.append(0)
    string_table = struct.pack("<I", 4 + len(string_payload)) + string_payload

    section_table_end = 20 + len(section_rows) * 40
    cursor = section_table_end
    raw_offsets: list[int] = []
    for _, _, section_data, _ in section_rows:
        cursor = (cursor + 3) & ~3
        raw_offsets.append(cursor)
        cursor += len(section_data)
    symbol_table_offset = (cursor + 3) & ~3
    payload = bytearray(symbol_table_offset)
    struct.pack_into(
        "<HHIIIHH",
        payload,
        0,
        matchlib.IMAGE_FILE_MACHINE_I386,
        len(section_rows),
        0,
        symbol_table_offset,
        len(symbols) * 3,
        0,
        0,
    )
    for index, (
        (_, section_name, section_data, characteristics),
        raw_offset,
    ) in enumerate(
        zip(section_rows, raw_offsets, strict=True),
    ):
        header_offset = 20 + index * 40
        payload[header_offset : header_offset + 8] = section_name.encode().ljust(
            8,
            b"\x00",
        )
        struct.pack_into(
            "<IIIIIIHHI",
            payload,
            header_offset + 8,
            0,
            0,
            len(section_data),
            raw_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )
        payload[raw_offset : raw_offset + len(section_data)] = section_data

    section_number_by_symbol: dict[str, int] = {}
    for section_number, (symbol, section_name, section_data, _) in enumerate(
        section_rows,
        start=1,
    ):
        section_number_by_symbol[symbol.name] = section_number
        payload.extend(
            struct.pack(
                "<8sIhHBB",
                section_name.encode().ljust(8, b"\x00"),
                0,
                section_number,
                0,
                matchlib.IMAGE_SYM_CLASS_STATIC,
                1,
            ),
        )
        payload.extend(
            struct.pack(
                "<IHHIhB3x",
                len(section_data),
                0,
                0,
                0,
                0,
                2,
            ),
        )
        encoded = symbol.name.encode("latin1")
        name_field = (
            encoded.ljust(8, b"\x00")
            if len(encoded) <= 8
            else struct.pack("<II", 0, string_offsets[symbol.name])
        )
        payload.extend(name_field)
        symbol_type = 0x20 if symbol.binding == "function" else 0
        payload.extend(
            struct.pack(
                "<IhHBB",
                0,
                section_number,
                symbol_type,
                matchlib.IMAGE_SYM_CLASS_EXTERNAL,
                0,
            ),
        )
    payload.extend(string_table)

    object_data = bytes(payload)
    coff = matchlib.parse_coff_object(object_data)
    parsed = {
        symbol.name: symbol
        for symbol in coff.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL
    }
    if set(parsed) != {symbol.name for symbol in symbols}:
        raise ValueError("generated provider placeholder symbols did not round-trip")
    for symbol in symbols:
        parsed_symbol = parsed[symbol.name]
        if parsed_symbol.section_number != section_number_by_symbol[symbol.name]:
            raise ValueError(
                f"generated provider placeholder {symbol.name!r} has wrong section",
            )
        section = coff.sections[parsed_symbol.section_number - 1]
        if section.comdat_key != symbol.name or section.comdat_selection != 2:
            raise ValueError(
                f"generated provider placeholder {symbol.name!r} is not a selectable COMDAT",
            )
    return object_data


def native_weak_alias_object_bytes(
    aliases: tuple[tuple[str, str], ...],
) -> bytes:
    if not aliases:
        raise ValueError("weak alias object requires at least one alias")
    if len({alias for alias, _ in aliases}) != len(aliases):
        raise ValueError("weak alias object contains duplicate aliases")

    targets = sorted({target for _, target in aliases})
    names = [*targets, *(alias for alias, _ in aliases)]
    string_offsets: dict[str, int] = {}
    string_payload = bytearray()
    for name in names:
        try:
            encoded = name.encode("latin1")
        except UnicodeEncodeError as error:
            raise ValueError(f"COFF symbol {name!r} is not Latin-1") from error
        if len(encoded) <= 8 or name in string_offsets:
            continue
        string_offsets[name] = 4 + len(string_payload)
        string_payload.extend(encoded)
        string_payload.append(0)

    def symbol_name_field(name: str) -> bytes:
        encoded = name.encode("latin1")
        if len(encoded) <= 8:
            return encoded.ljust(8, b"\x00")
        return struct.pack("<II", 0, string_offsets[name])

    target_indices = {
        target: index
        for index, target in enumerate(targets)
    }
    symbol_count = len(targets) + len(aliases) * 2
    payload = bytearray(
        struct.pack(
            "<HHIIIHH",
            matchlib.IMAGE_FILE_MACHINE_I386,
            0,
            0,
            20,
            symbol_count,
            0,
            0,
        ),
    )
    for target in targets:
        payload.extend(symbol_name_field(target))
        payload.extend(
            struct.pack(
                "<IhHBB",
                0,
                0,
                0,
                matchlib.IMAGE_SYM_CLASS_EXTERNAL,
                0,
            ),
        )
    for alias, target in aliases:
        payload.extend(symbol_name_field(alias))
        payload.extend(
            struct.pack(
                "<IhHBB",
                0,
                0,
                0,
                IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                1,
            ),
        )
        payload.extend(
            struct.pack(
                "<II10x",
                target_indices[target],
                IMAGE_WEAK_EXTERN_SEARCH_ALIAS,
            ),
        )
    payload.extend(struct.pack("<I", 4 + len(string_payload)))
    payload.extend(string_payload)

    object_data = bytes(payload)
    coff = matchlib.parse_coff_object(object_data)
    parsed = {symbol.name: symbol for symbol in coff.symbols}
    if set(parsed) != set(names):
        raise ValueError("generated linker alias object symbol table did not round-trip")
    for target in targets:
        symbol = parsed[target]
        if (
            symbol.section_number != 0
            or symbol.storage_class != matchlib.IMAGE_SYM_CLASS_EXTERNAL
        ):
            raise ValueError(
                f"generated linker alias target {target!r} did not remain undefined",
            )
    for alias, target in aliases:
        symbol = parsed[alias]
        fallback = next(
            candidate
            for candidate in coff.symbols
            if candidate.raw_index == symbol.weak_default_symbol_index
        )
        if (
            symbol.storage_class != IMAGE_SYM_CLASS_WEAK_EXTERNAL
            or symbol.weak_search != IMAGE_WEAK_EXTERN_SEARCH_ALIAS
            or fallback.name != target
        ):
            raise ValueError(
                f"generated linker alias {alias!r} did not retain "
                f"fallback {target!r}",
            )
    return object_data


def native_linker_alias_object_bytes(
    aliases: tuple[NativeLinkerAliasSpec, ...],
) -> bytes:
    return native_weak_alias_object_bytes(
        tuple((alias.alias, alias.target) for alias in aliases),
    )


def _validate_native_linker_aliases(
    config: NativeLinkerAliasConfig,
    *,
    records: tuple[NativeObjectRecord, ...],
    manifest: matchlib.FunctionManifest,
    reference_image_path: Path,
) -> None:
    loaded_image = matchlib.load_image(reference_image_path, manifest.image_base)
    definitions: dict[str, list[NativeObjectRecord]] = defaultdict(list)
    references: dict[str, list[NativeObjectRecord]] = defaultdict(list)
    bindings_by_address_and_symbol: dict[
        tuple[int, str],
        list[tuple[NativeObjectRecord, NativeFunctionBinding]],
    ] = defaultdict(list)
    records_by_function: dict[str, list[NativeObjectRecord]] = defaultdict(list)
    for record in records:
        for binding in _record_bindings(record):
            bindings_by_address_and_symbol[
                (binding.function.address, binding.object_symbol)
            ].append((record, binding))
            records_by_function[binding.function.name].append(record)
        for symbol in record.coff.symbols:
            if symbol.storage_class not in (
                matchlib.IMAGE_SYM_CLASS_EXTERNAL,
                IMAGE_SYM_CLASS_WEAK_EXTERNAL,
            ):
                continue
            if symbol.section_number > 0 or (
                symbol.section_number == 0
                and symbol.value > 0
            ):
                definitions[symbol.name].append(record)
            elif symbol.section_number == 0:
                references[symbol.name].append(record)

    for alias in config.aliases:
        if definitions.get(alias.alias):
            raise ValueError(
                f"{config.path}: linker alias {alias.alias!r} already has a definition",
            )
        target_bindings = bindings_by_address_and_symbol.get(
            (alias.target_address, alias.target),
            [],
        )
        if len(target_bindings) != 1:
            raise ValueError(
                f"{config.path}: linker alias target {alias.target!r} must be the "
                f"unique selected function symbol at 0x{alias.target_address:08x}",
            )
        target_records = definitions.get(alias.target, [])
        if len(target_records) != 1 or target_records[0] is not target_bindings[0][0]:
            raise ValueError(
                f"{config.path}: linker alias target {alias.target!r} must have one "
                "exact COFF definition in its selected function object",
            )

        reference_function = manifest.by_name.get(alias.reference_function)
        if reference_function is None:
            raise ValueError(
                f"{config.path}: linker alias reference function "
                f"{alias.reference_function!r} is not in the active manifest",
            )
        reference_records = records_by_function.get(alias.reference_function, [])
        if len(reference_records) != 1:
            raise ValueError(
                f"{config.path}: linker alias reference function "
                f"{alias.reference_function!r} must bind to one object",
            )
        if reference_records[0] not in references.get(alias.alias, []):
            raise ValueError(
                f"{config.path}: {alias.reference_function!r} does not request "
                f"linker alias {alias.alias!r}",
            )

        for callsite in alias.reference_callsites:
            if not (
                reference_function.address
                <= callsite
                and callsite + 5 <= reference_function.end
            ):
                raise ValueError(
                    f"{config.path}: callsite 0x{callsite:08x} is outside "
                    f"{alias.reference_function}",
                )
            offset = callsite - loaded_image.image_base
            instruction = loaded_image.mapped[offset : offset + 5]
            if len(instruction) != 5 or instruction[0] != 0xE8:
                raise ValueError(
                    f"{config.path}: callsite 0x{callsite:08x} is not a direct call",
                )
            actual_target = (
                callsite
                + 5
                + struct.unpack_from("<i", instruction, 1)[0]
            )
            if actual_target != alias.target_address:
                raise ValueError(
                    f"{config.path}: callsite 0x{callsite:08x} targets "
                    f"0x{actual_target:08x}, expected 0x{alias.target_address:08x}",
                )


def build_native_linker_alias_object(
    config: NativeLinkerAliasConfig,
    *,
    records: tuple[NativeObjectRecord, ...],
    manifest: matchlib.FunctionManifest,
    reference_image_path: Path,
    output_path: Path | None = None,
) -> NativeLinkerAliasObjectRecord:
    _validate_native_linker_aliases(
        config,
        records=records,
        manifest=manifest,
        reference_image_path=reference_image_path,
    )
    object_data = native_linker_alias_object_bytes(config.aliases)
    resolved_output_path = (
        output_path
        if output_path is not None
        else default_native_linker_alias_object_path(config.image)
    )
    _write_bytes_atomic(resolved_output_path, object_data)
    return NativeLinkerAliasObjectRecord(
        object_path=resolved_output_path.resolve(),
        coff=matchlib.parse_coff_object(object_data),
        config_path=config.path,
        config_sha256=config.sha256,
        object_sha256=_normalized_coff_sha256(object_data),
        aliases=config.aliases,
    )


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
        or bool(entry.get("initializer_symbols"))
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
    program_rows = [
        row
        for row in payload.get("entries", [])
        if row.get("program") == image
    ]
    rows_by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in program_rows:
        rows_by_kind[_data_map_entry_kind(row)].append(row)
    source_rows = rows_by_kind["data"]

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
        if definition is not None and definition["initializer_symbols"]:
            entry["initializer_symbols"] = definition["initializer_symbols"]
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
        "data_map_sha256": matchlib.native_json_program_sha256(
            data_map_path,
            image,
        ),
        "data_map_projection": {
            "kind": matchlib.NATIVE_JSON_PROGRAM_PROJECTION,
            "program": image,
        },
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
            "code_label_entries": len(rows_by_kind["code_label"]),
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
                or bool(entry.get("initializer_symbols"))
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
            "source_entry_count": len(program_rows),
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
    linker_alias_configs: dict[str, Path] | None = None,
) -> NativeAudit:
    analysis_inputs_before = _analysis_input_snapshot(
        image,
        scope,
        translation_unit_configs=translation_unit_configs,
        linker_alias_configs=linker_alias_configs,
    )
    objects = build_native_object_set(
        image,
        scope=scope,
        match_root=match_root,
        jobs=jobs,
        translation_unit_configs=translation_unit_configs,
        linker_alias_configs=linker_alias_configs,
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
        linker_alias_configs=linker_alias_configs,
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


def normalize_coff_archive_timestamps(data: bytes) -> bytes:
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("expected a COFF archive")
    normalized = bytearray(data)
    offset = 8
    while offset < len(normalized):
        if offset + 60 > len(normalized):
            raise ValueError("truncated COFF archive member header")
        if normalized[offset + 58 : offset + 60] != b"`\n":
            raise ValueError("invalid COFF archive member header")
        raw_size = bytes(normalized[offset + 48 : offset + 58]).decode(
            "ascii",
            errors="strict",
        )
        try:
            member_size = int(raw_size.strip())
        except ValueError as error:
            raise ValueError("invalid COFF archive member size") from error
        normalized[offset + 16 : offset + 28] = b"0           "
        member_offset = offset + 60
        member_end = member_offset + member_size
        if member_end > len(normalized):
            raise ValueError("truncated COFF archive member")
        member = normalized[member_offset:member_end]
        if (
            len(member) >= 20
            and struct.unpack_from("<H", member, 0)[0]
            == matchlib.IMAGE_FILE_MACHINE_I386
        ):
            normalized[member_offset + 4 : member_offset + 8] = b"\x00" * 4
        elif len(member) >= 20 and member[0:4] == b"\x00\x00\xff\xff":
            normalized[member_offset + 8 : member_offset + 12] = b"\x00" * 4
        offset = member_end + (member_size & 1)
    if offset != len(normalized):
        raise ValueError("invalid COFF archive alignment")
    return bytes(normalized)


def normalize_pe_timestamp(data: bytes) -> bytes:
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError("expected a PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE header")
    normalized = bytearray(data)
    normalized[pe_offset + 8 : pe_offset + 12] = b"\x00" * 4
    _, section_count, _, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH",
        normalized,
        pe_offset + 4,
    )
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(normalized):
        raise ValueError("truncated PE optional header")
    if struct.unpack_from("<H", normalized, optional_offset)[0] != 0x10B:
        raise ValueError("expected a PE32 optional header")
    export_rva, export_size = struct.unpack_from(
        "<II",
        normalized,
        optional_offset + 96,
    )
    section_table_offset = optional_offset + optional_size
    if section_table_offset + section_count * 40 > len(normalized):
        raise ValueError("truncated PE section table")
    if export_rva and export_size >= 8:
        export_offset: int | None = None
        for index in range(section_count):
            section_offset = section_table_offset + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII",
                normalized,
                section_offset + 8,
            )
            section_size = max(virtual_size, raw_size)
            if virtual_address <= export_rva < virtual_address + section_size:
                export_offset = raw_offset + export_rva - virtual_address
                break
        if export_offset is None or export_offset + 8 > len(normalized):
            raise ValueError("PE export directory is outside mapped sections")
        normalized[export_offset + 4 : export_offset + 8] = b"\x00" * 4
    return bytes(normalized)


def native_pe_summary(data: bytes) -> dict[str, Any]:
    normalized = normalize_pe_timestamp(data)
    pe_offset = struct.unpack_from("<I", normalized, 0x3C)[0]
    machine, section_count, timestamp, _, _, optional_size, characteristics = (
        struct.unpack_from("<HHIIIHH", normalized, pe_offset + 4)
    )
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(normalized):
        raise ValueError("truncated PE optional header")
    magic = struct.unpack_from("<H", normalized, optional_offset)[0]
    if magic != 0x10B:
        raise ValueError(f"expected PE32 optional header, got 0x{magic:x}")
    entry_point = struct.unpack_from("<I", normalized, optional_offset + 16)[0]
    image_base = struct.unpack_from("<I", normalized, optional_offset + 28)[0]
    image_size = struct.unpack_from("<I", normalized, optional_offset + 56)[0]
    subsystem = struct.unpack_from("<H", normalized, optional_offset + 68)[0]
    return {
        "characteristics": characteristics,
        "dll": bool(characteristics & 0x2000),
        "entry_point_rva": entry_point,
        "image_base": image_base,
        "image_size": image_size,
        "machine": machine,
        "optional_magic": magic,
        "section_count": section_count,
        "subsystem": subsystem,
        "timestamp": timestamp,
    }


def native_pe_imports(data: bytes) -> dict[str, tuple[str, ...]]:
    try:
        import pefile
    except ModuleNotFoundError as error:
        raise RuntimeError("pefile is required to validate linked imports") from error

    pe = pefile.PE(data=data, fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ],
        )
        imports: dict[str, set[str]] = defaultdict(set)
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            module = descriptor.dll.decode("latin1").casefold().removesuffix(".dll")
            for imported in descriptor.imports:
                if imported.import_by_ordinal:
                    imports[module].add(f"#{int(imported.ordinal)}")
                elif imported.name is not None:
                    imports[module].add(imported.name.decode("latin1"))
        return {
            module: tuple(sorted(names))
            for module, names in sorted(imports.items())
        }
    finally:
        pe.close()


def _validate_linked_reference_imports(
    config: NativeProviderConfig,
    image_data: bytes,
    symbol_closure: dict[str, Any],
) -> dict[str, Any]:
    actual = native_pe_imports(image_data)
    expected: dict[str, set[str]] = defaultdict(set)
    dependencies: dict[str, set[str]] = defaultdict(set)
    for provider in config.providers:
        if provider.kind != "reference-import":
            continue
        assert provider.module is not None
        module = provider.module.casefold().removesuffix(".dll")
        target = (
            dependencies
            if provider.scope == "link-dependency"
            else expected
        )
        target[module].update(
            _native_provider_import_identity(symbol)
            for symbol in provider.symbols
        )
    missing = sorted(
        (module, symbol)
        for module, symbols in expected.items()
        for symbol in symbols
        if symbol not in actual.get(module, ())
    )
    if missing:
        rendered = ", ".join(
            f"{module}.dll!{symbol}"
            for module, symbol in missing
        )
        raise ValueError(
            f"linked PE is missing configured reference imports: {rendered}",
        )
    raw_reference_imports = symbol_closure.get("reference_imports")
    if not isinstance(raw_reference_imports, list):
        raise TypeError("closure reference_imports must be an array")
    reference = {
        (
            str(row.get("module", "")).casefold().removesuffix(".dll"),
            (
                f"#{int(row['ordinal'])}"
                if isinstance(row.get("ordinal"), int) and int(row["ordinal"]) > 0
                else str(row.get("name", ""))
            ),
        )
        for row in raw_reference_imports
        if isinstance(row, dict)
    }
    unexpected = sorted(
        (module, symbol)
        for module, symbols in actual.items()
        for symbol in symbols
        if (module, symbol) not in reference
    )
    if unexpected:
        rendered = ", ".join(
            f"{module}.dll!{symbol}"
            for module, symbol in unexpected
        )
        raise ValueError(
            f"linked PE imports symbols absent from the reference image: {rendered}",
        )
    dependency_rows = [
        {
            "declared_symbols": sorted(symbols),
            "discarded_symbols": sorted(symbols - set(actual.get(module, ()))),
            "module": module,
            "retained_symbols": sorted(symbols & set(actual.get(module, ()))),
        }
        for module, symbols in sorted(dependencies.items())
    ]
    return {
        "link_dependencies": dependency_rows,
        "link_dependency_retained_symbol_count": sum(
            len(row["retained_symbols"])
            for row in dependency_rows
        ),
        "modules": [
            {
                "module": module,
                "symbols": sorted(symbols),
            }
            for module, symbols in sorted(expected.items())
        ],
        "output_modules": [
            {
                "module": module,
                "symbols": list(symbols),
            }
            for module, symbols in sorted(actual.items())
        ],
        "output_symbol_count": sum(len(symbols) for symbols in actual.values()),
        "symbol_count": sum(len(symbols) for symbols in expected.values()),
    }


def _wibo_windows_path(path: Path) -> str:
    windows_path = str(path.resolve()).replace("/", "\\")
    return f"Z:{windows_path}"


def _provider_file_stem(name: str) -> str:
    stem = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
    if not stem:
        raise ValueError(f"provider name {name!r} has no usable file stem")
    return stem


def _native_linker_tools(objects: NativeObjectSet) -> tuple[Path, Path, Path]:
    if objects.toolchain is None:
        raise ValueError("native object set lacks a toolchain snapshot")
    candidates = [
        (
            bundle.root / "Bin" / "LIB.EXE",
            bundle.root / "Bin" / "LINK.EXE",
        )
        for bundle in objects.toolchain.compiler_bundles
        if (bundle.root / "Bin" / "LIB.EXE").is_file()
        and (bundle.root / "Bin" / "LINK.EXE").is_file()
    ]
    if len(candidates) != 1:
        raise ValueError(
            "native structural link requires exactly one compiler bundle with "
            f"LIB.EXE and LINK.EXE, found {len(candidates)}",
        )
    library_tool, linker = candidates[0]
    return objects.toolchain.wibo, library_tool, linker


def _run_native_tool(
    argv: list[str],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _native_provider_archive_payload(
    archive: NativeProviderArchiveSpec,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    if not archive.path.is_file():
        relative = _repo_relative(archive.path, repo_root=repo_root)
        raise ValueError(
            f"provider archive {archive.id!r} is missing at {relative}; "
            "extract the provenance-pinned source member before linking",
        )
    actual_size = archive.path.stat().st_size
    if actual_size != archive.size:
        raise ValueError(
            f"provider archive {archive.id!r} size mismatch: "
            f"{actual_size}/{archive.size}",
        )
    actual_sha256 = _sha256(archive.path)
    if actual_sha256 != archive.sha256:
        raise ValueError(
            f"provider archive {archive.id!r} SHA-256 mismatch: "
            f"{actual_sha256}/{archive.sha256}",
        )
    return {
        "file": _file_payload(archive.path, repo_root=repo_root),
        "id": archive.id,
        "provenance": {
            "manifest": _file_payload(
                archive.provenance.path,
                repo_root=repo_root,
            ),
            **(
                {"derived_artifact": archive.provenance.derived_artifact}
                if archive.provenance.derived_artifact is not None
                else {
                    "member": archive.provenance.member,
                    "source_artifact": archive.provenance.source_artifact,
                }
            ),
        },
    }


def _native_link_image_options(
    image: str,
    *,
    export_path: Path,
    import_library_path: Path,
) -> list[str]:
    suffix = Path(image).suffix.casefold()
    if suffix == ".dll":
        return [
            "/dll",
            f"/implib:{_wibo_windows_path(import_library_path)}",
            f"/def:{_wibo_windows_path(export_path)}",
        ]
    if suffix == ".exe":
        return ["/subsystem:windows"]
    raise ValueError(f"native link does not support image kind {image!r}")


_NATIVE_LINK_MAP_SYMBOL = re.compile(
    r"^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)",
    re.MULTILINE,
)


def _native_link_map_public_symbols(map_text: str) -> frozenset[str]:
    return frozenset(_NATIVE_LINK_MAP_SYMBOL.findall(map_text))


def link_native_image(
    audit: NativeAudit,
    provider_config: NativeProviderConfig,
    output_directory: Path,
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> tuple[NativeLinkedImageArtifacts, dict[str, Any]]:
    closure_summary = audit.symbol_closure.get("summary")
    if not isinstance(closure_summary, dict):
        raise TypeError("native closure summary must be an object")
    if not closure_summary.get("game_owned_closure"):
        raise ValueError("native link requires game-owned closure")
    coverage = native_provider_coverage(provider_config, audit.symbol_closure)
    wibo, library_tool, linker = _native_linker_tools(audit.objects)

    output_directory.mkdir(parents=True, exist_ok=True)
    provider_directory = output_directory / "providers"
    provider_directory.mkdir(parents=True, exist_ok=True)
    linker_output: list[str] = []
    provider_artifact_rows: list[dict[str, Any]] = []
    archive_artifact_rows: list[dict[str, Any]] = []
    archive_libraries: list[Path] = []
    import_libraries: list[Path] = []
    provider_alias_objects: list[Path] = []
    entry_alias_payload: dict[str, Any] | None = None
    if provider_config.entry_aliases:
        entry_alias_path = provider_directory / "entry-aliases.obj"
        entry_alias_bytes = native_weak_alias_object_bytes(
            tuple(
                (alias.alias, alias.target)
                for alias in provider_config.entry_aliases
            ),
        )
        _write_bytes_atomic(entry_alias_path, entry_alias_bytes)
        provider_alias_objects.append(entry_alias_path)
        entry_alias_payload = {
            "object": _file_payload(entry_alias_path, repo_root=repo_root),
            "symbols": [
                {"alias": alias.alias, "target": alias.target}
                for alias in provider_config.entry_aliases
            ],
        }
    linked_archive_ids: set[str] = set()
    stems: set[str] = set()
    for provider in provider_config.providers:
        evidence = [
            {
                **_file_payload(row.path, repo_root=repo_root),
                "note": row.note,
            }
            for row in provider.evidence
        ]
        artifact_row: dict[str, Any] = {
            "evidence": evidence,
            "kind": provider.kind,
            "name": provider.name,
            "resolution": provider.resolution,
            "scope": provider.scope,
            "symbols": [symbol.name for symbol in provider.symbols],
        }
        stem: str | None = None
        if provider.resolution == "import-library" or provider.aliases:
            stem = _provider_file_stem(provider.name)
            if stem in stems:
                raise ValueError(f"provider file stem collision: {stem!r}")
            stems.add(stem)
        if provider.archive is not None:
            artifact_row["archive"] = provider.archive.id
            if provider.archive.id not in linked_archive_ids:
                archive_artifact_rows.append(
                    _native_provider_archive_payload(
                        provider.archive,
                        repo_root=repo_root,
                    ),
                )
                archive_libraries.append(provider.archive.path)
                linked_archive_ids.add(provider.archive.id)
        if provider.aliases:
            assert stem is not None
            alias_path = provider_directory / f"{stem}-aliases.obj"
            alias_bytes = native_weak_alias_object_bytes(
                tuple(
                    (alias.alias, alias.target)
                    for alias in provider.aliases
                ),
            )
            _write_bytes_atomic(alias_path, alias_bytes)
            provider_alias_objects.append(alias_path)
            artifact_row["aliases"] = {
                "object": _file_payload(alias_path, repo_root=repo_root),
                "symbols": [
                    {
                        "alias": alias.alias,
                        "target": alias.target,
                    }
                    for alias in provider.aliases
                ],
            }
        if provider.resolution == "import-library":
            assert stem is not None
            definition_path = provider_directory / f"{stem}.def"
            import_library_path = provider_directory / f"{stem}.lib"
            matchlib._write_text_atomic(
                definition_path,
                render_native_import_definition(provider),
            )
            completed = _run_native_tool(
                [
                    str(wibo),
                    str(library_tool),
                    "/nologo",
                    f"/def:{_wibo_windows_path(definition_path)}",
                    f"/out:{_wibo_windows_path(import_library_path)}",
                    "/machine:ix86",
                ],
                cwd=repo_root,
            )
            linker_output.extend(
                part
                for part in (completed.stdout, completed.stderr)
                if part
            )
            if completed.returncode != 0 or not import_library_path.is_file():
                raise RuntimeError(
                    f"failed to build import library for {provider.name}: "
                    f"exit={completed.returncode}",
                )
            _write_bytes_atomic(
                import_library_path,
                normalize_coff_archive_timestamps(import_library_path.read_bytes()),
            )
            generated_exp = import_library_path.with_suffix(".exp")
            if generated_exp.is_file():
                generated_exp.unlink()
            import_libraries.append(import_library_path)
            artifact_row.update(
                {
                    "definition": _file_payload(
                        definition_path,
                        repo_root=repo_root,
                    ),
                    "import_library": _file_payload(
                        import_library_path,
                        repo_root=repo_root,
                    ),
                    "module": provider.module,
                },
            )
        provider_artifact_rows.append(artifact_row)

    placeholder_providers = tuple(
        provider
        for provider in provider_config.providers
        if provider.resolution == "placeholder-object"
    )
    placeholder_path: Path | None = None
    placeholder_payload: dict[str, Any] | None = None
    if placeholder_providers:
        placeholder_path = provider_directory / "placeholders.obj"
        placeholder_bytes = native_provider_placeholder_object_bytes(
            placeholder_providers,
        )
        _write_bytes_atomic(placeholder_path, placeholder_bytes)
        placeholder_payload = {
            **_file_payload(placeholder_path, repo_root=repo_root),
            "symbol_count": coverage["placeholder_symbols"],
        }

    object_paths = [
        *(record.object_path for record in audit.objects.records),
        *(record.object_path for record in audit.objects.data_records),
        *(record.object_path for record in audit.objects.linker_alias_records),
        *provider_alias_objects,
        *import_libraries,
    ]
    if placeholder_path is not None:
        object_paths.append(placeholder_path)
    object_paths.extend(archive_libraries)
    response_path = output_directory / "link.rsp"
    matchlib._write_text_atomic(
        response_path,
        "".join(f'"{_wibo_windows_path(path)}"\n' for path in object_paths),
    )
    export_path = output_directory / "exports.def"
    matchlib._write_text_atomic(
        export_path,
        render_export_definition(audit.objects.image, audit.symbol_closure),
    )
    image_path = output_directory / audit.objects.image
    import_library_path = output_directory / f"{Path(audit.objects.image).stem}.lib"
    map_path = output_directory / f"{audit.objects.image}.map"
    log_path = output_directory / "link.log"
    manifest_path = output_directory / "link.json"
    is_dll = Path(audit.objects.image).suffix.casefold() == ".dll"
    link_completed = _run_native_tool(
        [
            str(wibo),
            str(linker),
            "/nologo",
            "/nodefaultlib",
            "/opt:ref",
            "/machine:ix86",
            f"/entry:{provider_config.entry}",
            f"/base:0x{provider_config.image_base:08x}",
            f"/out:{_wibo_windows_path(image_path)}",
            f"/map:{_wibo_windows_path(map_path)}",
            *_native_link_image_options(
                audit.objects.image,
                export_path=export_path,
                import_library_path=import_library_path,
            ),
            f"@{_wibo_windows_path(response_path)}",
        ],
        cwd=repo_root,
    )
    linker_output.extend(
        part
        for part in (link_completed.stdout, link_completed.stderr)
        if part
    )
    matchlib._write_text_atomic(log_path, "".join(linker_output))
    if link_completed.returncode != 0 or not image_path.is_file():
        raise RuntimeError(
            f"native link failed: exit={link_completed.returncode}; log={log_path}",
        )

    _write_bytes_atomic(
        image_path,
        normalize_pe_timestamp(image_path.read_bytes()),
    )
    if import_library_path.is_file():
        _write_bytes_atomic(
            import_library_path,
            normalize_coff_archive_timestamps(import_library_path.read_bytes()),
        )
    generated_exp = import_library_path.with_suffix(".exp")
    if generated_exp.is_file():
        exp_data = bytearray(generated_exp.read_bytes())
        if (
            len(exp_data) >= 20
            and struct.unpack_from("<H", exp_data, 0)[0]
            == matchlib.IMAGE_FILE_MACHINE_I386
        ):
            exp_data[4:8] = b"\x00" * 4
            _write_bytes_atomic(generated_exp, bytes(exp_data))

    linked_image_data = image_path.read_bytes()
    pe_summary = native_pe_summary(linked_image_data)
    if (
        pe_summary["machine"] != matchlib.IMAGE_FILE_MACHINE_I386
        or pe_summary["dll"] is not is_dll
        or pe_summary["image_base"] != provider_config.image_base
        or (not is_dll and pe_summary["subsystem"] != 2)
        or pe_summary["timestamp"] != 0
    ):
        raise ValueError(f"linked PE failed structural validation: {pe_summary}")
    reference_imports = _validate_linked_reference_imports(
        provider_config,
        linked_image_data,
        audit.symbol_closure,
    )
    if reference_imports["symbol_count"] != coverage["import_exports"]:
        raise ValueError(
            "linked reference-import count disagrees with provider coverage",
        )
    map_symbols = _native_link_map_public_symbols(
        map_path.read_text(encoding="latin1"),
    )
    placeholder_symbols_by_scope = {
        scope: {
            symbol.name
            for provider in placeholder_providers
            if provider.scope == scope
            for symbol in provider.symbols
        }
        for scope in ("closure", "link-dependency")
    }
    configured_placeholder_symbols = set().union(
        *placeholder_symbols_by_scope.values(),
    )
    retained_placeholder_symbols = configured_placeholder_symbols & map_symbols
    discarded_placeholder_symbols = (
        configured_placeholder_symbols - retained_placeholder_symbols
    )
    linked_runnable = not retained_placeholder_symbols
    for provider, artifact_row in zip(
        provider_config.providers,
        provider_artifact_rows,
        strict=True,
    ):
        if provider.resolution != "placeholder-object":
            continue
        provider_symbols = {symbol.name for symbol in provider.symbols}
        artifact_row["discarded_symbols"] = sorted(
            provider_symbols & discarded_placeholder_symbols,
        )
        artifact_row["retained_symbols"] = sorted(
            provider_symbols & retained_placeholder_symbols,
        )
    if placeholder_payload is not None:
        placeholder_payload.update(
            {
                "discarded_symbols": sorted(discarded_placeholder_symbols),
                "retained_symbols": sorted(retained_placeholder_symbols),
            },
        )
    manifest = {
        "archives": archive_artifact_rows,
        "audit_digest": audit.object_manifest["audit_digest"],
        "entry": {
            **({"aliases": entry_alias_payload} if entry_alias_payload else {}),
            "symbol": provider_config.entry,
        },
        "image": audit.objects.image,
        "kind": NATIVE_LINK_MANIFEST_KIND,
        "mode": provider_config.mode,
        "output": {
            **_file_payload(image_path, repo_root=repo_root),
            "pe": pe_summary,
        },
        "placeholder_object": placeholder_payload,
        "provider_config": {
            **_file_payload(provider_config.path, repo_root=repo_root),
            "declared_sha256": provider_config.sha256,
        },
        "providers": provider_artifact_rows,
        "reference_imports": reference_imports,
        "runnable": linked_runnable,
        "schema": NATIVE_LINK_MANIFEST_SCHEMA,
        "status": "linked",
        "summary": {
            **coverage,
            "discarded_placeholder_symbols": len(discarded_placeholder_symbols),
            "input_object_count": len(object_paths),
            "retained_closure_placeholder_symbols": len(
                placeholder_symbols_by_scope["closure"]
                & retained_placeholder_symbols,
            ),
            "retained_link_dependency_placeholder_symbols": len(
                placeholder_symbols_by_scope["link-dependency"]
                & retained_placeholder_symbols,
            ),
            "retained_link_dependency_import_symbols": (
                reference_imports["link_dependency_retained_symbol_count"]
            ),
            "retained_placeholder_symbols": len(retained_placeholder_symbols),
            "runnable": linked_runnable,
            "validated_output_import_symbols": (
                reference_imports["output_symbol_count"]
            ),
            "validated_reference_import_symbols": reference_imports["symbol_count"],
        },
        "toolchain": {
            "library_tool": _file_payload(library_tool, repo_root=repo_root),
            "linker": _file_payload(linker, repo_root=repo_root),
            "wibo": _file_payload(wibo, repo_root=repo_root),
        },
    }
    matchlib.write_match_json(manifest_path, manifest)
    artifacts = NativeLinkedImageArtifacts(
        image=image_path,
        import_library=import_library_path,
        map_file=map_path,
        response_file=response_path,
        log=log_path,
        manifest=manifest_path,
    )
    return artifacts, manifest
