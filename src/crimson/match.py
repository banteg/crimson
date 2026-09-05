from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shlex
import struct
from collections import Counter, defaultdict
from collections.abc import Collection
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

from . import match_experiments, match_process, match_toolchain
from .match_process import run_compiler

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VERSION = "1.9.93-gog"
DEFAULT_GAME_DIR = REPO_ROOT / "game_bins" / "crimsonland" / DEFAULT_VERSION
DEFAULT_IMAGE_NAME = "crimsonland.exe"
TRACKED_IMAGE_NAMES = ("crimsonland.exe", "grim.dll")
DEFAULT_MATCH_ROOT = REPO_ROOT / "tools" / "match"
DEFAULT_FUNCTIONS_PATH = REPO_ROOT / "analysis" / "ida" / "raw" / DEFAULT_IMAGE_NAME / "functions.json"
DEFAULT_METADATA_PATH = REPO_ROOT / "analysis" / "ida" / "raw" / DEFAULT_IMAGE_NAME / "metadata.json"
DEFAULT_IMAGE_PATH = DEFAULT_GAME_DIR / DEFAULT_IMAGE_NAME
DEFAULT_DATA_MAP_PATH = REPO_ROOT / "analysis" / "ghidra" / "maps" / "data_map.json"
DEFAULT_NAME_MAP_PATH = REPO_ROOT / "analysis" / "ghidra" / "maps" / "name_map.json"
DEFAULT_NAMING_HINTS_PATH = DEFAULT_MATCH_ROOT / "naming_hints.json"
DEFAULT_MATCHING_SCOPE_PATH = REPO_ROOT / "analysis" / "matching_scope.json"
DEFAULT_NATIVE_ANALYSIS_ROOT = REPO_ROOT / "analysis" / "native"
DEFAULT_MATCH_SCOPE = "port"
ANALYZER_PLACEHOLDER_RE = re.compile(
    r"^(?:FUN_[0-9a-f]+|sub_[0-9a-f]+|unknown(?:_libname)?(?:_[0-9]+)?|"
    r"nullsub_[0-9]+|j_(?:FUN_[0-9a-f]+|sub_[0-9a-f]+|nullsub_[0-9]+)|"
    r"j_[a-z_][a-z0-9_]*|"
    r"DAT_[0-9a-f]+|LAB_[0-9a-f]+|PTR_[0-9a-f]+|"
    r"(?:switchD|caseD|lookup_table)_[0-9a-f]+)$",
    re.IGNORECASE,
)
ANALYZER_ADDRESS_NAME_RE = re.compile(r"^(?:j_)?(?:FUN_|sub_)([0-9a-f]+)$", re.IGNORECASE)
ANALYZER_PLACEHOLDER_TOKEN_RE = re.compile(
    r"(?<![0-9a-z])(?:j_(?:FUN_[0-9a-f]+|sub_[0-9a-f]+|nullsub_[0-9]+)|"
    r"_?(?:DAT_|FUN_|LAB_|PTR_|sub_)[0-9a-f]+|"
    r"(?:switchD|caseD|lookup_table)_[0-9a-f]+|"
    r"unknown_libname(?:_[0-9]+)?|unknown_[0-9]+|nullsub_[0-9]+)(?![0-9a-z])",
    re.IGNORECASE,
)
IDENTIFIER_TOKEN_RE = re.compile(r"(?<![0-9a-z_])[a-z_][a-z0-9_]*(?![0-9a-z_])", re.IGNORECASE)
ADDRESS_DERIVED_IDENTITY_RE = re.compile(
    r"^(?:j_(?:FUN|sub)_|FUN_|sub_|DAT_|data_|LAB_|loc_|PTR_|"
    r"(?:switchD|caseD|lookup_table)_|(?:byte|word|dword|qword|off|unk|field)_)[0-9a-f]+$|"
    r"^(?:j_)?nullsub_[0-9]+$|^unknown(?:_libname)?(?:_[0-9]+)?$",
    re.IGNORECASE,
)
ADDRESS_DERIVED_REFERENCE_RE = re.compile(
    r"(?<![0-9a-z_])(?P<token>_?(?P<prefix>j_FUN|j_sub|FUN|sub|DAT|data|LAB|loc|PTR|"
    r"switchD|caseD|lookup_table|byte|word|dword|qword|off|unk|field)_"
    r"(?P<address>[0-9a-f]{6,16}))(?![0-9a-z_])",
    re.IGNORECASE,
)
FUNCTION_REFERENCE_PREFIXES = frozenset({"j_fun", "j_sub", "fun", "sub"})
RESOLVED_NAME_AUDIT_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".inc",
        ".js",
        ".json",
        ".md",
        ".py",
        ".sh",
        ".toml",
        ".ts",
        ".yaml",
        ".yml",
        ".zig",
    },
)
RESOLVED_NAME_AUDIT_PRUNED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".git",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "node_modules",
    },
)
MATCH_SCOPE_SCHEMA = 2
MATCH_SCOPE_FUNCTION_DISPOSITIONS = frozenset(
    {
        "platform-replaced",
        "third-party",
    },
)
DEFAULT_MATCH_JOBS = min(8, max(1, os.cpu_count() or 1))
CACHE_VERSION = 2
SHARD_SCHEMA = 1
SHARD_PLAN_KIND = "crimson-match-shard-plan"
WORKER_CLAIM_KIND = "crimson-match-worker-claim"
WORKER_OUTCOME_KIND = "crimson-match-worker-outcome"
WORKER_OUTCOME_FILE = "outcomes.jsonl"
WORKER_OUTCOME_DISPOSITIONS = frozenset({"matched", "improved", "falsified", "blocked"})
WORKER_HYPOTHESIS_KINDS = frozenset(
    {
        "analysis",
        "references",
        "source-shape",
        "toolchain",
        "unknown",
    },
)

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_CLASS_LABEL = 6
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_REL_I386_DIR32 = 0x06
IMAGE_REL_I386_REL32 = 0x14
IMAGE_REL_I386_WIDTHS = {
    0x0000: 0,
    0x0006: 4,
    0x0007: 4,
    0x000A: 2,
    0x000B: 4,
    0x000C: 4,
    0x000D: 1,
    0x0014: 4,
}
SYM_TYPE_FUNCTION = 0x20
PADDING_BYTES = b"\xcc\x90"
PADDING_LINE_TEXT = {
    "add eax, 0x0",
    "add byte [eax], al",
    "int3",
    "lea ecx, dword [ecx]",
    "lea edi, dword [edi]",
    "lea esi, dword [esi]",
    "lea esp, dword [esp]",
    "mov edi, edi",
    "mov esi, esi",
    "nop",
}
BRANCH_TARGET_RE = re.compile(r"\bL([0-9a-f]+)\b")
ADDRESS_REFERENCE_KEY_RE = re.compile(r"^address:0x([0-9a-fA-F]+)$")
LOCAL_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"\r\n]+)"', re.MULTILINE)
VC6_SINGLE_DELETE_UNWIND_KEY = "compiler:vc6-cxx-frame-handler:single-delete-unwind"
VC6_UNWIND_ONLY_KEY = "compiler:vc6-cxx-frame-handler:unwind-only"
VC6_LOCAL_JUMP_TABLE_KEY = "compiler:vc6-local-jump-table"
VC6_LOCAL_SWITCH_PARTITION_KEY = "compiler:vc6-local-switch-partition"
VC6_PROVEN_COPY_LOAD_KEY = "compiler:vc6-proven-copy-load"


def parse_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 0)


def load_name_map_rows(path: Path) -> tuple[dict[str, Any], ...]:
    """Load curated symbols while rejecting ambiguous address overrides."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise TypeError(f"{path}: name map must contain a JSON array")

    rows: list[dict[str, Any]] = []
    seen: dict[tuple[str, int], int] = {}
    for index, row in enumerate(payload):
        if not isinstance(row, dict):
            raise TypeError(f"{path}: name-map row {index} must be an object")
        typed_row = cast(dict[str, Any], row)
        program = str(typed_row.get("program", ""))
        address = parse_int(typed_row["address"])
        key = (program, address)
        if key in seen:
            raise ValueError(
                f"{path}: duplicate name-map entry for {program}:0x{address:x} "
                f"at rows {seen[key]} and {index}",
            )
        seen[key] = index
        rows.append(typed_row)
    return tuple(rows)


def default_image_path(image: str = DEFAULT_IMAGE_NAME) -> Path:
    return DEFAULT_GAME_DIR / image


def default_functions_path(image: str = DEFAULT_IMAGE_NAME) -> Path:
    return REPO_ROOT / "analysis" / "ida" / "raw" / image / "functions.json"


def default_metadata_path(image: str = DEFAULT_IMAGE_NAME) -> Path:
    return REPO_ROOT / "analysis" / "ida" / "raw" / image / "metadata.json"


@dataclass(frozen=True, slots=True)
class FunctionSymbol:
    name: str
    address: int
    end: int
    size: int


@dataclass(frozen=True, slots=True)
class FunctionManifest:
    image_name: str
    image_base: int
    functions: tuple[FunctionSymbol, ...]

    @property
    def by_name(self) -> dict[str, FunctionSymbol]:
        return {function.name: function for function in self.functions}


@dataclass(frozen=True, slots=True)
class MatchScopeRange:
    start: int
    end: int
    owner: str

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True, slots=True)
class MatchScopeFunctionDisposition:
    address: int
    name: str
    disposition: str
    reason: str


@dataclass(frozen=True, slots=True)
class MatchingScopeDefinition:
    ranges: dict[str, tuple[MatchScopeRange, ...]]
    function_dispositions: dict[str, tuple[MatchScopeFunctionDisposition, ...]]


def _load_matching_scope_definition(
    scope: str,
    *,
    path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> MatchingScopeDefinition:
    if scope == "all":
        return MatchingScopeDefinition(ranges={}, function_dispositions={})
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != MATCH_SCOPE_SCHEMA:
        raise ValueError(f"{path}: unsupported matching scope schema")
    try:
        scope_payload = payload["scopes"][scope]
        programs = scope_payload["programs"]
    except KeyError as exc:
        available = ", ".join(sorted(payload.get("scopes", {})))
        raise ValueError(f"unknown matching scope {scope!r}; available: {available}, all") from exc

    ranges_by_program: dict[str, tuple[MatchScopeRange, ...]] = {}
    for program, rows in programs.items():
        ranges: list[MatchScopeRange] = []
        for row in rows:
            start = parse_int(row["start"])
            end = parse_int(row["end"])
            if end <= start:
                raise ValueError(f"{path}: invalid {program} range 0x{start:x}..0x{end:x}")
            ranges.append(MatchScopeRange(start=start, end=end, owner=str(row["owner"])))
        ranges_by_program[str(program)] = tuple(ranges)

    dispositions_by_program: dict[str, tuple[MatchScopeFunctionDisposition, ...]] = {}
    raw_dispositions = scope_payload.get("function_dispositions", {})
    for raw_program, rows in raw_dispositions.items():
        program = str(raw_program)
        owned_ranges = ranges_by_program.get(program, ())
        if not owned_ranges:
            raise ValueError(f"{path}: function dispositions require an owned {program} range")
        dispositions: list[MatchScopeFunctionDisposition] = []
        seen_addresses: set[int] = set()
        for row in rows:
            address = parse_int(row["address"])
            name = str(row.get("name", "")).strip()
            disposition = str(row.get("disposition", "")).strip()
            reason = str(row.get("reason", "")).strip()
            if address in seen_addresses:
                raise ValueError(f"{path}: duplicate {program} function disposition at 0x{address:x}")
            if not any(owned_range.contains(address) for owned_range in owned_ranges):
                raise ValueError(
                    f"{path}: {program} function disposition at 0x{address:x} is outside owned ranges",
                )
            if not name:
                raise ValueError(f"{path}: {program}:0x{address:x} function disposition needs a name")
            if disposition not in MATCH_SCOPE_FUNCTION_DISPOSITIONS:
                available = ", ".join(sorted(MATCH_SCOPE_FUNCTION_DISPOSITIONS))
                raise ValueError(
                    f"{path}: unknown function disposition {disposition!r}; available: {available}",
                )
            if not reason:
                raise ValueError(f"{path}: {program}:{name} function disposition needs a reason")
            seen_addresses.add(address)
            dispositions.append(
                MatchScopeFunctionDisposition(
                    address=address,
                    name=name,
                    disposition=disposition,
                    reason=reason,
                ),
            )
        dispositions_by_program[program] = tuple(dispositions)
    return MatchingScopeDefinition(
        ranges=ranges_by_program,
        function_dispositions=dispositions_by_program,
    )


def load_matching_scope(
    scope: str,
    *,
    path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> dict[str, tuple[MatchScopeRange, ...]]:
    """Load one stable, address-keyed ownership scope.

    ``all`` is an explicit escape hatch for consulting every non-external
    function. It is intentionally not represented by address ranges.
    """
    return _load_matching_scope_definition(scope, path=path).ranges


def load_matching_scope_function_dispositions(
    scope: str,
    *,
    path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> dict[str, tuple[MatchScopeFunctionDisposition, ...]]:
    """Load explicit function-level omissions from one matching scope."""
    return _load_matching_scope_definition(scope, path=path).function_dispositions


def matching_scope_function_disposition_payloads(
    scope: str,
    *,
    path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> list[dict[str, Any]]:
    dispositions = load_matching_scope_function_dispositions(scope, path=path)
    return [
        {
            "image": image,
            "address": row.address,
            "function": row.name,
            "disposition": row.disposition,
            "reason": row.reason,
        }
        for image in sorted(dispositions)
        for row in sorted(dispositions[image], key=lambda candidate: candidate.address)
    ]


def matching_scope_images(
    scope: str | None,
    *,
    path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> tuple[str, ...]:
    if scope is None or scope == "all":
        return TRACKED_IMAGE_NAMES
    ranges = load_matching_scope(scope, path=path)
    return tuple(program for program in TRACKED_IMAGE_NAMES if ranges.get(program))


def address_in_matching_scope(
    image_name: str,
    address: int,
    *,
    scope: str,
    path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> bool:
    if scope == "all":
        return True
    definition = _load_matching_scope_definition(scope, path=path)
    owned = any(row.contains(address) for row in definition.ranges.get(image_name, ()))
    dispositioned = any(
        row.address == address
        for row in definition.function_dispositions.get(image_name, ())
    )
    return owned and not dispositioned


@dataclass(frozen=True, slots=True)
class ReferenceCatalog:
    names_by_address: dict[int, tuple[str, ...]]
    addresses_by_name: dict[str, tuple[int, ...]] = field(default_factory=dict)
    import_addresses: frozenset[int] = frozenset()
    object_alias_addresses: dict[str, tuple[int, ...]] = field(default_factory=dict)

    def keys_for_address(self, address: int) -> tuple[str, ...]:
        return (
            f"address:0x{address:08x}",
            *(f"name:{_canonical_symbol_name(name)}" for name in self.names_by_address.get(address, ())),
        )

    def keys_for_object_reference(self, symbol_name: str, addend: int) -> tuple[str, ...]:
        canonical = _canonical_symbol_name(symbol_name)
        lookup_name = _symbol_lookup_name(symbol_name)
        keys = [f"name:{canonical}{_format_addend(addend)}"]
        if lookup_name != canonical:
            keys.append(f"name:{lookup_name}{_format_addend(addend)}")
        addresses = self._addresses_for_symbol(symbol_name)
        if len(addresses) == 1:
            keys.append(f"address:0x{addresses[0] + addend:08x}")
        return tuple(dict.fromkeys(keys))

    def knows_name(self, symbol_name: str) -> bool:
        return len(self._addresses_for_symbol(symbol_name)) == 1

    def _addresses_for_symbol(self, symbol_name: str) -> tuple[int, ...]:
        imported = _is_import_symbol(symbol_name)
        lookup_name = _symbol_lookup_name(symbol_name)
        if not imported and (addresses := self.object_alias_addresses.get(lookup_name)) is not None:
            return addresses
        canonical = _canonical_symbol_name(symbol_name)
        addresses = self._addresses_for_name(canonical, imported=imported)
        if addresses:
            return addresses
        if lookup_name != canonical:
            return self._addresses_for_name(lookup_name, imported=imported)
        return ()

    def _addresses_for_name(self, name: str, *, imported: bool) -> tuple[int, ...]:
        addresses = self.addresses_by_name.get(name)
        if addresses is None:
            addresses = tuple(
                address
                for address, names in self.names_by_address.items()
                if any(_symbol_lookup_name(candidate) == name for candidate in names)
            )
        return tuple(address for address in addresses if (address in self.import_addresses) == imported)

    def with_object_aliases(
        self,
        aliases: tuple[tuple[str, str], ...],
    ) -> ReferenceCatalog:
        """Resolve reused compiler-local names against proven image symbols."""
        if not aliases:
            return self

        object_alias_addresses = dict(self.object_alias_addresses)
        for object_symbol, target_symbol in aliases:
            target_addresses = self._addresses_for_symbol(target_symbol)
            if len(target_addresses) != 1:
                raise ValueError(
                    f"reference alias target {target_symbol!r} must resolve to exactly one image address",
                )
            object_alias_addresses[_symbol_lookup_name(object_symbol)] = target_addresses
        return replace(self, object_alias_addresses=object_alias_addresses)


def load_reference_catalog(
    manifest: FunctionManifest,
    *,
    data_map_path: Path = DEFAULT_DATA_MAP_PATH,
    functions_path: Path | None = None,
    name_map_path: Path | None = DEFAULT_NAME_MAP_PATH,
) -> ReferenceCatalog:
    """Build the conservative symbol oracle used to audit masked image addresses.

    Only exact function, import-table, and data-map addresses are named.
    References into an unknown object or to an unlabelled import stay
    unresolved instead of being accepted on the strength of an ``ADDR``
    placeholder.
    """
    names: dict[int, list[str]] = {}
    import_addresses: set[int] = set()
    name_rows = (
        load_name_map_rows(name_map_path)
        if name_map_path is not None and name_map_path.exists()
        else []
    )
    curated_names_by_address = {
        parse_int(entry["address"]): str(entry["name"])
        for entry in name_rows
        if entry.get("program") == manifest.image_name and not bool(entry.get("exclude"))
    }
    for function in manifest.functions:
        names.setdefault(function.address, []).append(function.name)
    raw_functions_path = functions_path or default_functions_path(manifest.image_name)
    if raw_functions_path.exists():
        for entry in json.loads(raw_functions_path.read_text(encoding="utf-8")):
            address = parse_int(entry["address"])
            name = str(entry["name"])
            curated_name = curated_names_by_address.get(address)
            if curated_name is not None and curated_name != name:
                continue
            if address > 0 and name not in names.setdefault(address, []):
                names[address].append(name)
    imports_path = raw_functions_path.with_name("imports.json")
    if imports_path.exists():
        for module in json.loads(imports_path.read_text(encoding="utf-8")):
            for entry in module.get("entries", []):
                address = parse_int(entry["address"])
                name = str(entry.get("name") or "")
                if not name:
                    continue
                if address > 0:
                    import_addresses.add(address)
                    if name not in names.setdefault(address, []):
                        names[address].append(name)
    if data_map_path.exists():
        payload = json.loads(data_map_path.read_text(encoding="utf-8"))
        for entry in payload.get("entries", []):
            if entry.get("program") != manifest.image_name:
                continue
            address = parse_int(entry["address"])
            entry_names = (str(entry["name"]), *(str(alias) for alias in entry.get("aliases", [])))
            for name in entry_names:
                if name not in names.setdefault(address, []):
                    names[address].append(name)
    for entry in name_rows:
        if entry.get("program") != manifest.image_name:
            continue
        if bool(entry.get("exclude")):
            continue
        address = parse_int(entry["address"])
        entry_names = (str(entry["name"]), *(str(alias) for alias in entry.get("aliases", [])))
        for name in entry_names:
            if name not in names.setdefault(address, []):
                names[address].append(name)
    names_by_address = {address: tuple(values) for address, values in names.items()}
    addresses_by_name: dict[str, list[int]] = {}
    for address, values in names_by_address.items():
        for name in values:
            canonical = _canonical_symbol_name(name)
            lookup_name = _symbol_lookup_name(name)
            addresses_by_name.setdefault(canonical, []).append(address)
            if lookup_name != canonical:
                addresses_by_name.setdefault(lookup_name, []).append(address)
    return ReferenceCatalog(
        names_by_address,
        {name: tuple(dict.fromkeys(addresses)) for name, addresses in addresses_by_name.items()},
        frozenset(import_addresses),
    )


def _load_image_base(metadata_path: Path | None) -> int:
    if metadata_path is None or not metadata_path.exists():
        return 0x400000
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    return parse_int(metadata.get("image_base", "0x400000"))


def load_function_manifest(
    path: Path = DEFAULT_FUNCTIONS_PATH,
    *,
    metadata_path: Path | None = DEFAULT_METADATA_PATH,
    image_name: str | None = None,
    name_map_path: Path | None = DEFAULT_NAME_MAP_PATH,
    scope: str | None = None,
    scope_path: Path = DEFAULT_MATCHING_SCOPE_PATH,
) -> FunctionManifest:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    resolved_image_name = image_name or Path(path).parent.name
    scope_definition = (
        None
        if scope is None or scope == "all"
        else _load_matching_scope_definition(scope, path=scope_path)
    )
    scoped_ranges = (
        None
        if scope_definition is None
        else scope_definition.ranges.get(resolved_image_name, ())
    )
    scoped_dispositions = (
        ()
        if scope_definition is None
        else scope_definition.function_dispositions.get(resolved_image_name, ())
    )
    scoped_disposition_addresses = frozenset(row.address for row in scoped_dispositions)

    name_overrides: dict[int, str] = {}
    end_overrides: dict[int, int] = {}
    included_library_addresses: set[int] = set()
    excluded_addresses: set[int] = set()
    created_rows: list[dict[str, Any]] = []
    if name_map_path is not None and name_map_path.exists():
        name_rows = load_name_map_rows(name_map_path)
        for row in name_rows:
            if row.get("program") != resolved_image_name:
                continue
            address = parse_int(row["address"])
            if bool(row.get("exclude")):
                excluded_addresses.add(address)
                continue
            name_overrides[address] = str(row["name"])
            if not bool(row.get("create")) and row.get("end") is not None:
                end_overrides[address] = parse_int(row["end"])
            if bool(row.get("include_library")):
                included_library_addresses.add(address)
            if bool(row.get("create")) and row.get("end") is not None:
                created_rows.append(row)

    manifest_names_by_address = {
        parse_int(row["address"]): name_overrides.get(
            parse_int(row["address"]),
            str(row["name"]),
        )
        for row in rows
        if not bool(row.get("external"))
    }
    unknown_exclusions = excluded_addresses - manifest_names_by_address.keys()
    if unknown_exclusions:
        addresses = ", ".join(f"0x{address:x}" for address in sorted(unknown_exclusions))
        raise ValueError(
            f"{name_map_path}: {resolved_image_name} exclusions are absent from the "
            f"function manifest: {addresses}",
        )
    for row in created_rows:
        address = parse_int(row["address"])
        manifest_names_by_address.setdefault(address, str(row["name"]))
    for disposition in scoped_dispositions:
        observed_name = manifest_names_by_address.get(disposition.address)
        if observed_name is None:
            raise ValueError(
                f"{scope_path}: {resolved_image_name}:{disposition.name} disposition "
                f"address 0x{disposition.address:x} is absent from the function manifest",
            )
        if observed_name != disposition.name:
            raise ValueError(
                f"{scope_path}: {resolved_image_name}:0x{disposition.address:x} disposition "
                f"name {disposition.name!r} does not match manifest name {observed_name!r}",
            )

    def is_scoped(address: int) -> bool:
        return scoped_ranges is None or (
            address not in scoped_disposition_addresses
            and any(row.contains(address) for row in scoped_ranges)
        )

    functions: list[FunctionSymbol] = []
    for row in rows:
        address = parse_int(row["address"])
        if bool(row.get("external")):
            continue
        if address in excluded_addresses:
            continue
        if scope is None and bool(row.get("library")) and address not in included_library_addresses:
            continue
        if not is_scoped(address):
            continue
        end = end_overrides.get(address, parse_int(row["end"]))
        if end <= address:
            raise ValueError(
                f"curated function {name_overrides.get(address, row['name'])!r} "
                f"has invalid extent 0x{address:x}..0x{end:x}",
            )
        functions.append(
            FunctionSymbol(
                name=name_overrides.get(address, str(row["name"])),
                address=address,
                end=end,
                size=(
                    end - address
                    if address in end_overrides
                    else int(row.get("size") or end - address)
                ),
            ),
        )
    existing_addresses = {function.address for function in functions}
    for row in created_rows:
        address = parse_int(row["address"])
        if not is_scoped(address):
            continue
        if address in existing_addresses:
            continue
        end = parse_int(row["end"])
        if end <= address:
            raise ValueError(f"created function {row['name']!r} has invalid extent 0x{address:x}..0x{end:x}")
        if any(address < function.end and function.address < end for function in functions):
            raise ValueError(f"created function {row['name']!r} overlaps the existing manifest")
        functions.append(
            FunctionSymbol(
                name=str(row["name"]),
                address=address,
                end=end,
                size=end - address,
            ),
        )
        existing_addresses.add(address)
    sorted_functions = sorted(functions, key=lambda function: function.address)
    for index, function in enumerate(sorted_functions[:-1]):
        if (
            function.address in end_overrides
            and function.end > sorted_functions[index + 1].address
        ):
            next_function = sorted_functions[index + 1]
            raise ValueError(
                f"curated function {function.name!r} extent "
                f"0x{function.address:x}..0x{function.end:x} overlaps "
                f"{next_function.name!r} at 0x{next_function.address:x}",
            )
    return FunctionManifest(
        image_name=resolved_image_name,
        image_base=_load_image_base(metadata_path),
        functions=tuple(sorted_functions),
    )


def resolve_function(
    manifest: FunctionManifest,
    function: str,
    *,
    end_override: int | None = None,
) -> tuple[FunctionSymbol, int, int]:
    if function.startswith(("0x", "0X")):
        address = int(function, 16)
        matches = [candidate for candidate in manifest.functions if candidate.address == address]
    else:
        matches = [candidate for candidate in manifest.functions if candidate.name == function]
        if not matches:
            matches = [candidate for candidate in manifest.functions if function in candidate.name]
    if not matches:
        raise ValueError(f"function {function!r} not found in {manifest.image_name} manifest")
    if len(matches) > 1:
        names = ", ".join(candidate.name for candidate in matches[:8])
        suffix = "" if len(matches) <= 8 else ", ..."
        raise ValueError(f"function {function!r} is ambiguous: {names}{suffix}")
    symbol = matches[0]
    return symbol, symbol.address, end_override if end_override is not None else symbol.end


def resolve_function_with_scope_hint(
    manifest: FunctionManifest,
    function: str,
    *,
    scope: str | None,
    unscoped_manifest: FunctionManifest | None = None,
    end_override: int | None = None,
) -> tuple[FunctionSymbol, int, int]:
    """Resolve a function and explain when the active scope excluded it."""

    try:
        return resolve_function(manifest, function, end_override=end_override)
    except ValueError as exc:
        if scope in (None, "all") or unscoped_manifest is None:
            raise
        try:
            resolve_function(unscoped_manifest, function, end_override=end_override)
        except ValueError:
            raise exc from None
        raise ValueError(
            f"function {function!r} is outside matching scope {scope!r} for "
            f"{manifest.image_name}; retry with --scope all",
        ) from exc


@dataclass(frozen=True, slots=True)
class CoffRelocation:
    virtual_address: int
    symbol_index: int
    relocation_type: int


@dataclass(frozen=True, slots=True)
class CoffSection:
    name: str
    data: bytes
    characteristics: int
    relocations: tuple[CoffRelocation, ...]
    index: int = 0
    comdat_key: str | None = None
    comdat_selection: int | None = None
    comdat_associative_section: int | None = None
    logical_size: int | None = None


@dataclass(frozen=True, slots=True)
class CoffSymbol:
    raw_index: int
    name: str
    value: int
    section_number: int
    symbol_type: int
    storage_class: int
    aux_records: tuple[bytes, ...] = ()
    weak_default_symbol_index: int | None = None
    weak_search: int | None = None


@dataclass(frozen=True, slots=True)
class CoffObject:
    sections: tuple[CoffSection, ...]
    symbols: tuple[CoffSymbol, ...]


@dataclass(frozen=True, slots=True)
class ObjectFunction:
    name: str
    data: bytes
    relocation_offsets: frozenset[int]
    relocation_references: tuple[ObjectRelocationReference, ...] = ()


@dataclass(frozen=True, slots=True)
class ObjectRelocationReference:
    offset: int
    symbol_name: str
    key: str | None
    explained: bool
    addend: int | None = None
    symbol_data: bytes | None = None
    read_only_data: bool = False
    local_target_offset: int | None = None
    alternate_keys: tuple[str, ...] = ()
    relocation_type: int | None = None


@dataclass(frozen=True, slots=True)
class LoadedImage:
    mapped: bytes
    image_base: int
    size_of_image: int

    def function_bytes(self, start_va: int, end_va: int) -> bytes:
        data = self.mapped[start_va - self.image_base : end_va - self.image_base]
        return data.rstrip(PADDING_BYTES)


@dataclass(frozen=True, slots=True)
class DisassemblyLine:
    offset: int
    address: int
    text: str
    size: int = 0
    masked_references: tuple[MaskedReference, ...] = ()


@dataclass(frozen=True, slots=True)
class MaskedReference:
    operand_index: int
    kind: str
    source: str
    value: int | None
    text: str
    keys: tuple[str, ...]
    explained: bool


@dataclass(frozen=True, slots=True)
class MaskedOperandAuditEntry:
    target_index: int
    candidate_index: int
    target_offset: int
    candidate_offset: int
    target_address: int
    candidate_address: int
    instruction: str
    target_references: tuple[MaskedReference, ...]
    candidate_references: tuple[MaskedReference, ...]
    status: str


@dataclass(frozen=True, slots=True)
class MaskedOperandAudit:
    entries: tuple[MaskedOperandAuditEntry, ...] = ()

    @property
    def ok_count(self) -> int:
        return sum(entry.status == "ok" for entry in self.entries)

    @property
    def unresolved_count(self) -> int:
        return sum(entry.status == "unresolved" for entry in self.entries)

    @property
    def mismatch_count(self) -> int:
        return sum(entry.status == "mismatch" for entry in self.entries)

    @property
    def problem_count(self) -> int:
        return self.unresolved_count + self.mismatch_count


@dataclass(frozen=True, slots=True)
class MatchResult:
    ratio: float
    prefix_instructions: int
    target_lines: tuple[str, ...]
    candidate_lines: tuple[str, ...]
    target_disassembly: tuple[DisassemblyLine, ...] = ()
    candidate_disassembly: tuple[DisassemblyLine, ...] = ()
    masked_operand_audit: MaskedOperandAudit = field(default_factory=MaskedOperandAudit)
    body_byte_exact: bool | None = None
    target_padding_bytes: int = 0
    candidate_padding_bytes: int = 0

    @property
    def exact(self) -> bool:
        return self.ratio == 1.0 and self.masked_operand_audit.problem_count == 0

    @property
    def first_target_mismatch(self) -> str | None:
        if self.prefix_instructions >= len(self.target_lines):
            return None
        return self.target_lines[self.prefix_instructions]

    @property
    def first_candidate_mismatch(self) -> str | None:
        if self.prefix_instructions >= len(self.candidate_lines):
            return None
        return self.candidate_lines[self.prefix_instructions]

    def diff_lines(self, *, full: bool = False) -> list[str]:
        context = max(len(self.target_lines), len(self.candidate_lines)) if full else 3
        return list(
            difflib.unified_diff(
                self.target_lines,
                self.candidate_lines,
                fromfile="target",
                tofile="candidate",
                lineterm="",
                n=context,
            ),
        )


@dataclass(frozen=True, slots=True)
class DiffRegion:
    target_start: int
    target_end: int
    candidate_start: int
    candidate_end: int
    changed_target_instructions: int
    changed_candidate_instructions: int
    ratio: float
    prefix_instructions: int
    target_lines: tuple[str, ...]
    candidate_lines: tuple[str, ...]
    target_byte_start: int | None = None
    target_byte_end: int | None = None
    candidate_byte_start: int | None = None
    candidate_byte_end: int | None = None
    target_address_start: int | None = None
    target_address_end: int | None = None
    fuzzy_weighted_bytes: float = 0.0
    masked_ok: int = 0
    masked_unresolved: int = 0
    masked_mismatches: int = 0
    hints: tuple[str, ...] = ()

    @property
    def target_span(self) -> str:
        return f"{self.target_start}:{self.target_end}"

    @property
    def candidate_span(self) -> str:
        return f"{self.candidate_start}:{self.candidate_end}"

    @property
    def target_byte_span(self) -> str:
        if self.target_byte_start is None or self.target_byte_end is None:
            return "-"
        return f"0x{self.target_byte_start:x}:0x{self.target_byte_end:x}"

    @property
    def candidate_byte_span(self) -> str:
        if self.candidate_byte_start is None or self.candidate_byte_end is None:
            return "-"
        return f"0x{self.candidate_byte_start:x}:0x{self.candidate_byte_end:x}"

    @property
    def target_address_span(self) -> str:
        if self.target_address_start is None or self.target_address_end is None:
            return "-"
        return f"0x{self.target_address_start:08x}:0x{self.target_address_end:08x}"

    @property
    def target_byte_count(self) -> int:
        if self.target_byte_start is None or self.target_byte_end is None:
            return 0
        return self.target_byte_end - self.target_byte_start


@dataclass(frozen=True, slots=True)
class BasicBlock:
    index: int
    start_instruction: int
    end_instruction: int
    start_offset: int
    end_offset: int
    start_address: int
    end_address: int
    lines: tuple[str, ...]
    successors: tuple[int, ...]
    fallthrough: int | None

    @property
    def canonical_lines(self) -> tuple[str, ...]:
        return tuple(BRANCH_TARGET_RE.sub("LOCAL", line) for line in self.lines)

    @property
    def terminator(self) -> str:
        return self.lines[-1].partition(" ")[0] if self.lines else ""

    @property
    def instruction_count(self) -> int:
        return self.end_instruction - self.start_instruction


@dataclass(frozen=True, slots=True)
class CfgBlockPair:
    target_block: int
    candidate_block: int
    kind: str
    ratio: float
    structure_match: bool
    edge_consistent: bool | None = None
    edge_anchor: bool = False


@dataclass(frozen=True, slots=True)
class CfgAlignment:
    target_blocks: tuple[BasicBlock, ...]
    candidate_blocks: tuple[BasicBlock, ...]
    pairs: tuple[CfgBlockPair, ...]
    unmatched_target: tuple[int, ...]
    unmatched_candidate: tuple[int, ...]

    @property
    def exact_pairs(self) -> int:
        return sum(pair.kind == "exact" for pair in self.pairs)

    @property
    def exact_ambiguous_pairs(self) -> int:
        return sum(pair.kind == "exact-ambiguous" for pair in self.pairs)

    @property
    def similar_pairs(self) -> int:
        return sum(pair.kind == "similar" for pair in self.pairs)


@dataclass(frozen=True, slots=True)
class MatchDump:
    target_lines: tuple[DisassemblyLine, ...]
    candidate_lines: tuple[DisassemblyLine, ...]


def parse_coff_object(data: bytes) -> CoffObject:
    if len(data) < 20:
        raise ValueError("truncated COFF header")
    machine, section_count, _, symtab_offset, symbol_count, optional_header_size, _ = struct.unpack_from(
        "<HHIIIHH",
        data,
        0,
    )
    if machine != IMAGE_FILE_MACHINE_I386:
        raise ValueError(f"expected i386 COFF object, got machine 0x{machine:x}")

    section_headers_end = 20 + optional_header_size + section_count * 40
    if section_headers_end > len(data):
        raise ValueError("truncated COFF section table")
    symbol_table_end = symtab_offset + symbol_count * 18
    if symtab_offset < section_headers_end or symbol_table_end + 4 > len(data):
        raise ValueError("invalid COFF symbol table extent")
    string_table_offset = symtab_offset + symbol_count * 18
    string_table_size = struct.unpack_from("<I", data, string_table_offset)[0]
    if string_table_size < 4 or string_table_offset + string_table_size > len(data):
        raise ValueError("invalid COFF string table extent")
    string_table_end = string_table_offset + string_table_size

    def string_at(offset: int) -> str:
        absolute = string_table_offset + offset
        if offset < 4 or absolute >= string_table_end:
            raise ValueError(f"invalid COFF string offset {offset}")
        end = data.find(b"\x00", absolute, string_table_end)
        if end < 0:
            raise ValueError(f"unterminated COFF string at offset {offset}")
        return data[absolute:end].decode("latin1")

    def symbol_name(raw: bytes) -> str:
        if raw[:4] == b"\x00\x00\x00\x00":
            return string_at(struct.unpack_from("<I", raw, 4)[0])
        return raw.rstrip(b"\x00").decode("latin1")

    symbols: list[CoffSymbol] = []
    index = 0
    while index < symbol_count:
        record = data[symtab_offset + index * 18 : symtab_offset + (index + 1) * 18]
        value, section_number, symbol_type, storage_class, aux_count = struct.unpack_from("<IhHBB", record, 8)
        if index + 1 + aux_count > symbol_count:
            raise ValueError(f"COFF symbol {index} auxiliary records exceed the symbol table")
        aux_records = tuple(
            data[
                symtab_offset + (index + 1 + aux_index) * 18 :
                symtab_offset + (index + 2 + aux_index) * 18
            ]
            for aux_index in range(aux_count)
        )
        weak_default_symbol_index: int | None = None
        weak_search: int | None = None
        if storage_class == 105:
            if section_number != 0 or value != 0 or aux_count != 1:
                raise ValueError(f"COFF weak external {index} has invalid primary or auxiliary fields")
            weak_default_symbol_index, weak_search = struct.unpack_from("<II", aux_records[0], 0)
            if weak_search not in (1, 2, 3):
                raise ValueError(f"COFF weak external {index} has invalid search policy {weak_search}")
        symbols.append(
            CoffSymbol(
                raw_index=index,
                name=symbol_name(record[:8]),
                value=value,
                section_number=section_number,
                symbol_type=symbol_type,
                storage_class=storage_class,
                aux_records=aux_records,
                weak_default_symbol_index=weak_default_symbol_index,
                weak_search=weak_search,
            ),
        )
        index += 1 + aux_count

    symbols_by_raw_index = {symbol.raw_index: symbol for symbol in symbols}
    for symbol in symbols:
        if (
            symbol.storage_class == 105
            and symbol.weak_default_symbol_index not in symbols_by_raw_index
        ):
            raise ValueError(
                f"COFF weak external {symbol.raw_index} fallback "
                f"{symbol.weak_default_symbol_index} is not a primary symbol",
            )

    sections: list[CoffSection] = []
    for section_index in range(section_count):
        header_offset = 20 + optional_header_size + section_index * 40
        name_raw = data[header_offset : header_offset + 8]
        short_name = name_raw.rstrip(b"\x00").decode("latin1")
        if short_name.startswith("/") and short_name[1:].isdigit():
            section_name = string_at(int(short_name[1:], 10))
        else:
            section_name = short_name
        (
            _virtual_size,
            _virtual_address,
            raw_size,
            raw_offset,
            reloc_offset,
            _lines_offset,
            reloc_count,
            _line_count,
            characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", data, header_offset + 8)
        uninitialized = bool(characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        if raw_size and not uninitialized and (
            raw_offset < section_headers_end
            or raw_offset + raw_size > len(data)
        ):
            raise ValueError(f"section {section_name!r} has invalid raw-data extent")
        relocation_overflow = bool(characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
        if relocation_overflow and reloc_count != 0xFFFF:
            raise ValueError(
                f"section {section_name!r} has relocation-overflow flag without count 0xffff",
            )
        relocation_start_index = 0
        relocation_table_count = reloc_count
        if relocation_overflow:
            if reloc_offset < section_headers_end or reloc_offset + 10 > len(data):
                raise ValueError(f"section {section_name!r} has invalid relocation-overflow sentinel")
            extended_count, sentinel_symbol, sentinel_type = struct.unpack_from(
                "<IIH",
                data,
                reloc_offset,
            )
            if extended_count <= 0xFFFF or sentinel_symbol != 0 or sentinel_type != 0:
                raise ValueError(f"section {section_name!r} has invalid relocation-overflow sentinel")
            relocation_start_index = 1
            relocation_table_count = extended_count
        if relocation_table_count and (
            reloc_offset < section_headers_end
            or reloc_offset + relocation_table_count * 10 > len(data)
        ):
            raise ValueError(f"section {section_name!r} has invalid relocation extent")
        relocations = tuple(
            CoffRelocation(*struct.unpack_from("<IIH", data, reloc_offset + i * 10))
            for i in range(relocation_start_index, relocation_table_count)
        )
        if any(relocation.symbol_index not in symbols_by_raw_index for relocation in relocations):
            raise ValueError(f"section {section_name!r} relocation references an invalid symbol index")
        for relocation in relocations:
            width = IMAGE_REL_I386_WIDTHS.get(relocation.relocation_type)
            if width is None:
                raise ValueError(
                    f"section {section_name!r} has unsupported i386 relocation type "
                    f"0x{relocation.relocation_type:x}",
                )
            if relocation.virtual_address + width > raw_size:
                raise ValueError(
                    f"section {section_name!r} relocation at {relocation.virtual_address} "
                    f"with width {width} exceeds section size {raw_size}",
                )
        sections.append(
            CoffSection(
                name=section_name,
                data=(
                    b""
                    if uninitialized
                    else data[raw_offset : raw_offset + raw_size]
                ),
                characteristics=characteristics,
                relocations=relocations,
                index=section_index + 1,
                logical_size=raw_size,
            ),
        )

    for symbol in symbols:
        if symbol.section_number > len(sections) or symbol.section_number < -2:
            raise ValueError(
                f"COFF symbol {symbol.raw_index} references invalid section {symbol.section_number}",
            )
        if symbol.section_number > 0:
            section = sections[symbol.section_number - 1]
            logical_size = section.logical_size or 0
            if symbol.value > logical_size:
                raise ValueError(
                    f"COFF symbol {symbol.raw_index} value {symbol.value} exceeds "
                    f"section {symbol.section_number} size {logical_size}",
                )

    first_symbol_index_by_section: dict[int, int] = {}
    for symbol in symbols:
        if symbol.section_number > 0:
            first_symbol_index_by_section.setdefault(symbol.section_number, symbol.raw_index)

    section_metadata: dict[int, tuple[int, int | None, str | None]] = {}
    for symbol in symbols:
        if (
            symbol.storage_class != IMAGE_SYM_CLASS_STATIC
            or symbol.section_number <= 0
            or symbol.section_number > len(sections)
            or symbol.name != sections[symbol.section_number - 1].name
        ):
            continue
        section = sections[symbol.section_number - 1]
        if not symbol.aux_records:
            continue
        if symbol.value != 0 or symbol.symbol_type != 0:
            raise ValueError(
                f"COFF section symbol {symbol.raw_index} has invalid value or type",
            )
        if len(symbol.aux_records) != 1:
            raise ValueError(
                f"COFF section symbol {symbol.raw_index} must have one auxiliary record",
            )
        associated_section = struct.unpack_from("<h", symbol.aux_records[0], 12)[0]
        selection = symbol.aux_records[0][14]
        is_comdat = bool(section.characteristics & IMAGE_SCN_LNK_COMDAT)
        if selection == 0:
            if is_comdat:
                raise ValueError(
                    f"COMDAT section {section.name!r} has no selection policy",
                )
            continue
        if not 1 <= selection <= 7 or not is_comdat:
            raise ValueError(
                f"section {section.name!r} has invalid COMDAT selection {selection}",
            )
        if first_symbol_index_by_section[symbol.section_number] != symbol.raw_index:
            raise ValueError(
                f"COMDAT section {section.name!r} definition symbol must be first",
            )
        if symbol.section_number in section_metadata:
            raise ValueError(f"section {section.name!r} has duplicate definition symbols")

        comdat_key: str | None = None
        if selection == 5:
            if (
                not 1 <= associated_section <= len(sections)
                or associated_section == symbol.section_number
            ):
                raise ValueError(
                    f"associative COMDAT section {section.name!r} has invalid parent "
                    f"{associated_section}",
                )
        else:
            key_index = symbol.raw_index + 1 + len(symbol.aux_records)
            key_symbol = symbols_by_raw_index.get(key_index)
            if (
                key_symbol is None
                or key_symbol.storage_class
                not in (IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC)
                or key_symbol.section_number != symbol.section_number
                or key_symbol.value != 0
            ):
                raise ValueError(
                    f"COMDAT section {section.name!r} has invalid key symbol",
                )
            comdat_key = key_symbol.name
        section_metadata[symbol.section_number] = (
            selection,
            associated_section if selection == 5 else None,
            comdat_key,
        )

    for section in sections:
        is_comdat = bool(section.characteristics & IMAGE_SCN_LNK_COMDAT)
        if is_comdat and section.index not in section_metadata:
            raise ValueError(f"COMDAT section {section.name!r} has no definition symbol")
    for section_number, (selection, associated_section, _) in section_metadata.items():
        if selection != 5 or associated_section is None:
            continue
        parent = sections[associated_section - 1]
        if not parent.characteristics & IMAGE_SCN_LNK_COMDAT:
            raise ValueError(
                f"associative COMDAT section {section_number} has non-COMDAT parent "
                f"{associated_section}",
            )
        seen: set[int] = set()
        current = section_number
        while current in section_metadata and section_metadata[current][0] == 5:
            if current in seen:
                raise ValueError(f"associative COMDAT cycle at section {current}")
            seen.add(current)
            next_section = section_metadata[current][1]
            if next_section is None:
                break
            current = next_section

    sections = [
        replace(
            section,
            comdat_selection=section_metadata.get(section.index, (None, None, None))[0],
            comdat_associative_section=section_metadata.get(
                section.index,
                (None, None, None),
            )[1],
            comdat_key=section_metadata.get(section.index, (None, None, None))[2],
        )
        for section in sections
    ]
    return CoffObject(sections=tuple(sections), symbols=tuple(symbols))


def _is_function_symbol(symbol: CoffSymbol) -> bool:
    return (
        symbol.section_number > 0
        and symbol.symbol_type & SYM_TYPE_FUNCTION != 0
        and symbol.storage_class in (IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC)
        and re.fullmatch(r"TAG_PACKET_\d+", symbol.name) is None
    )


def _is_code_label_symbol(symbol: CoffSymbol) -> bool:
    return symbol.section_number > 0 and symbol.storage_class == IMAGE_SYM_CLASS_LABEL


def _symbol_matches(symbol_name: str, wanted: str) -> bool:
    return (
        symbol_name == wanted
        or _canonical_symbol_name(symbol_name) == _canonical_symbol_name(wanted)
        or _symbol_lookup_name(symbol_name) == wanted
    )


def _is_import_symbol(name: str) -> bool:
    return name.startswith("__imp_")


def _canonical_symbol_name(name: str) -> str:
    name = name.removeprefix("__imp_")
    name = name.removeprefix("__imp__")
    if name.startswith("?"):
        # Preserve a decorated C++ signature: reducing it to its display name
        # would collapse overloads into the same audit key.
        return name
    name = name.lstrip("_")
    return re.sub(r"@\d+$", "", name)


def _symbol_lookup_name(name: str) -> str:
    canonical = _canonical_symbol_name(name)
    if "@?1??" in canonical:
        # Function-local C++ statics carry their complete enclosing function
        # in the decorated symbol. Preserve that scope: reducing every VC6
        # guard to `$S1` (or every local object to its field name) would make
        # otherwise unrelated compiler locals collide in the symbol oracle.
        return canonical
    if canonical.startswith("?") and (match := re.match(r"^\?([^@]+)@", canonical)):
        return match.group(1)
    return canonical


def _coff_relocation_symbol(
    obj: CoffObject,
    section: CoffSection,
    virtual_address: int,
) -> CoffSymbol | None:
    relocation = next(
        (entry for entry in section.relocations if entry.virtual_address == virtual_address),
        None,
    )
    if relocation is None:
        return None
    return next((symbol for symbol in obj.symbols if symbol.raw_index == relocation.symbol_index), None)


def _coff_vc6_single_delete_unwind_key(obj: CoffObject, symbol: CoffSymbol) -> str | None:
    """Recognize a complete VC6 C++ frame-handler graph in a COFF object.

    The pushed handler address is target-specific, but its thunk, FuncInfo,
    unwind-map entry, and cleanup funclet are deterministic. Recognizing the
    whole graph avoids accepting an arbitrary compiler-local ``$L`` label.
    """

    if not symbol.name.startswith("$L") or symbol.section_number <= 0:
        return None
    handler_section = obj.sections[symbol.section_number - 1]
    handler = handler_section.data[symbol.value : symbol.value + 10]
    if len(handler) != 10 or handler[:1] != b"\xb8" or handler[5:6] != b"\xe9":
        return None
    if handler[1:5] != b"\x00" * 4 or handler[6:10] != b"\x00" * 4:
        return None

    func_info_symbol = _coff_relocation_symbol(obj, handler_section, symbol.value + 1)
    frame_handler_symbol = _coff_relocation_symbol(obj, handler_section, symbol.value + 6)
    if (
        func_info_symbol is None
        or func_info_symbol.section_number <= 0
        or frame_handler_symbol is None
        or _symbol_lookup_name(frame_handler_symbol.name) != "CxxFrameHandler"
    ):
        return None

    func_info_section = obj.sections[func_info_symbol.section_number - 1]
    base = func_info_symbol.value
    func_info = func_info_section.data[base : base + 40]
    if len(func_info) != 40:
        return None
    if struct.unpack_from("<II", func_info) != (0x19930520, 1):
        return None
    if func_info[8:12] != b"\x00" * 4 or func_info[36:40] != b"\x00" * 4:
        return None
    if func_info[12:32] != b"\x00" * 20 or struct.unpack_from("<i", func_info, 32)[0] != -1:
        return None

    unwind_map_symbol = _coff_relocation_symbol(obj, func_info_section, base + 8)
    cleanup_symbol = _coff_relocation_symbol(obj, func_info_section, base + 36)
    if (
        unwind_map_symbol is None
        or unwind_map_symbol.section_number != func_info_symbol.section_number
        or unwind_map_symbol.value != base + 32
        or cleanup_symbol is None
        or cleanup_symbol.section_number <= 0
    ):
        return None

    cleanup_section = obj.sections[cleanup_symbol.section_number - 1]
    cleanup = cleanup_section.data[cleanup_symbol.value : cleanup_symbol.value + 11]
    if cleanup[:2] != bytes.fromhex("8b45") or cleanup[3:5] != bytes.fromhex("50e8"):
        return None
    if cleanup[5:9] != b"\x00" * 4 or cleanup[9:] != bytes.fromhex("59c3"):
        return None
    delete_symbol = _coff_relocation_symbol(obj, cleanup_section, cleanup_symbol.value + 5)
    if delete_symbol is None or not delete_symbol.name.startswith("??3@"):
        return None
    return f"{VC6_SINGLE_DELETE_UNWIND_KEY}:ebp+0x{cleanup[2]:02x}"


def _vc6_frame_slot_key(displacement: int) -> str:
    signed = displacement if displacement < 0x80 else displacement - 0x100
    operator = "+" if signed >= 0 else "-"
    return f"ebp{operator}0x{abs(signed):02x}"


def _coff_vc6_unwind_only_key(
    obj: CoffObject,
    function: CoffSymbol,
    function_end: int,
    symbol: CoffSymbol,
) -> str | None:
    """Recognize a one-state VC6 base-destructor cleanup graph.

    The compiler-local handler address is not a selectable function symbol.
    Accept it only when the complete graph is present and its cleanup tail
    reaches the same external destructor referenced by the protected function.
    """

    if not symbol.name.startswith("$L") or symbol.section_number <= 0:
        return None
    handler_section = obj.sections[symbol.section_number - 1]
    handler = handler_section.data[symbol.value : symbol.value + 10]
    if len(handler) != 10 or handler[:1] != b"\xb8" or handler[5:6] != b"\xe9":
        return None
    if handler[1:5] != b"\x00" * 4 or handler[6:10] != b"\x00" * 4:
        return None

    func_info_symbol = _coff_relocation_symbol(obj, handler_section, symbol.value + 1)
    frame_handler_symbol = _coff_relocation_symbol(obj, handler_section, symbol.value + 6)
    if (
        func_info_symbol is None
        or func_info_symbol.section_number <= 0
        or frame_handler_symbol is None
        or _symbol_lookup_name(frame_handler_symbol.name) != "CxxFrameHandler"
    ):
        return None

    func_info_section = obj.sections[func_info_symbol.section_number - 1]
    base = func_info_symbol.value
    # VC6 consumes 28 bytes here. Do not inspect the following contribution:
    # the linker is free to place an unrelated unwind-map entry immediately
    # after this FuncInfo record.
    func_info = func_info_section.data[base : base + 28]
    if len(func_info) != 28 or struct.unpack_from("<II", func_info) != (0x19930520, 1):
        return None
    if func_info[8:12] != b"\x00" * 4 or func_info[12:28] != b"\x00" * 16:
        return None

    unwind_map_symbol = _coff_relocation_symbol(obj, func_info_section, base + 8)
    if unwind_map_symbol is None or unwind_map_symbol.section_number <= 0:
        return None
    unwind_map_section = obj.sections[unwind_map_symbol.section_number - 1]
    unwind_base = unwind_map_symbol.value
    unwind_entry = unwind_map_section.data[unwind_base : unwind_base + 8]
    if len(unwind_entry) != 8 or struct.unpack_from("<i", unwind_entry)[0] != -1:
        return None
    if unwind_entry[4:8] != b"\x00" * 4:
        return None

    cleanup_symbol = _coff_relocation_symbol(obj, unwind_map_section, unwind_base + 4)
    if cleanup_symbol is None or cleanup_symbol.section_number <= 0:
        return None
    cleanup_section = obj.sections[cleanup_symbol.section_number - 1]
    cleanup = cleanup_section.data[cleanup_symbol.value : cleanup_symbol.value + 8]
    if len(cleanup) != 8 or cleanup[:2] != bytes.fromhex("8b4d"):
        return None
    if cleanup[3:4] != b"\xe9" or cleanup[4:8] != b"\x00" * 4:
        return None

    cleanup_target = _coff_relocation_symbol(obj, cleanup_section, cleanup_symbol.value + 4)
    if (
        cleanup_target is None
        or cleanup_target.storage_class != IMAGE_SYM_CLASS_EXTERNAL
        or cleanup_target.symbol_type & SYM_TYPE_FUNCTION == 0
        or not cleanup_target.name.startswith("??1")
        or function.section_number <= 0
    ):
        return None
    function_section = obj.sections[function.section_number - 1]
    if not any(
        function.value <= relocation.virtual_address < function_end
        and relocation.symbol_index == cleanup_target.raw_index
        for relocation in function_section.relocations
    ):
        return None
    return f"{VC6_UNWIND_ONLY_KEY}:ecx=[{_vc6_frame_slot_key(cleanup[2])}]"


def _local_jump_table_key(offsets: list[int]) -> str | None:
    if len(offsets) < 2:
        return None
    return f"{VC6_LOCAL_JUMP_TABLE_KEY}:" + ",".join(f"0x{offset:x}" for offset in offsets)


def _local_switch_partition_key(indices: bytes, offsets: Collection[int]) -> str | None:
    """Describe a sparse switch by the equivalence classes of its destinations."""

    destinations = tuple(offsets)
    if len(indices) < 4 or len(destinations) < 2 or any(index >= len(destinations) for index in indices):
        return None
    classes: dict[int, int] = {}
    partition = bytes(classes.setdefault(destinations[index], len(classes)) for index in indices)
    if len(classes) < 2:
        return None
    return f"{VC6_LOCAL_SWITCH_PARTITION_KEY}:{partition.hex()}"


def _coff_local_jump_table_offsets(
    obj: CoffObject,
    function: CoffSymbol,
    table: CoffSymbol,
    addend: int = 0,
) -> tuple[int, ...]:
    """Return a compiler-local absolute switch table's function-relative targets."""

    if (
        not table.name.startswith("$L")
        or function.section_number <= 0
        or table.section_number != function.section_number
    ):
        return ()
    section = obj.sections[table.section_number - 1]
    table_start = table.value + addend
    if table_start < function.value or table_start >= len(section.data):
        return ()

    symbols_by_raw_index = {symbol.raw_index: symbol for symbol in obj.symbols}
    relocations_by_offset = {relocation.virtual_address: relocation for relocation in section.relocations}
    offsets: list[int] = []
    cursor = table_start
    for _ in range(256):
        relocation = relocations_by_offset.get(cursor)
        if relocation is None or cursor + 4 > len(section.data):
            break
        target = symbols_by_raw_index.get(relocation.symbol_index)
        if target is None or target.section_number != function.section_number:
            break
        entry_addend = struct.unpack_from("<i", section.data, cursor)[0]
        destination = target.value + entry_addend
        if destination < function.value or destination >= table_start:
            break
        offsets.append(destination - function.value)
        cursor += 4
    return tuple(offsets)


def _coff_local_jump_table_key(
    obj: CoffObject,
    function: CoffSymbol,
    table: CoffSymbol,
    addend: int = 0,
) -> str | None:
    """Describe a compiler-local absolute switch table by its function-relative targets."""

    return _local_jump_table_key(list(_coff_local_jump_table_offsets(obj, function, table, addend)))


def _coff_local_switch_partition_keys(
    obj: CoffObject,
    function: CoffSymbol,
    end: int,
) -> dict[tuple[int, int], str]:
    """Key paired VC6 byte lookup and jump tables by their effective dispatch partition."""

    if function.section_number <= 0:
        return {}
    section = obj.sections[function.section_number - 1]
    symbols_by_raw_index = {symbol.raw_index: symbol for symbol in obj.symbols}
    references: list[tuple[CoffSymbol, int]] = []
    for relocation in section.relocations:
        if not (function.value <= relocation.virtual_address < end):
            continue
        symbol = symbols_by_raw_index.get(relocation.symbol_index)
        if symbol is None or relocation.virtual_address + 4 > len(section.data):
            continue
        addend = struct.unpack_from("<i", section.data, relocation.virtual_address)[0]
        references.append((symbol, addend))

    keys: dict[tuple[int, int], str] = {}
    for table, table_addend in references:
        offsets = _coff_local_jump_table_offsets(obj, function, table, table_addend)
        table_start = table.value + table_addend
        if len(offsets) < 2 or table_start < end:
            continue
        lookup_start = table_start + len(offsets) * 4
        lookup_reference = next(
            (
                (symbol, addend)
                for symbol, addend in references
                if symbol.section_number == function.section_number
                and symbol.name.startswith("$L")
                and symbol.value + addend == lookup_start
            ),
            None,
        )
        if lookup_reference is None:
            continue
        lookup, lookup_addend = lookup_reference
        lookup_end = min(
            (
                symbol.value
                for symbol in obj.symbols
                if symbol.section_number == lookup.section_number and symbol.value > lookup_start
            ),
            default=len(section.data),
        )
        available = section.data[lookup_start:lookup_end]
        indices_end = next((index for index, value in enumerate(available) if value >= len(offsets)), len(available))
        indices = available[:indices_end]
        if partition_key := _local_switch_partition_key(indices, offsets):
            keys[(table.raw_index, table_addend)] = partition_key
            keys[(lookup.raw_index, lookup_addend)] = partition_key
    return keys


def _coff_trailing_jump_table_start(
    obj: CoffObject,
    function: CoffSymbol,
    end: int,
) -> int | None:
    """Return the first complete compiler-local switch table appended to a function."""

    section = obj.sections[function.section_number - 1]
    symbols_by_raw_index = {symbol.raw_index: symbol for symbol in obj.symbols}
    starts: list[int] = []
    for relocation in section.relocations:
        if not (function.value <= relocation.virtual_address < end):
            continue
        table = symbols_by_raw_index.get(relocation.symbol_index)
        if table is None or relocation.virtual_address + 4 > len(section.data):
            continue
        addend = struct.unpack_from("<i", section.data, relocation.virtual_address)[0]
        table_start = table.value + addend
        if not (relocation.virtual_address < table_start < end):
            continue
        if _coff_local_jump_table_key(obj, function, table, addend) is not None:
            starts.append(table_start)
    return min(starts, default=None)


def _image_local_jump_table_offsets(
    image: LoadedImage | None,
    table_address: int,
    function_start: int,
    function_end: int,
) -> tuple[int, ...]:
    """Return a linked absolute switch table's function-relative targets."""

    if image is None or function_end <= function_start:
        return ()
    offsets: list[int] = []
    for index in range(256):
        raw = _image_bytes(image, table_address + index * 4, 4)
        if raw is None:
            break
        destination = struct.unpack("<I", raw)[0]
        if destination < function_start or destination >= function_end:
            break
        offsets.append(destination - function_start)
    return tuple(offsets)


def _image_local_jump_table_key(
    image: LoadedImage | None,
    table_address: int,
    function_start: int,
    function_end: int,
) -> str | None:
    """Describe a linked absolute switch table by its function-relative targets."""

    return _local_jump_table_key(
        list(_image_local_jump_table_offsets(image, table_address, function_start, function_end)),
    )


def _image_local_switch_partition_key_from_table(
    image: LoadedImage | None,
    table_address: int,
    function_start: int,
    function_end: int,
    reference_catalog: ReferenceCatalog | None = None,
) -> str | None:
    """Describe a linked VC6 sparse switch whose byte lookup follows its jump table."""

    if image is None or table_address < function_end:
        return None
    offsets = _image_local_jump_table_offsets(image, table_address, function_start, function_end)
    if len(offsets) < 2:
        return None
    lookup_address = table_address + len(offsets) * 4
    return _image_local_switch_partition_key(
        image,
        lookup_address,
        offsets,
        reference_catalog=reference_catalog,
    )


def _image_local_switch_partition_key_from_lookup(
    image: LoadedImage | None,
    lookup_address: int,
    function_start: int,
    function_end: int,
    reference_catalog: ReferenceCatalog | None = None,
) -> str | None:
    """Describe a linked VC6 sparse switch from a lookup table following absolute targets."""

    if image is None or function_end <= function_start:
        return None
    reverse_offsets: list[int] = []
    for index in range(1, 257):
        raw = _image_bytes(image, lookup_address - index * 4, 4)
        if raw is None:
            break
        destination = struct.unpack("<I", raw)[0]
        if destination < function_start or destination >= function_end:
            break
        reverse_offsets.append(destination - function_start)
    offsets = tuple(reversed(reverse_offsets))
    if len(offsets) < 2:
        return None
    table_address = lookup_address - len(offsets) * 4
    if table_address < function_end:
        return None
    return _image_local_switch_partition_key(
        image,
        lookup_address,
        offsets,
        reference_catalog=reference_catalog,
    )


def _image_local_switch_partition_key(
    image: LoadedImage,
    lookup_address: int,
    offsets: Collection[int],
    *,
    reference_catalog: ReferenceCatalog | None,
) -> str | None:
    """Key a linked byte lookup, optionally bounded by the next known symbol."""

    lookup_offset = lookup_address - image.image_base
    if lookup_offset < 0 or lookup_offset >= len(image.mapped):
        return None
    lookup_limit = 256
    if reference_catalog is not None:
        next_address = min(
            (address for address in reference_catalog.names_by_address if address > lookup_address),
            default=None,
        )
        if next_address is not None:
            lookup_limit = min(lookup_limit, next_address - lookup_address)
    available = image.mapped[lookup_offset : lookup_offset + lookup_limit]
    lookup_end = next((index for index, value in enumerate(available) if value >= len(offsets)), len(available))
    return _local_switch_partition_key(available[:lookup_end], offsets)


def _object_reference_key(symbol: CoffSymbol, addend: int) -> tuple[str | None, bool]:
    if symbol.name.startswith(("$L", "??_C@", "__real@")) or not symbol.name:
        return None, False
    canonical = _canonical_symbol_name(symbol.name)
    if not canonical:
        return None, False
    return f"name:{canonical}{_format_addend(addend)}", True


def _is_vc_exception_chain_reference(reference: ObjectRelocationReference | None) -> bool:
    """Return whether a COFF relocation denotes the x86 FS exception-chain head.

    VC6 emits relocations against the absolute ``__except_list`` symbol for
    ``fs:[0]``. The PE linker resolves that symbol to numeric zero, so retaining
    an ``ADDR`` placeholder would create a false instruction mismatch against
    the linked image.
    """

    return reference is not None and reference.symbol_name == "__except_list"


def _format_addend(addend: int) -> str:
    if addend == 0:
        return ""
    operator = "+" if addend > 0 else "-"
    return f"{operator}0x{abs(addend):x}"


def _coff_implicit_direct_branch_references(
    obj: CoffObject,
    target: CoffSymbol,
    end: int,
    *,
    explicit_offsets: frozenset[int],
) -> tuple[ObjectRelocationReference, ...]:
    """Recover same-section branches resolved by the VC6 assembler.

    MASM can encode a direct relative call or jump between symbols in one
    ``.text`` section without leaving a COFF relocation. Accept destinations
    that remain inside that section, recording a symbol when one is
    unambiguous and otherwise preserving the exact entry-relative offset.
    Destinations outside the section remain literal and continue to mismatch.
    """

    try:
        import capstone
    except ModuleNotFoundError as exc:
        raise RuntimeError("capstone is required for matching; run `uv sync --dev`") from exc

    section = obj.sections[target.section_number - 1]
    symbols_by_value: dict[int, list[CoffSymbol]] = defaultdict(list)
    function_symbols_by_value: dict[int, list[CoffSymbol]] = defaultdict(list)
    for symbol in obj.symbols:
        if (
            symbol.section_number == target.section_number
            and (_is_function_symbol(symbol) or _is_code_label_symbol(symbol))
        ):
            symbols_by_value[symbol.value].append(symbol)
            if _is_function_symbol(symbol):
                function_symbols_by_value[symbol.value].append(symbol)
    function_starts = sorted(function_symbols_by_value)

    def destination_symbol(address: int) -> tuple[CoffSymbol, int] | None:
        exact = {
            symbol.name: symbol
            for symbol in symbols_by_value.get(address, ())
            if symbol.name
        }
        if len(exact) == 1:
            return next(iter(exact.values())), 0
        if exact:
            return None

        owner_start = max(
            (value for value in function_starts if value < address),
            default=None,
        )
        if owner_start is None:
            return None
        owner_end = min(
            (value for value in function_starts if value > owner_start),
            default=len(section.data),
        )
        if address >= owner_end:
            return None
        owners = {
            symbol.name: symbol
            for symbol in function_symbols_by_value[owner_start]
            if symbol.name
        }
        if len(owners) != 1:
            return None
        return next(iter(owners.values())), address - owner_start

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    references: list[ObjectRelocationReference] = []
    for instruction in md.disasm(section.data[target.value : end], target.value):
        if not (
            capstone.CS_GRP_JUMP in instruction.groups
            or capstone.CS_GRP_CALL in instruction.groups
        ):
            continue
        immediate_operands = [
            operand
            for operand in instruction.operands
            if operand.type == capstone.x86.X86_OP_IMM
        ]
        if len(immediate_operands) != 1 or not instruction.imm_offset:
            continue
        offset = instruction.address - target.value + instruction.imm_offset
        if any(
            offset + delta in explicit_offsets
            for delta in range(max(instruction.imm_size, 1))
        ):
            continue
        destination = int(immediate_operands[0].imm)
        if target.value <= destination < end:
            continue
        resolved = destination_symbol(destination)
        if resolved is None and not 0 <= destination < len(section.data):
            continue
        if resolved is None:
            symbol_name = f"{section.name}+0x{destination:x}"
            addend = 0
            key = None
            explained = True
        else:
            symbol, addend = resolved
            symbol_name = symbol.name
            key, explained = _object_reference_key(symbol, addend)
        references.append(
            ObjectRelocationReference(
                offset=offset,
                symbol_name=symbol_name,
                key=key,
                explained=explained,
                addend=addend,
                local_target_offset=destination - target.value,
            ),
        )
    return tuple(references)


def extract_object_function(
    obj: CoffObject,
    name: str | None = None,
    *,
    extent: str = "symbol",
    end_symbol: str | None = None,
    size: int | None = None,
) -> ObjectFunction:
    if extent not in ARCHIVE_EXTENT_VALUES:
        allowed = ", ".join(sorted(ARCHIVE_EXTENT_VALUES))
        raise ValueError(f"invalid object function extent {extent!r}; use {allowed}")
    if end_symbol is not None and extent != "symbol":
        raise ValueError("object end symbol cannot be combined with a non-symbol extent")
    if size is not None:
        if extent != "symbol":
            raise ValueError("object symbol size cannot be combined with a non-symbol extent")
        if end_symbol is not None:
            raise ValueError("object symbol size cannot be combined with an end symbol")
        if size <= 0:
            raise ValueError("object symbol size must be positive")
    explicit_code_label = False
    candidates = [symbol for symbol in obj.symbols if _is_function_symbol(symbol)]
    if name is not None:
        exact = [symbol for symbol in candidates if symbol.name == name]
        candidates = exact or [symbol for symbol in candidates if _symbol_matches(symbol.name, name)]
        if not candidates:
            candidates = [
                symbol
                for symbol in obj.symbols
                if symbol.name == name and _is_code_label_symbol(symbol)
            ]
            explicit_code_label = bool(candidates)
    if not candidates:
        raise ValueError(f"no matching function symbol (name={name!r})")
    if len(candidates) > 1 and name is not None:
        exact = [
            symbol
            for symbol in candidates
            if symbol.name == f"_{name}" or symbol.name.startswith((f"?{name}@@", f"_{name}@"))
        ]
        if len(exact) == 1:
            candidates = exact
    if len(candidates) > 1:
        names = ", ".join(symbol.name for symbol in candidates)
        raise ValueError(f"ambiguous function symbol, candidates: {names}")

    target = candidates[0]
    section = obj.sections[target.section_number - 1]
    if section.characteristics & IMAGE_SCN_CNT_CODE == 0:
        raise ValueError(f"symbol {target.name!r} is not in a code section")

    siblings = sorted(
        symbol.value
        for symbol in obj.symbols
        if (_is_function_symbol(symbol) or (explicit_code_label and _is_code_label_symbol(symbol)))
        and symbol.section_number == target.section_number
        and symbol.value > target.value
    )
    if size is not None:
        end = target.value + size
        if end > len(section.data):
            raise ValueError(
                f"symbol {target.name!r} size {size} exceeds section {section.name!r}",
            )
    elif end_symbol is not None:
        end_candidates = [
            symbol
            for symbol in obj.symbols
            if symbol.name == end_symbol
            and symbol.section_number == target.section_number
            and (_is_function_symbol(symbol) or _is_code_label_symbol(symbol))
        ]
        if len(end_candidates) != 1:
            raise ValueError(
                f"end symbol {end_symbol!r} must name exactly one code symbol "
                f"in section {section.name!r}",
            )
        end = end_candidates[0].value
        if not target.value < end <= len(section.data):
            raise ValueError(
                f"end symbol {end_symbol!r} must follow function symbol {target.name!r}",
            )
    elif extent == "section-tail" or not siblings:
        end = len(section.data)
    else:
        end = siblings[0]
    if (jump_table_start := _coff_trailing_jump_table_start(obj, target, end)) is not None:
        end = jump_table_start
    symbols_by_raw_index = {symbol.raw_index: symbol for symbol in obj.symbols}
    switch_partition_keys = _coff_local_switch_partition_keys(obj, target, end)
    relocation_references: list[ObjectRelocationReference] = []
    for relocation in section.relocations:
        if not (target.value <= relocation.virtual_address < end):
            continue
        offset = relocation.virtual_address - target.value
        symbol = symbols_by_raw_index.get(relocation.symbol_index)
        if symbol is None:
            relocation_references.append(
                ObjectRelocationReference(
                    offset=offset,
                    symbol_name=f"<symbol#{relocation.symbol_index}>",
                    key=None,
                    explained=False,
                ),
            )
            continue
        addend = struct.unpack_from("<i", section.data, relocation.virtual_address)[0]
        key, explained = _object_reference_key(symbol, addend)
        alternate_keys: tuple[str, ...] = ()
        compiler_key = _coff_vc6_unwind_only_key(
            obj,
            target,
            end,
            symbol,
        ) or _coff_vc6_single_delete_unwind_key(obj, symbol)
        if compiler_key:
            key = compiler_key
            explained = True
        elif switch_partition_key := switch_partition_keys.get((symbol.raw_index, addend)):
            if jump_table_key := _coff_local_jump_table_key(obj, target, symbol, addend):
                key = jump_table_key
                alternate_keys = (switch_partition_key,)
            else:
                key = switch_partition_key
            explained = True
        elif jump_table_key := _coff_local_jump_table_key(obj, target, symbol, addend):
            key = jump_table_key
            explained = True
        symbol_section = obj.sections[symbol.section_number - 1] if symbol.section_number > 0 else None
        symbol_end = (
            min(
                (
                    sibling.value
                    for sibling in obj.symbols
                    if sibling.section_number == symbol.section_number and sibling.value > symbol.value
                ),
                default=len(symbol_section.data),
            )
            if symbol_section is not None
            else None
        )
        relocation_references.append(
            ObjectRelocationReference(
                offset=offset,
                symbol_name=symbol.name,
                key=key,
                explained=explained,
                addend=addend,
                symbol_data=(
                    symbol_section.data[symbol.value : symbol_end]
                    if symbol_section is not None and symbol_end is not None
                    else None
                ),
                read_only_data=(
                    symbol_section is not None
                    and symbol_section.name.startswith(".rdata")
                    and symbol.storage_class == IMAGE_SYM_CLASS_STATIC
                    and symbol_section.characteristics & IMAGE_SCN_MEM_WRITE == 0
                ),
                local_target_offset=(
                    symbol.value + addend - target.value
                    if (
                        relocation.relocation_type == IMAGE_REL_I386_REL32
                        or (
                            relocation.relocation_type == IMAGE_REL_I386_DIR32
                            and symbol.storage_class != IMAGE_SYM_CLASS_EXTERNAL
                        )
                    )
                    and symbol.section_number == target.section_number
                    and target.value <= symbol.value + addend < end
                    else None
                ),
                relocation_type=relocation.relocation_type,
                alternate_keys=alternate_keys,
            ),
        )
    explicit_offsets = frozenset(reference.offset for reference in relocation_references)
    relocation_references.extend(
        _coff_implicit_direct_branch_references(
            obj,
            target,
            end,
            explicit_offsets=explicit_offsets,
        ),
    )
    relocation_references.sort(key=lambda reference: reference.offset)
    return ObjectFunction(
        name=target.name,
        data=section.data[target.value : end].rstrip(PADDING_BYTES),
        relocation_offsets=frozenset(reference.offset for reference in relocation_references),
        relocation_references=tuple(relocation_references),
    )


def load_image(path: Path, image_base: int | None = None) -> LoadedImage:
    try:
        import pefile
    except ModuleNotFoundError as exc:
        raise RuntimeError("pefile is required for matching; run `uv sync --dev`") from exc

    pe = pefile.PE(data=Path(path).read_bytes(), fast_load=True)
    resolved_base = int(image_base if image_base is not None else pe.OPTIONAL_HEADER.ImageBase)
    return LoadedImage(
        mapped=pe.get_memory_mapped_image(ImageBase=resolved_base),
        image_base=resolved_base,
        size_of_image=int(pe.OPTIONAL_HEADER.SizeOfImage),
    )


_OPERAND_SIZE_NAMES = {1: "byte", 2: "word", 4: "dword", 8: "qword", 10: "tword"}
_MAX_AUDITED_STRING_BYTES = 0x1000


def _printable_string_key(data: bytes) -> str | None:
    end = data.find(b"\x00", 0, _MAX_AUDITED_STRING_BYTES + 1)
    if end <= 0:
        return None
    raw = data[:end]
    if any((byte < 0x20 and byte not in b"\t\n\r") or byte > 0x7E for byte in raw):
        return None
    return f"string:{json.dumps(raw.decode('ascii'), ensure_ascii=True)}"


def _image_bytes(image: LoadedImage | None, address: int, byte_count: int) -> bytes | None:
    if image is None:
        return None
    offset = address - image.image_base
    if offset < 0 or offset + byte_count > len(image.mapped):
        return None
    return image.mapped[offset : offset + byte_count]


def _image_vc6_single_delete_unwind_key(
    image: LoadedImage | None,
    reference_catalog: ReferenceCatalog | None,
    address: int,
) -> str | None:
    if image is None or reference_catalog is None:
        return None
    handler = _image_bytes(image, address, 10)
    if handler is None or handler[:1] != b"\xb8" or handler[5:6] != b"\xe9":
        return None

    func_info_address = struct.unpack_from("<I", handler, 1)[0]
    frame_handler_address = address + 10 + struct.unpack_from("<i", handler, 6)[0]
    if not any(
        _symbol_lookup_name(name) == "CxxFrameHandler"
        for name in reference_catalog.names_by_address.get(frame_handler_address, ())
    ):
        return None

    func_info = _image_bytes(image, func_info_address, 40)
    if func_info is None or struct.unpack_from("<II", func_info) != (0x19930520, 1):
        return None
    if func_info[12:32] != b"\x00" * 20 or struct.unpack_from("<i", func_info, 32)[0] != -1:
        return None
    if struct.unpack_from("<I", func_info, 8)[0] != func_info_address + 32:
        return None

    cleanup_address = struct.unpack_from("<I", func_info, 36)[0]
    cleanup = _image_bytes(image, cleanup_address, 11)
    if cleanup is None or cleanup[:2] != bytes.fromhex("8b45") or cleanup[3:5] != bytes.fromhex("50e8"):
        return None
    if cleanup[9:] != bytes.fromhex("59c3"):
        return None
    delete_address = cleanup_address + 9 + struct.unpack_from("<i", cleanup, 5)[0]
    if not any(name.startswith("??3@") for name in reference_catalog.names_by_address.get(delete_address, ())):
        return None
    return f"{VC6_SINGLE_DELETE_UNWIND_KEY}:ebp+0x{cleanup[2]:02x}"


def _image_vc6_unwind_only_key(
    image: LoadedImage | None,
    reference_catalog: ReferenceCatalog | None,
    address: int,
    direct_branch_targets: Collection[int],
) -> str | None:
    if image is None or reference_catalog is None:
        return None
    handler = _image_bytes(image, address, 10)
    if handler is None or handler[:1] != b"\xb8" or handler[5:6] != b"\xe9":
        return None

    func_info_address = struct.unpack_from("<I", handler, 1)[0]
    frame_handler_address = address + 10 + struct.unpack_from("<i", handler, 6)[0]
    if not any(
        _symbol_lookup_name(name) == "CxxFrameHandler"
        for name in reference_catalog.names_by_address.get(frame_handler_address, ())
    ):
        return None

    func_info = _image_bytes(image, func_info_address, 28)
    if func_info is None or struct.unpack_from("<II", func_info) != (0x19930520, 1):
        return None
    if func_info[12:28] != b"\x00" * 16:
        return None

    unwind_map_address = struct.unpack_from("<I", func_info, 8)[0]
    unwind_entry = _image_bytes(image, unwind_map_address, 8)
    if unwind_entry is None or struct.unpack_from("<i", unwind_entry)[0] != -1:
        return None
    cleanup_address = struct.unpack_from("<I", unwind_entry, 4)[0]
    cleanup = _image_bytes(image, cleanup_address, 8)
    if cleanup is None or cleanup[:2] != bytes.fromhex("8b4d") or cleanup[3:4] != b"\xe9":
        return None

    cleanup_target = cleanup_address + 8 + struct.unpack_from("<i", cleanup, 4)[0]
    if cleanup_target not in direct_branch_targets:
        return None
    return f"{VC6_UNWIND_ONLY_KEY}:ecx=[{_vc6_frame_slot_key(cleanup[2])}]"


def _format_memory_operand(insn, operand, masked_disp: bool) -> str:
    mem = operand.mem
    parts: list[str] = []
    base_name = insn.reg_name(mem.base) if mem.base != 0 else None
    index_name = insn.reg_name(mem.index) if mem.index != 0 else None
    frame_registers = {"ebp", "esp"}
    if (
        base_name is not None
        and index_name is not None
        and mem.scale == 1
        and base_name not in frame_registers
        and index_name not in frame_registers
    ):
        # A scale-one SIB computes base + index regardless of which register
        # occupies either encoding field. Preserve EBP/ESP roles because
        # swapping the architectural base can change the default segment.
        base_name, index_name = sorted((base_name, index_name))
    if base_name is not None:
        parts.append(base_name)
    if index_name is not None:
        parts.append(f"{index_name}*{mem.scale}")
    if masked_disp:
        parts.append("ADDR")
    elif mem.disp != 0 or not parts:
        parts.append(f"0x{mem.disp:x}" if mem.disp >= 0 else f"-0x{-mem.disp:x}")
    size = _OPERAND_SIZE_NAMES.get(operand.size, str(operand.size))
    return f"{size} [{'+'.join(parts)}]"


def disassemble_normalized_function(
    data: bytes,
    *,
    relocation_offsets: frozenset[int] | None = None,
    relocation_references: tuple[ObjectRelocationReference, ...] = (),
    address_range: tuple[int, int] | None = None,
    base_address: int = 0,
    reference_catalog: ReferenceCatalog | None = None,
    image: LoadedImage | None = None,
) -> tuple[DisassemblyLine, ...]:
    try:
        import capstone
    except ModuleNotFoundError as exc:
        raise RuntimeError("capstone is required for matching; run `uv sync --dev`") from exc

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    relocation_offsets = relocation_offsets or frozenset()
    relocation_by_offset = {reference.offset: reference for reference in relocation_references}
    size = len(data)
    instructions = tuple(md.disasm(data, base_address))
    direct_branch_targets = (
        frozenset(
            int(operand.imm)
            for instruction in instructions
            if capstone.CS_GRP_JUMP in instruction.groups
            or capstone.CS_GRP_CALL in instruction.groups
            for operand in instruction.operands
            if operand.type == capstone.x86.X86_OP_IMM
        )
        if image is not None and reference_catalog is not None
        else frozenset()
    )

    def is_masked_value(value: int) -> bool:
        return address_range is not None and address_range[0] <= value < address_range[1]

    def relocation_in_span(start: int, byte_count: int) -> ObjectRelocationReference | None:
        return next(
            (
                relocation_by_offset[offset]
                for offset in range(start, start + max(byte_count, 1))
                if offset in relocation_by_offset
            ),
            None,
        )

    def object_reference(
        reference: ObjectRelocationReference | None,
        *,
        operand_index: int,
        kind: str,
        byte_count: int,
    ) -> MaskedReference:
        if reference is None:
            return MaskedReference(
                operand_index=operand_index,
                kind=kind,
                source="reloc",
                value=None,
                text="<unknown relocation>",
                keys=(),
                explained=False,
            )
        keys = (reference.key,) if reference.key is not None else ()
        keys = tuple(dict.fromkeys((*keys, *reference.alternate_keys)))
        explained = reference.explained
        symbol_data = reference.symbol_data or b""
        if reference.local_target_offset is not None:
            keys = (f"local:{reference.local_target_offset:+#x}",)
            explained = True
        elif reference.symbol_name.startswith("??_C@") and (string_key := _printable_string_key(symbol_data)):
            keys = (string_key,)
            explained = True
        elif reference.symbol_name.startswith("__real@") and len(symbol_data) >= byte_count:
            keys = (f"bytes{byte_count}:{symbol_data[:byte_count].hex()}",)
            explained = True
        elif reference.key is not None and reference.key.startswith("compiler:vc6-"):
            pass
        elif reference_catalog is not None and reference_catalog.knows_name(
            reference.symbol_name,
        ):
            keys = reference_catalog.keys_for_object_reference(
                reference.symbol_name,
                reference.addend or 0,
            )
            explained = True
        elif reference.read_only_data:
            data_offset = reference.addend or 0
            if 0 <= data_offset and data_offset + byte_count <= len(symbol_data):
                keys = (
                    f"bytes{byte_count}:{symbol_data[data_offset : data_offset + byte_count].hex()}",
                )
                explained = True
            else:
                explained = False
        elif reference_catalog is not None:
            explained = False
        return MaskedReference(
            operand_index=operand_index,
            kind=kind,
            source="reloc",
            value=None,
            text=reference.symbol_name,
            keys=keys,
            explained=explained,
        )

    def image_reference(
        value: int,
        *,
        operand_index: int,
        kind: str,
        byte_count: int | None = None,
    ) -> MaskedReference:
        keys = list(reference_catalog.keys_for_address(value) if reference_catalog is not None else ())
        keys.append(f"local:{value - base_address:+#x}")
        if image is not None:
            available = image.mapped[value - image.image_base :] if image.image_base <= value else b""
            if string_key := _printable_string_key(available):
                keys.append(string_key)
            if byte_count is not None and (raw := _image_bytes(image, value, byte_count)) is not None:
                keys.append(f"bytes{byte_count}:{raw.hex()}")
        if compiler_key := _image_vc6_unwind_only_key(
            image,
            reference_catalog,
            value,
            direct_branch_targets,
        ):
            keys.append(compiler_key)
        if compiler_key := _image_vc6_single_delete_unwind_key(image, reference_catalog, value):
            keys.append(compiler_key)
        if jump_table_key := _image_local_jump_table_key(
            image,
            value,
            base_address,
            base_address + len(data),
        ):
            keys.append(jump_table_key)
        switch_catalogs = (None, reference_catalog) if reference_catalog is not None else (None,)
        for switch_catalog in switch_catalogs:
            switch_partition_key = _image_local_switch_partition_key_from_table(
                image,
                value,
                base_address,
                base_address + len(data),
                switch_catalog,
            ) or _image_local_switch_partition_key_from_lookup(
                image,
                value,
                base_address,
                base_address + len(data),
                switch_catalog,
            )
            if switch_partition_key:
                keys.append(switch_partition_key)
        names = reference_catalog.names_by_address.get(value, ()) if reference_catalog is not None else ()
        return MaskedReference(
            operand_index=operand_index,
            kind=kind,
            source="image",
            value=value,
            text="|".join(names) if names else f"0x{value:08x}",
            keys=tuple(dict.fromkeys(keys)),
            explained=True,
        )

    lines: list[DisassemblyLine] = []
    for insn in instructions:
        insn_offset = insn.address - base_address
        is_branch = capstone.CS_GRP_JUMP in insn.groups or capstone.CS_GRP_CALL in insn.groups
        imm_relocation = relocation_in_span(insn_offset + insn.imm_offset, insn.imm_size) if insn.imm_offset else None
        imm_masked = (
            any(
                insn_offset + rel_offset in relocation_offsets
                for rel_offset in range(insn.imm_offset, insn.imm_offset + max(insn.imm_size, 1))
            )
            if insn.imm_offset
            else False
        )
        disp_relocation = (
            relocation_in_span(insn_offset + insn.disp_offset, insn.disp_size) if insn.disp_offset else None
        )
        disp_masked = (
            any(
                insn_offset + rel_offset in relocation_offsets
                for rel_offset in range(insn.disp_offset, insn.disp_offset + max(insn.disp_size, 1))
            )
            if insn.disp_offset
            else False
        )
        if _is_vc_exception_chain_reference(disp_relocation):
            disp_masked = False

        operands: list[str] = []
        masked_references: list[MaskedReference] = []
        for operand_index, operand in enumerate(insn.operands):
            if operand.type == capstone.x86.X86_OP_REG:
                operands.append(insn.reg_name(operand.reg))
            elif operand.type == capstone.x86.X86_OP_IMM:
                value = operand.imm
                target_offset = value - base_address
                if (
                    imm_masked
                    and is_branch
                    and imm_relocation is not None
                    and imm_relocation.local_target_offset is not None
                    and 0 <= imm_relocation.local_target_offset < size
                ):
                    operands.append(f"L{imm_relocation.local_target_offset:x}")
                elif imm_masked:
                    operands.append("ADDR")
                    masked_references.append(
                        object_reference(
                            imm_relocation,
                            operand_index=operand_index,
                            kind="imm",
                            byte_count=operand.size,
                        ),
                    )
                elif is_branch and 0 <= target_offset < size:
                    operands.append(f"L{target_offset:x}")
                elif is_masked_value(value):
                    operands.append("ADDR")
                    masked_references.append(image_reference(value, operand_index=operand_index, kind="imm"))
                elif is_branch:
                    operands.append(f"R{target_offset:+#x}")
                else:
                    operands.append(f"0x{value:x}" if value >= 0 else f"-0x{-value:x}")
            elif operand.type == capstone.x86.X86_OP_MEM:
                masked = disp_masked or is_masked_value(operand.mem.disp)
                operands.append(_format_memory_operand(insn, operand, masked))
                if disp_masked:
                    masked_references.append(
                        object_reference(
                            disp_relocation,
                            operand_index=operand_index,
                            kind="disp",
                            byte_count=operand.size,
                        ),
                    )
                elif is_masked_value(operand.mem.disp):
                    masked_references.append(
                        image_reference(
                            operand.mem.disp,
                            operand_index=operand_index,
                            kind="disp",
                            byte_count=operand.size,
                        ),
                    )
            else:
                operands.append("?")
        lines.append(
            DisassemblyLine(
                offset=insn_offset,
                address=insn.address,
                text=f"{insn.mnemonic} {', '.join(operands)}".strip(),
                size=insn.size,
                masked_references=tuple(masked_references),
            ),
        )
    decoded_end = (
        instructions[-1].address - base_address + instructions[-1].size
        if instructions
        else 0
    )
    for offset in range(decoded_end, len(data)):
        lines.append(
            DisassemblyLine(
                offset=offset,
                address=base_address + offset,
                text=f"db 0x{data[offset]:02x}",
                size=1,
            ),
        )
    return _strip_trailing_padding_lines(tuple(lines))


def _strip_trailing_padding_lines(lines: tuple[DisassemblyLine, ...]) -> tuple[DisassemblyLine, ...]:
    trim_start = len(lines)
    while trim_start > 0 and lines[trim_start - 1].text in PADDING_LINE_TEXT:
        trim_start -= 1
    if trim_start == len(lines) or trim_start == 0:
        return lines
    terminator = lines[trim_start - 1].text
    if not terminator.startswith(("ret", "jmp ")):
        return lines

    padding_offsets = {line.offset for line in lines[trim_start:]}
    for line in lines[:trim_start]:
        targets = {int(match.group(1), 16) for match in BRANCH_TARGET_RE.finditer(line.text)}
        if targets & padding_offsets:
            return lines
    return lines[:trim_start]


@dataclass(frozen=True, slots=True)
class _ProvenCopyRange:
    source: int
    destination: int
    size: int

    def canonical_address(self, address: int) -> int | None:
        if self.source <= address < self.source + self.size:
            return address
        if self.destination <= address < self.destination + self.size:
            return self.source + address - self.destination
        return None


def _masked_reference_address(reference: MaskedReference) -> int | None:
    addresses = {reference.value} if reference.value is not None else set()
    for key in reference.keys:
        if match := ADDRESS_REFERENCE_KEY_RE.fullmatch(key):
            addresses.add(int(match.group(1), 16))
    if len(addresses) != 1:
        return None
    return next(iter(addresses))


def _line_reference_address(line: DisassemblyLine, operand_index: int) -> int | None:
    addresses = {
        address
        for reference in line.masked_references
        if reference.operand_index == operand_index
        if (address := _masked_reference_address(reference)) is not None
    }
    if len(addresses) != 1:
        return None
    return next(iter(addresses))


def _ranges_overlap(first_start: int, first_size: int, second_start: int, second_size: int) -> bool:
    return first_start < second_start + second_size and second_start < first_start + first_size


def _annotate_vc6_proven_copy_loads(
    lines: tuple[DisassemblyLine, ...],
) -> tuple[DisassemblyLine, ...]:
    """Key the first direct load from either side of a proven ``rep movsd`` copy.

    VC6 can propagate a copied aggregate's source value while another build
    reloads the equal destination field. Keep this deliberately local: the
    copy must have constant absolute endpoints and a constant dword count in
    the same straight-line block, the ranges must not overlap, and the first
    subsequent direct access retires the proof. Calls, branches, and unknown
    indirect memory accesses also discard it.
    """

    branch_targets = {
        int(match.group(1), 16)
        for line in lines
        for match in BRANCH_TARGET_RE.finditer(line.text)
    }
    live_copies: list[_ProvenCopyRange] = []
    copy_count: int | None = None
    copy_source: int | None = None
    copy_destination: int | None = None
    annotated: list[DisassemblyLine] = []

    def clear_copy_setup() -> None:
        nonlocal copy_count, copy_source, copy_destination
        copy_count = None
        copy_source = None
        copy_destination = None

    for line in lines:
        if line.offset in branch_targets:
            live_copies.clear()
            clear_copy_setup()

        references = list(line.masked_references)
        touched_copies: set[_ProvenCopyRange] = set()
        for reference_index, reference in enumerate(references):
            address = _masked_reference_address(reference)
            if address is None:
                continue
            matching_copies = [
                copy_range
                for copy_range in live_copies
                if copy_range.canonical_address(address) is not None
            ]
            if (
                line.text == "fld dword [ADDR]"
                and len(references) == 1
                and len(matching_copies) == 1
            ):
                canonical_address = matching_copies[0].canonical_address(address)
                assert canonical_address is not None
                key = f"{VC6_PROVEN_COPY_LOAD_KEY}:0x{canonical_address:08x}"
                references[reference_index] = replace(
                    reference,
                    keys=tuple(dict.fromkeys((*reference.keys, key))),
                )
            touched_copies.update(matching_copies)
        if touched_copies:
            live_copies = [copy_range for copy_range in live_copies if copy_range not in touched_copies]

        annotated.append(replace(line, masked_references=tuple(references)))
        text = line.text

        if text == "rep movsd dword [edi], dword [esi]":
            if (
                copy_count is not None
                and 0 < copy_count <= 0x1000
                and copy_source is not None
                and copy_destination is not None
            ):
                copy_size = copy_count * 4
                if not _ranges_overlap(copy_source, copy_size, copy_destination, copy_size):
                    live_copies = [
                        copy_range
                        for copy_range in live_copies
                        if not _ranges_overlap(
                            copy_destination,
                            copy_size,
                            copy_range.source,
                            copy_range.size,
                        )
                        and not _ranges_overlap(
                            copy_destination,
                            copy_size,
                            copy_range.destination,
                            copy_range.size,
                        )
                    ]
                    live_copies.append(
                        _ProvenCopyRange(
                            source=copy_source,
                            destination=copy_destination,
                            size=copy_size,
                        ),
                    )
            clear_copy_setup()
            continue

        if match := re.fullmatch(r"mov ecx, 0x([0-9a-f]+)", text):
            copy_count = int(match.group(1), 16)
        elif text == "mov esi, ADDR":
            copy_source = _line_reference_address(line, 1)
        elif text == "mov edi, ADDR":
            copy_destination = _line_reference_address(line, 1)
        else:
            for register in ("ecx", "esi", "edi"):
                if re.search(rf"\b{register}\b", text):
                    if register == "ecx":
                        copy_count = None
                    elif register == "esi":
                        copy_source = None
                    else:
                        copy_destination = None

        mnemonic = text.partition(" ")[0]
        if (
            mnemonic.startswith("j")
            or mnemonic in {"call", "loop", "loope", "loopne", "ret", "retf", "iret"}
            or ("[" in text and "ADDR" not in text)
        ):
            live_copies.clear()
            clear_copy_setup()

    return tuple(annotated)


def normalize_function(
    data: bytes,
    *,
    relocation_offsets: frozenset[int] | None = None,
    address_range: tuple[int, int] | None = None,
    base_address: int = 0,
) -> tuple[str, ...]:
    lines = disassemble_normalized_function(
        data,
        relocation_offsets=relocation_offsets,
        address_range=address_range,
        base_address=base_address,
    )
    return tuple(line.text for line in lines)


def common_prefix_length(target_lines: tuple[str, ...], candidate_lines: tuple[str, ...]) -> int:
    for index, (target, candidate_line) in enumerate(zip(target_lines, candidate_lines)):
        if target != candidate_line:
            return index
    return min(len(target_lines), len(candidate_lines))


def _local_branch_offsets(line: DisassemblyLine) -> tuple[int, ...]:
    return tuple(int(match.group(1), 16) for match in BRANCH_TARGET_RE.finditer(line.text))


def _block_terminates(line: DisassemblyLine) -> bool:
    mnemonic = line.text.partition(" ")[0]
    return mnemonic.startswith(("j", "loop")) or mnemonic in {"ret", "retf", "iret", "int3"}


def _has_fallthrough(line: DisassemblyLine) -> bool:
    mnemonic = line.text.partition(" ")[0]
    return mnemonic not in {"jmp", "ret", "retf", "iret", "int3"}


def build_basic_blocks(lines: tuple[DisassemblyLine, ...]) -> tuple[BasicBlock, ...]:
    """Recover a bounded intraprocedural block graph from normalized disassembly."""

    if not lines:
        return ()
    index_by_offset = {line.offset: index for index, line in enumerate(lines)}
    leaders = {0}
    for index, line in enumerate(lines):
        leaders.update(
            index_by_offset[offset]
            for offset in _local_branch_offsets(line)
            if offset in index_by_offset
        )
        if _block_terminates(line) and index + 1 < len(lines):
            leaders.add(index + 1)
    starts = sorted(leaders)
    ranges = [
        (start, starts[index + 1] if index + 1 < len(starts) else len(lines))
        for index, start in enumerate(starts)
    ]
    block_by_offset = {
        lines[start].offset: index
        for index, (start, _end) in enumerate(ranges)
    }
    blocks: list[BasicBlock] = []
    for block_index, (start, end) in enumerate(ranges):
        first = lines[start]
        last = lines[end - 1]
        successor_indices: list[int] = []
        mnemonic = last.text.partition(" ")[0]
        if mnemonic.startswith(("j", "loop")):
            successor_indices.extend(
                block_by_offset[offset]
                for offset in _local_branch_offsets(last)
                if offset in block_by_offset
            )
        fallthrough = block_index + 1 if _has_fallthrough(last) and block_index + 1 < len(ranges) else None
        if fallthrough is not None:
            successor_indices.append(fallthrough)
        blocks.append(
            BasicBlock(
                index=block_index,
                start_instruction=start,
                end_instruction=end,
                start_offset=first.offset,
                end_offset=last.offset + last.size,
                start_address=first.address,
                end_address=last.address + last.size,
                lines=tuple(line.text for line in lines[start:end]),
                successors=tuple(dict.fromkeys(successor_indices)),
                fallthrough=fallthrough,
            ),
        )
    return tuple(blocks)


def _cfg_predecessor_counts(blocks: tuple[BasicBlock, ...]) -> tuple[int, ...]:
    counts = [0] * len(blocks)
    for block in blocks:
        for successor in block.successors:
            counts[successor] += 1
    return tuple(counts)


def _cfg_block_shape(block: BasicBlock, predecessor_count: int) -> tuple[str, int, bool, int]:
    return (
        block.terminator,
        len(block.successors),
        block.fallthrough is not None,
        predecessor_count,
    )


def _cfg_exact_anchor_shape(block: BasicBlock) -> tuple[str, int, bool]:
    """Return only stable outgoing shape for unique exact anchor discovery.

    Predecessor counts are intentionally excluded. Repeated loop latches can
    trade incoming edges as surrounding reconstruction changes; using that
    count to make otherwise duplicate instruction blocks unique can cross-pair
    distant loops and manufacture anchored edge conflicts.
    """

    return (
        block.terminator,
        len(block.successors),
        block.fallthrough is not None,
    )


def _cfg_monotonic_exact_anchor_indices(
    pairs: list[CfgBlockPair],
    *,
    target_count: int,
    candidate_count: int,
) -> frozenset[int]:
    """Select a conservative monotonic backbone from unique exact pairs."""

    exact_indices = sorted(
        (index for index, pair in enumerate(pairs) if pair.kind == "exact"),
        key=lambda index: pairs[index].target_block,
    )
    if not exact_indices:
        return frozenset()

    target_denominator = max(1, target_count - 1)
    candidate_denominator = max(1, candidate_count - 1)
    max_order_distance = 0.05
    exact_indices = [
        index
        for index in exact_indices
        if abs(
            pairs[index].target_block / target_denominator
            - pairs[index].candidate_block / candidate_denominator,
        )
        <= max_order_distance
    ]
    if not exact_indices:
        return frozenset()
    lengths = [1] * len(exact_indices)
    local_costs = [
        abs(
            pairs[index].target_block / target_denominator
            - pairs[index].candidate_block / candidate_denominator,
        )
        for index in exact_indices
    ]
    costs = local_costs.copy()
    previous: list[int | None] = [None] * len(exact_indices)

    for current, pair_index in enumerate(exact_indices):
        current_pair = pairs[pair_index]
        for earlier in range(current):
            earlier_pair = pairs[exact_indices[earlier]]
            if earlier_pair.candidate_block >= current_pair.candidate_block:
                continue
            proposed_length = lengths[earlier] + 1
            proposed_cost = costs[earlier] + local_costs[current]
            if proposed_length > lengths[current] or (
                proposed_length == lengths[current] and proposed_cost < costs[current]
            ):
                lengths[current] = proposed_length
                costs[current] = proposed_cost
                previous[current] = earlier

    tail = min(
        range(len(exact_indices)),
        key=lambda index: (-lengths[index], costs[index], pairs[exact_indices[index]].target_block),
    )
    selected: set[int] = set()
    while True:
        selected.add(exact_indices[tail])
        predecessor = previous[tail]
        if predecessor is None:
            break
        tail = predecessor
    return frozenset(selected)


def align_basic_blocks(result: MatchResult) -> CfgAlignment:
    """Align exact CFG anchors and conservative similar blocks for diagnostics only."""

    target = build_basic_blocks(result.target_disassembly)
    candidate = build_basic_blocks(result.candidate_disassembly)
    target_predecessors = _cfg_predecessor_counts(target)
    candidate_predecessors = _cfg_predecessor_counts(candidate)
    unmatched_target = set(range(len(target)))
    unmatched_candidate = set(range(len(candidate)))
    pairs: list[CfgBlockPair] = []

    target_fingerprints: dict[tuple[tuple[str, ...], tuple[str, int, bool]], list[int]] = {}
    candidate_fingerprints: dict[tuple[tuple[str, ...], tuple[str, int, bool]], list[int]] = {}
    for index, block in enumerate(target):
        key = block.canonical_lines, _cfg_exact_anchor_shape(block)
        target_fingerprints.setdefault(key, []).append(index)
    for index, block in enumerate(candidate):
        key = block.canonical_lines, _cfg_exact_anchor_shape(block)
        candidate_fingerprints.setdefault(key, []).append(index)
    for key in sorted(
        target_fingerprints.keys() & candidate_fingerprints.keys(),
        key=lambda value: (value[0], value[1]),
    ):
        target_indices = target_fingerprints[key]
        candidate_indices = candidate_fingerprints[key]
        if len(target_indices) != 1 or len(candidate_indices) != 1:
            continue
        target_index = target_indices[0]
        candidate_index = candidate_indices[0]
        pairs.append(
            CfgBlockPair(
                target_block=target_index,
                candidate_block=candidate_index,
                kind="exact",
                ratio=1.0,
                structure_match=True,
            ),
        )
        unmatched_target.remove(target_index)
        unmatched_candidate.remove(candidate_index)

    similar: list[tuple[float, float, int, int, bool]] = []
    target_denominator = max(1, len(target) - 1)
    candidate_denominator = max(1, len(candidate) - 1)
    for target_index in unmatched_target:
        target_block = target[target_index]
        target_shape = _cfg_block_shape(target_block, target_predecessors[target_index])
        for candidate_index in unmatched_candidate:
            candidate_block = candidate[candidate_index]
            candidate_shape = _cfg_block_shape(candidate_block, candidate_predecessors[candidate_index])
            structure_match = target_shape == candidate_shape
            if not structure_match:
                continue
            ratio = difflib.SequenceMatcher(
                a=target_block.canonical_lines,
                b=candidate_block.canonical_lines,
                autojunk=False,
            ).ratio()
            if ratio < 0.55:
                continue
            order_distance = abs(
                target_index / target_denominator - candidate_index / candidate_denominator,
            )
            similar.append((ratio, -order_distance, target_index, candidate_index, structure_match))
    for ratio, _order, target_index, candidate_index, structure_match in sorted(similar, reverse=True):
        if target_index not in unmatched_target or candidate_index not in unmatched_candidate:
            continue
        pairs.append(
            CfgBlockPair(
                target_block=target_index,
                candidate_block=candidate_index,
                kind="exact-ambiguous" if ratio == 1.0 else "similar",
                ratio=ratio,
                structure_match=structure_match,
            ),
        )
        unmatched_target.remove(target_index)
        unmatched_candidate.remove(candidate_index)

    anchor_indices = _cfg_monotonic_exact_anchor_indices(
        pairs,
        target_count=len(target),
        candidate_count=len(candidate),
    )
    anchored_target_to_candidate = {
        pairs[index].target_block: pairs[index].candidate_block for index in anchor_indices
    }
    anchored_candidates = set(anchored_target_to_candidate.values())
    checked_pairs: list[CfgBlockPair] = []
    for pair_index, pair in enumerate(pairs):
        target_successors = {
            anchored_target_to_candidate[successor]
            for successor in target[pair.target_block].successors
            if successor in anchored_target_to_candidate
        }
        candidate_successors = {
            successor
            for successor in candidate[pair.candidate_block].successors
            if successor in anchored_candidates
        }
        edge_consistent = (
            target_successors == candidate_successors
            if target_successors or candidate_successors
            else None
        )
        checked_pairs.append(
            replace(
                pair,
                edge_consistent=edge_consistent,
                edge_anchor=pair_index in anchor_indices,
            ),
        )

    return CfgAlignment(
        target_blocks=target,
        candidate_blocks=candidate,
        pairs=tuple(sorted(checked_pairs, key=lambda pair: pair.target_block)),
        unmatched_target=tuple(sorted(unmatched_target)),
        unmatched_candidate=tuple(sorted(unmatched_candidate)),
    )


def _basic_block_payload(block: BasicBlock) -> dict[str, Any]:
    return {
        "index": block.index,
        "instructions": {
            "start": block.start_instruction,
            "end": block.end_instruction,
            "count": block.instruction_count,
        },
        "bytes": {"start": block.start_offset, "end": block.end_offset},
        "addresses": {"start": block.start_address, "end": block.end_address},
        "terminator": block.terminator,
        "successors": list(block.successors),
        "fallthrough": block.fallthrough,
        "lines": list(block.lines),
    }


def _basic_block_location_payload(block: BasicBlock) -> dict[str, Any]:
    return {
        "index": block.index,
        "instructions": {
            "start": block.start_instruction,
            "end": block.end_instruction,
            "count": block.instruction_count,
        },
        "bytes": {"start": block.start_offset, "end": block.end_offset},
        "addresses": {"start": block.start_address, "end": block.end_address},
        "terminator": block.terminator,
        "successors": list(block.successors),
    }


def cfg_alignment_payload(alignment: CfgAlignment) -> dict[str, Any]:
    edge_consistent = sum(
        pair.edge_anchor and pair.edge_consistent is True
        for pair in alignment.pairs
    )
    edge_conflicts = sum(
        pair.edge_anchor and pair.edge_consistent is False
        for pair in alignment.pairs
    )
    heuristic_edge_consistent = sum(
        not pair.edge_anchor and pair.edge_consistent is True
        for pair in alignment.pairs
    )
    heuristic_edge_conflicts = sum(
        not pair.edge_anchor and pair.edge_consistent is False
        for pair in alignment.pairs
    )
    edge_unchecked = sum(pair.edge_consistent is None for pair in alignment.pairs)
    return {
        "method": (
            "diagnostic-only: unique exact normalized block contents and outgoing shape, "
            "followed by greedy structurally identical pairs with at least 55% instruction "
            "similarity; edges are checked only against a monotonic backbone of unique exact "
            "pairs within 5% normalized order distance; predecessor counts never make "
            "duplicate blocks unique"
        ),
        "summary": {
            "target_blocks": len(alignment.target_blocks),
            "candidate_blocks": len(alignment.candidate_blocks),
            "exact_pairs": alignment.exact_pairs,
            "exact_ambiguous_pairs": alignment.exact_ambiguous_pairs,
            "similar_pairs": alignment.similar_pairs,
            "edge_anchor_pairs": sum(pair.edge_anchor for pair in alignment.pairs),
            "unmatched_target": len(alignment.unmatched_target),
            "unmatched_candidate": len(alignment.unmatched_candidate),
            "edge_consistent_pairs": edge_consistent,
            "edge_conflicts": edge_conflicts,
            "heuristic_edge_consistent_pairs": heuristic_edge_consistent,
            "heuristic_edge_conflicts": heuristic_edge_conflicts,
            "edge_unchecked_pairs": edge_unchecked,
        },
        "pairs": [
            {
                "target_block": pair.target_block,
                "candidate_block": pair.candidate_block,
                "kind": pair.kind,
                "match_ratio": pair.ratio,
                "structure_match": pair.structure_match,
                "edge_anchor": pair.edge_anchor,
                "edge_consistent": pair.edge_consistent,
                "target": _basic_block_location_payload(
                    alignment.target_blocks[pair.target_block],
                ),
                "candidate": _basic_block_location_payload(
                    alignment.candidate_blocks[pair.candidate_block],
                ),
            }
            for pair in alignment.pairs
        ],
        "unmatched_target": [
            _basic_block_payload(alignment.target_blocks[index])
            for index in alignment.unmatched_target
        ],
        "unmatched_candidate": [
            _basic_block_payload(alignment.candidate_blocks[index])
            for index in alignment.unmatched_candidate
        ],
    }


def _masked_reference_status(
    target_references: tuple[MaskedReference, ...],
    candidate_references: tuple[MaskedReference, ...],
) -> str:
    if len(target_references) != len(candidate_references):
        return "unresolved"
    explained = all(reference.explained and reference.keys for reference in (*target_references, *candidate_references))
    if not explained:
        return "unresolved"
    if all(
        target.operand_index == candidate.operand_index
        and target.kind == candidate.kind
        and bool(set(target.keys) & set(candidate.keys))
        for target, candidate in zip(target_references, candidate_references)
    ):
        return "ok"
    return "mismatch"


def audit_masked_operands(
    target_disassembly: tuple[DisassemblyLine, ...],
    candidate_disassembly: tuple[DisassemblyLine, ...],
) -> MaskedOperandAudit:
    matcher = difflib.SequenceMatcher(
        a=tuple(line.text for line in target_disassembly),
        b=tuple(line.text for line in candidate_disassembly),
        autojunk=False,
    )
    entries: list[MaskedOperandAuditEntry] = []
    for tag, target_start, target_end, candidate_start, candidate_end in matcher.get_opcodes():
        if tag != "equal":
            continue
        for target_index, candidate_index in zip(
            range(target_start, target_end),
            range(candidate_start, candidate_end),
        ):
            target_line = target_disassembly[target_index]
            candidate_line = candidate_disassembly[candidate_index]
            if not target_line.masked_references and not candidate_line.masked_references:
                continue
            entries.append(
                MaskedOperandAuditEntry(
                    target_index=target_index,
                    candidate_index=candidate_index,
                    target_offset=target_line.offset,
                    candidate_offset=candidate_line.offset,
                    target_address=target_line.address,
                    candidate_address=candidate_line.address,
                    instruction=target_line.text,
                    target_references=target_line.masked_references,
                    candidate_references=candidate_line.masked_references,
                    status=_masked_reference_status(
                        target_line.masked_references,
                        candidate_line.masked_references,
                    ),
                ),
            )
    return MaskedOperandAudit(tuple(entries))


def _encoded_body_comparison(
    target_data: bytes,
    candidate: ObjectFunction,
    result: MatchResult,
) -> tuple[bool, int, int]:
    """Ignore only audited COFF relocation fields, preserving every encoding bit."""
    target_end = max((line.offset + line.size for line in result.target_disassembly), default=0)
    candidate_end = max((line.offset + line.size for line in result.candidate_disassembly), default=0)
    padding = (len(target_data) - target_end, len(candidate.data) - candidate_end)
    if not result.exact or target_end != candidate_end:
        return False, *padding
    target = bytearray(target_data[:target_end])
    encoded = bytearray(candidate.data[:candidate_end])
    audited = {entry.candidate_index for entry in result.masked_operand_audit.entries if entry.status == "ok"}
    for reference in candidate.relocation_references:
        if reference.offset not in candidate.relocation_offsets:
            continue
        if reference.relocation_type not in (IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32):
            continue
        for index in audited:
            line = result.candidate_disassembly[index]
            target_line = result.target_disassembly[index]
            if line.offset <= reference.offset and reference.offset + 4 <= line.offset + line.size:
                if line.offset != target_line.offset or line.size != target_line.size:
                    return False, *padding
                target[reference.offset : reference.offset + 4] = b"\0" * 4
                encoded[reference.offset : reference.offset + 4] = b"\0" * 4
                break
    return target == encoded, *padding


def match_function(
    target_data: bytes,
    candidate: ObjectFunction,
    *,
    image: LoadedImage,
    target_va: int,
    reference_catalog: ReferenceCatalog | None = None,
) -> MatchResult:
    address_range = (image.image_base, image.image_base + image.size_of_image)
    candidate_data = bytearray(candidate.data)
    materialized_local_offsets: set[int] = set()
    for reference in candidate.relocation_references:
        if (
            reference.relocation_type == IMAGE_REL_I386_DIR32
            and reference.local_target_offset is not None
            and 0 <= reference.offset <= len(candidate_data) - 4
        ):
            linked_value = struct.pack("<I", target_va + reference.local_target_offset)
            if target_data[reference.offset : reference.offset + 4] == linked_value:
                candidate_data[reference.offset : reference.offset + 4] = linked_value
                materialized_local_offsets.add(reference.offset)
    target_disassembly = disassemble_normalized_function(
        target_data,
        address_range=address_range,
        base_address=target_va,
        reference_catalog=reference_catalog,
        image=image,
    )
    candidate_disassembly = disassemble_normalized_function(
        bytes(candidate_data),
        relocation_offsets=candidate.relocation_offsets - materialized_local_offsets,
        relocation_references=tuple(
            reference
            for reference in candidate.relocation_references
            if reference.offset not in materialized_local_offsets
        ),
        address_range=address_range,
        reference_catalog=reference_catalog,
        image=image,
    )
    target_disassembly = _annotate_vc6_proven_copy_loads(target_disassembly)
    candidate_disassembly = _annotate_vc6_proven_copy_loads(candidate_disassembly)
    target_lines = tuple(line.text for line in target_disassembly)
    candidate_lines = tuple(line.text for line in candidate_disassembly)
    ratio = difflib.SequenceMatcher(a=target_lines, b=candidate_lines, autojunk=False).ratio()
    result = MatchResult(
        ratio=ratio,
        prefix_instructions=common_prefix_length(target_lines, candidate_lines),
        target_lines=target_lines,
        candidate_lines=candidate_lines,
        target_disassembly=target_disassembly,
        candidate_disassembly=candidate_disassembly,
        masked_operand_audit=audit_masked_operands(target_disassembly, candidate_disassembly),
    )
    body_exact, target_padding, candidate_padding = _encoded_body_comparison(target_data, candidate, result)
    return replace(
        result,
        body_byte_exact=body_exact,
        target_padding_bytes=target_padding,
        candidate_padding_bytes=candidate_padding,
    )


def _disassembly_slice_bounds(
    lines: tuple[DisassemblyLine, ...],
    start: int,
    end: int,
) -> tuple[int | None, int | None, int | None, int | None]:
    if not lines:
        return None, None, None, None

    def boundary(index: int) -> tuple[int, int]:
        if index < len(lines):
            line = lines[index]
            return line.offset, line.address
        line = lines[-1]
        return line.offset + line.size, line.address + line.size

    byte_start, address_start = boundary(start)
    byte_end, address_end = boundary(end)
    return byte_start, byte_end, address_start, address_end


def _region_hints(
    target_lines: tuple[str, ...],
    candidate_lines: tuple[str, ...],
    *,
    masked_unresolved: int,
    masked_mismatches: int,
) -> tuple[str, ...]:
    target_mnemonics = tuple(line.partition(" ")[0] for line in target_lines)
    candidate_mnemonics = tuple(line.partition(" ")[0] for line in candidate_lines)
    all_mnemonics = (*target_mnemonics, *candidate_mnemonics)
    hints: list[str] = []

    if masked_mismatches:
        hints.append("reference-mismatch")
    if masked_unresolved:
        hints.append("unresolved-reference")
    branch_mnemonics = {
        mnemonic
        for mnemonic in all_mnemonics
        if mnemonic.startswith("j") or mnemonic in {"call", "loop", "loope", "loopne"}
    }
    if branch_mnemonics and target_mnemonics != candidate_mnemonics:
        hints.append("possible-control-flow-shape")
    if any(mnemonic.startswith("f") for mnemonic in all_mnemonics) and target_lines != candidate_lines:
        hints.append("possible-x87-lifetime-or-ordering")
    if len(target_lines) > len(candidate_lines):
        hints.append("possible-missing-candidate-instructions")
    elif len(candidate_lines) > len(target_lines):
        hints.append("possible-extra-candidate-instructions")
    if target_lines != candidate_lines and any(
        re.search(r"\b(?:esp|ebp)\b", line) for line in (*target_lines, *candidate_lines)
    ):
        hints.append("possible-stack-frame-or-lifetime")
    if target_mnemonics == candidate_mnemonics and target_lines != candidate_lines:
        hints.append("possible-register-literal-or-operand-allocation")
    elif Counter(target_mnemonics) == Counter(candidate_mnemonics) and target_mnemonics != candidate_mnemonics:
        hints.append("possible-instruction-scheduling")
    if not hints:
        hints.append("instruction-shape-difference")
    return tuple(dict.fromkeys(hints))


def diff_regions(
    result: MatchResult,
    *,
    context: int = 4,
    max_regions: int | None = None,
) -> list[DiffRegion]:
    if context < 0:
        raise ValueError("context must be non-negative")
    matcher = difflib.SequenceMatcher(a=result.target_lines, b=result.candidate_lines, autojunk=False)
    groups: list[dict[str, int]] = []
    current: dict[str, int] | None = None
    pending_equal: tuple[int, int, int, int] | None = None
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            if current is not None:
                pending_equal = (a0, a1, b0, b1)
            continue
        if current is None:
            current = {"a0": a0, "a1": a1, "b0": b0, "b1": b1, "changed_a": a1 - a0, "changed_b": b1 - b0}
        elif pending_equal is not None and (
            (pending_equal[1] - pending_equal[0]) <= context or (pending_equal[3] - pending_equal[2]) <= context
        ):
            current["a1"] = a1
            current["b1"] = b1
            current["changed_a"] += a1 - a0
            current["changed_b"] += b1 - b0
        else:
            groups.append(current)
            current = {"a0": a0, "a1": a1, "b0": b0, "b1": b1, "changed_a": a1 - a0, "changed_b": b1 - b0}
        pending_equal = None
    if current is not None:
        groups.append(current)

    regions: list[DiffRegion] = []
    for group in groups[:max_regions]:
        target_start = max(0, group["a0"] - context)
        target_end = min(len(result.target_lines), group["a1"] + context)
        candidate_start = max(0, group["b0"] - context)
        candidate_end = min(len(result.candidate_lines), group["b1"] + context)
        target_slice = result.target_lines[target_start:target_end]
        candidate_slice = result.candidate_lines[candidate_start:candidate_end]
        local_ratio = difflib.SequenceMatcher(a=target_slice, b=candidate_slice, autojunk=False).ratio()
        target_byte_start, target_byte_end, target_address_start, target_address_end = _disassembly_slice_bounds(
            result.target_disassembly,
            target_start,
            target_end,
        )
        candidate_byte_start, candidate_byte_end, _, _ = _disassembly_slice_bounds(
            result.candidate_disassembly,
            candidate_start,
            candidate_end,
        )
        scoped_audit = [
            entry
            for entry in result.masked_operand_audit.entries
            if (
                target_start <= entry.target_index < target_end
                or candidate_start <= entry.candidate_index < candidate_end
            )
        ]
        masked_ok = sum(entry.status == "ok" for entry in scoped_audit)
        masked_unresolved = sum(entry.status == "unresolved" for entry in scoped_audit)
        masked_mismatches = sum(entry.status == "mismatch" for entry in scoped_audit)
        changed_target_lines = result.target_lines[group["a0"] : group["a1"]]
        changed_candidate_lines = result.candidate_lines[group["b0"] : group["b1"]]
        target_byte_count = (
            target_byte_end - target_byte_start
            if target_byte_start is not None and target_byte_end is not None
            else 0
        )
        regions.append(
            DiffRegion(
                target_start=target_start,
                target_end=target_end,
                candidate_start=candidate_start,
                candidate_end=candidate_end,
                changed_target_instructions=group["changed_a"],
                changed_candidate_instructions=group["changed_b"],
                ratio=local_ratio,
                prefix_instructions=common_prefix_length(target_slice, candidate_slice),
                target_lines=target_slice,
                candidate_lines=candidate_slice,
                target_byte_start=target_byte_start,
                target_byte_end=target_byte_end,
                candidate_byte_start=candidate_byte_start,
                candidate_byte_end=candidate_byte_end,
                target_address_start=target_address_start,
                target_address_end=target_address_end,
                fuzzy_weighted_bytes=target_byte_count * local_ratio,
                masked_ok=masked_ok,
                masked_unresolved=masked_unresolved,
                masked_mismatches=masked_mismatches,
                hints=_region_hints(
                    changed_target_lines,
                    changed_candidate_lines,
                    masked_unresolved=masked_unresolved,
                    masked_mismatches=masked_mismatches,
                ),
            ),
        )
    return regions


def diff_region_payload(region: DiffRegion) -> dict[str, Any]:
    return {
        "target_instructions": {
            "start": region.target_start,
            "end": region.target_end,
            "changed": region.changed_target_instructions,
        },
        "candidate_instructions": {
            "start": region.candidate_start,
            "end": region.candidate_end,
            "changed": region.changed_candidate_instructions,
        },
        "target_bytes": {
            "start": region.target_byte_start,
            "end": region.target_byte_end,
            "count": region.target_byte_count,
            "address_start": region.target_address_start,
            "address_end": region.target_address_end,
        },
        "candidate_bytes": {
            "start": region.candidate_byte_start,
            "end": region.candidate_byte_end,
        },
        "match_ratio": region.ratio,
        "fuzzy_weighted_bytes": region.fuzzy_weighted_bytes,
        "prefix_instructions": region.prefix_instructions,
        "references": {
            "ok": region.masked_ok,
            "unresolved": region.masked_unresolved,
            "mismatch": region.masked_mismatches,
        },
        "hints": list(region.hints),
        "target_lines": list(region.target_lines),
        "candidate_lines": list(region.candidate_lines),
    }


_PROLOGUE_STACK_ALLOCATION_RE = re.compile(r"^sub esp, (0x[0-9a-f]+|\d+)$")


def _prologue_stack_allocation(lines: tuple[str, ...]) -> int | None:
    for line in lines[:16]:
        if match := _PROLOGUE_STACK_ALLOCATION_RE.match(line):
            return int(match.group(1), 0)
    return None


def stack_frame_diagnostic_payload(result: MatchResult) -> dict[str, Any] | None:
    """Compare explicit prologue allocation without multiplying it into local claims."""

    target = _prologue_stack_allocation(result.target_lines)
    candidate = _prologue_stack_allocation(result.candidate_lines)
    if target is None and candidate is None:
        return None
    delta = target - candidate if target is not None and candidate is not None else None
    if delta is None:
        classification = "incomparable-prologue"
    elif delta > 0:
        classification = "native-frame-larger"
    elif delta < 0:
        classification = "candidate-frame-larger"
    else:
        classification = "same-prologue-allocation"
    return {
        "target_prologue_allocation_bytes": target,
        "candidate_prologue_allocation_bytes": candidate,
        "target_minus_candidate_bytes": delta,
        "classification": classification,
        "caveat": (
            "Diagnostic only: prologue allocation includes compiler temporaries and stack-slot "
            "coloring; its delta does not imply missing source locals byte-for-byte."
        ),
    }


def match_result_payload(
    result: MatchResult,
    *,
    region_context: int = 4,
    max_regions: int | None = None,
) -> dict[str, Any]:
    regions = diff_regions(result, context=region_context, max_regions=max_regions) if result.ratio != 1.0 else []
    cfg = align_basic_blocks(result) if result.target_disassembly or result.candidate_disassembly else None
    return {
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "padding_bytes": {"target": result.target_padding_bytes, "candidate": result.candidate_padding_bytes},
        "match_ratio": result.ratio,
        "prefix_instructions": result.prefix_instructions,
        "target_instructions": len(result.target_lines),
        "candidate_instructions": len(result.candidate_lines),
        "references": {
            "ok": result.masked_operand_audit.ok_count,
            "unresolved": result.masked_operand_audit.unresolved_count,
            "mismatch": result.masked_operand_audit.mismatch_count,
        },
        "stack_frame": stack_frame_diagnostic_payload(result),
        "regions": [diff_region_payload(region) for region in regions],
        "cfg_alignment": cfg_alignment_payload(cfg) if cfg is not None else None,
    }


def run_match(
    *,
    obj_path: Path,
    function: str,
    image_path: Path = DEFAULT_IMAGE_PATH,
    functions_path: Path = DEFAULT_FUNCTIONS_PATH,
    metadata_path: Path | None = DEFAULT_METADATA_PATH,
    symbol_name: str | None = None,
    object_extent: str = "symbol",
    object_end_symbol: str | None = None,
    object_size: int | None = None,
    end_va: int | None = None,
    reference_aliases: tuple[tuple[str, str], ...] = (),
    scope: str | None = None,
) -> MatchResult:
    manifest = load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image_path.name,
        scope=scope,
    )
    try:
        resolved = resolve_function(manifest, function, end_override=end_va)
    except ValueError:
        unscoped_manifest = (
            load_function_manifest(
                functions_path,
                metadata_path=metadata_path,
                image_name=image_path.name,
                scope="all",
            )
            if scope not in (None, "all")
            else None
        )
        resolved = resolve_function_with_scope_hint(
            manifest,
            function,
            scope=scope,
            unscoped_manifest=unscoped_manifest,
            end_override=end_va,
        )
    obj = parse_coff_object(Path(obj_path).read_bytes())
    candidate = extract_object_function(
        obj,
        symbol_name,
        extent=object_extent,
        end_symbol=object_end_symbol,
        size=object_size,
    )
    _, start, end = resolved
    image = load_image(image_path, manifest.image_base)
    catalog = load_reference_catalog(manifest, functions_path=functions_path).with_object_aliases(
        reference_aliases,
    )
    return match_function(
        image.function_bytes(start, end),
        candidate,
        image=image,
        target_va=start,
        reference_catalog=catalog,
    )


def run_match_dump(
    *,
    obj_path: Path,
    function: str,
    image_path: Path = DEFAULT_IMAGE_PATH,
    functions_path: Path = DEFAULT_FUNCTIONS_PATH,
    metadata_path: Path | None = DEFAULT_METADATA_PATH,
    symbol_name: str | None = None,
    object_extent: str = "symbol",
    object_end_symbol: str | None = None,
    object_size: int | None = None,
    end_va: int | None = None,
    scope: str | None = None,
) -> MatchDump:
    manifest = load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image_path.name,
        scope=scope,
    )
    obj = parse_coff_object(Path(obj_path).read_bytes())
    candidate = extract_object_function(
        obj,
        symbol_name,
        extent=object_extent,
        end_symbol=object_end_symbol,
        size=object_size,
    )
    _, start, end = resolve_function(manifest, function, end_override=end_va)
    image = load_image(image_path, manifest.image_base)
    catalog = load_reference_catalog(manifest, functions_path=functions_path)
    address_range = (image.image_base, image.image_base + image.size_of_image)
    return MatchDump(
        target_lines=disassemble_normalized_function(
            image.function_bytes(start, end),
            address_range=address_range,
            base_address=start,
            reference_catalog=catalog,
            image=image,
        ),
        candidate_lines=disassemble_normalized_function(
            candidate.data,
            relocation_offsets=candidate.relocation_offsets,
            relocation_references=candidate.relocation_references,
            address_range=address_range,
            reference_catalog=catalog,
            image=image,
        ),
    )


DEFAULT_SCRATCH_IMAGE = DEFAULT_IMAGE_NAME
DEFAULT_SCRATCH_COMPILER = "msvc6.5"
DEFAULT_SCRATCH_CFLAGS = "/O2 /GB /W3 /GR-"
RECOVERY_VALUES = frozenset({"incomplete", "semantic-complete"})
RESIDUAL_VALUES = frozenset({"analysis", "compiler", "references"})
ARCHIVE_EXTENT_VALUES = frozenset({"symbol", "section-tail"})
SCRATCH_CONFIG_KEYS = frozenset(
    {
        "ARCHIVE",
        "ARCHIVE_END_SYMBOL",
        "ARCHIVE_EXTENT",
        "ARCHIVE_MEMBER",
        "ARCHIVE_SHA256",
        "ARCHIVE_SIZE",
        "AUTO_INLINE_OFF",
        "CFLAGS",
        "COMPILER",
        "DISPROVEN_COMPILERS",
        "END",
        "FUNCTION",
        "IMAGE",
        "IMPORT_THUNK",
        "NOTE",
        "RECOVERY",
        "REFERENCE_ALIASES",
        "RESIDUAL",
        "SOURCE",
        "SYMBOL",
    },
)


@dataclass(frozen=True, slots=True)
class ScratchConfig:
    directory: Path
    function: str
    image: str
    compiler: str
    cflags: str
    source: str
    end_va: int | None
    symbol: str | None
    note: str
    reference_aliases: tuple[tuple[str, str], ...] = ()
    recovery: str | None = None
    residuals: tuple[str, ...] = ()
    archive: str | None = None
    archive_member: str | None = None
    archive_sha256: str | None = None
    archive_extent: str = "symbol"
    archive_end_symbol: str | None = None
    archive_size: int | None = None
    import_thunk: str | None = None
    auto_inline_off: tuple[str, ...] = ()
    disproven_compilers: tuple[str, ...] = ()
    include_overlay: Path | None = None


@dataclass(frozen=True, slots=True)
class ScratchStatus:
    config: ScratchConfig
    address: int
    target_size: int
    ratio: float | None
    prefix_instructions: int
    target_instructions: int
    candidate_instructions: int
    error: str | None
    masked_ok: int = 0
    masked_unresolved: int = 0
    masked_mismatches: int = 0
    audit: MaskedOperandAudit = field(default_factory=MaskedOperandAudit)
    first_target_mismatch_offset: int | None = None
    first_candidate_mismatch_offset: int | None = None

    body_byte_exact: bool | None = None
    target_padding_bytes: int = 0
    candidate_padding_bytes: int = 0

    @property
    def state(self) -> str:
        if self.ratio is None:
            return "error"
        if self.ratio != 1.0:
            return "wip"
        if self.masked_unresolved or self.masked_mismatches:
            return "audit"
        return "match"

    @property
    def fuzzy_weighted_bytes(self) -> float:
        return self.target_size * self.ratio if self.ratio is not None else 0.0

    @property
    def fuzzy_gap_bytes(self) -> float:
        return max(0.0, self.target_size - self.fuzzy_weighted_bytes)


@dataclass(frozen=True, slots=True)
class NamingDebtRow:
    image: str
    address: int
    function: str
    configured_function: str
    scratch: str
    issues: tuple[str, ...]
    placeholder_aliases: tuple[str, ...]
    placeholder_references: tuple[str, ...]
    reference_suggestions: tuple[tuple[str, str, str], ...]
    provider_symbol: str | None
    provider_member: str | None
    suggestion: str | None
    suggestion_sources: tuple[str, ...]
    suggestion_comment: str | None = None
    map_kind: str = "function"
    placeholder_comment_tokens: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolvedNameReferenceRow:
    path: str
    line: int
    source: str
    token: str
    image: str
    address: int
    canonical_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NamingHint:
    image: str
    address: int
    name: str
    comment: str
    evidence: str


def load_naming_hints(
    path: Path = DEFAULT_NAMING_HINTS_PATH,
) -> dict[tuple[str, int], NamingHint]:
    """Load address-keyed identities backed by explicit repository evidence."""

    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise ValueError(f"{path}: unsupported naming-hint schema")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise TypeError(f"{path}: naming hints require an entries array")

    hints: dict[tuple[str, int], NamingHint] = {}
    for index, raw_value in enumerate(raw_entries):
        location = f"{path}:entries[{index}]"
        if not isinstance(raw_value, dict):
            raise TypeError(f"{location}: naming hint must be an object")
        raw_entry = cast(dict[str, Any], raw_value)
        unknown = sorted(
            set(raw_entry) - {"program", "address", "name", "comment", "evidence"},
        )
        if unknown:
            raise ValueError(f"{location}: unknown fields: {', '.join(unknown)}")
        image = raw_entry.get("program")
        if not isinstance(image, str) or image not in TRACKED_IMAGE_NAMES:
            raise ValueError(f"{location}: unsupported program {image!r}")
        raw_address = raw_entry.get("address")
        if not isinstance(raw_address, (str, int)):
            raise TypeError(f"{location}: invalid address")
        try:
            address = parse_int(raw_address)
        except ValueError as exc:
            raise ValueError(f"{location}: invalid address") from exc
        name = raw_entry.get("name")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            or is_analyzer_placeholder(name)
        ):
            raise ValueError(f"{location}: invalid canonical name {name!r}")
        comment = raw_entry.get("comment")
        evidence = raw_entry.get("evidence")
        if not isinstance(comment, str) or not comment.strip():
            raise ValueError(f"{location}: comment must be non-empty")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError(f"{location}: evidence must be non-empty")
        key = (image, address)
        if key in hints:
            raise ValueError(f"{location}: duplicate hint for {image}:0x{address:08x}")
        hints[key] = NamingHint(
            image=image,
            address=address,
            name=name,
            comment=comment.strip(),
            evidence=evidence.strip(),
        )
    return hints


def _scratch_image_prefix(image: str) -> str:
    return {
        "crimsonland.exe": "crimson",
        "grim.dll": "grim",
    }.get(image, Path(image).stem.lower())


def _replace_config_assignment(text: str, key: str, value: str) -> str:
    lines = text.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(f"{key}=")]
    if len(matches) != 1:
        raise ValueError(f"scratch.conf must contain exactly one {key}= assignment")
    index = matches[0]
    newline = "\n" if lines[index].endswith("\n") else ""
    lines[index] = f"{key}={shlex.quote(value)}{newline}"
    return "".join(lines)


def _replace_identity_tokens(text: str, replacements: dict[str, str]) -> tuple[str, int]:
    replaced = text
    count = 0
    for old, new in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])"
        replaced, occurrences = re.subn(pattern, new, replaced, flags=re.IGNORECASE)
        count += occurrences
    return replaced, count


def scratch_recovery(status: ScratchStatus) -> str:
    if status.state == "match":
        return "exact"
    return status.config.recovery or "unspecified"


@dataclass(frozen=True, slots=True)
class ImageTotals:
    image: str
    function_count: int
    byte_total: int
    matched_functions: int
    matched_bytes: int
    fuzzy_weighted_bytes: float
    candidate_functions: int
    candidate_bytes: int
    scratch_count: int
    matched_scratches: int

    @property
    def function_percentage(self) -> float:
        return self.matched_functions / self.function_count if self.function_count else 0.0

    @property
    def byte_percentage(self) -> float:
        return self.matched_bytes / self.byte_total if self.byte_total else 0.0

    @property
    def fuzzy_byte_percentage(self) -> float:
        return self.fuzzy_weighted_bytes / self.byte_total if self.byte_total else 0.0

    @property
    def candidate_byte_percentage(self) -> float:
        return self.candidate_bytes / self.byte_total if self.byte_total else 0.0


@dataclass(frozen=True, slots=True)
class NativeLinkStatus:
    image: str
    artifact_state: str
    artifact_note: str
    function_count: int | None = None
    object_count: int | None = None
    translation_unit_clusters: int | None = None
    abi_status: str | None = None
    function_closure: bool | None = None
    game_owned_closure: bool | None = None
    all_references_closed: bool | None = None
    hard_duplicate_symbols: int | None = None
    resolved_symbols: int | None = None
    unresolved_symbols: int | None = None
    unresolved_by_category: tuple[tuple[str, int], ...] = ()
    data_entries: int | None = None
    typed_data_entries: int | None = None
    explicit_size_entries: int | None = None
    explicit_alignment_entries: int | None = None
    explicit_initializer_entries: int | None = None


@dataclass(frozen=True, slots=True)
class TriageExperimentEvidence:
    records: int = 0
    current_records: int = 0
    historical_records: int = 0
    unversioned_records: int = 0
    mutation_sweeps: int = 0
    probes: int = 0
    evaluated_variants: int = 0
    unique_variants: int = 0
    unique_specs: int = 0
    no_improvement_streak: int = 0
    current_inconclusive_sweeps: int = 0
    current_errored_variants: int = 0
    audited_errored_variants: int = 0
    mutation_error_audits: int = 0
    strict_errors: int = 0
    flags: tuple[str, ...] = ()
    errors: int = 0


@dataclass(frozen=True, slots=True)
class TriageRow:
    image: str
    function: str
    address: int
    target_size: int
    state: str
    exact_bytes: int
    fuzzy_weighted_bytes: float
    candidate_bytes: int
    scratch_count: int
    best_status: ScratchStatus | None = None
    experiments: TriageExperimentEvidence = TriageExperimentEvidence()

    @property
    def fuzzy_gap_bytes(self) -> float:
        return max(0.0, self.target_size - self.fuzzy_weighted_bytes)


@dataclass(frozen=True, slots=True)
class ResidualFrontierRow:
    status: ScratchStatus
    experiments: TriageExperimentEvidence = TriageExperimentEvidence()

    @property
    def evidence_state(self) -> str:
        if not self.experiments.current_records:
            return "historical-only" if self.experiments.records else "unexplored"
        if self.experiments.strict_errors:
            return "current-error"
        if self.experiments.current_inconclusive_sweeps:
            return "current-inconclusive"
        if "stalled" in self.experiments.flags:
            return "current-stalled"
        return "current-active"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    baseline: ScratchStatus
    probe: ScratchStatus
    source_sha256: str
    label: str | None = None
    source_tree_sha256: str | None = None
    source_dependencies: tuple[str, ...] = ()

    @property
    def fuzzy_delta_bytes(self) -> float:
        return self.probe.fuzzy_weighted_bytes - self.baseline.fuzzy_weighted_bytes

    @property
    def ratio_delta(self) -> float | None:
        if self.baseline.ratio is None or self.probe.ratio is None:
            return None
        return self.probe.ratio - self.baseline.ratio


@dataclass(frozen=True, slots=True)
class CompilerListingSpan:
    source_lines: tuple[int, ...]
    instruction_offsets: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CompilerListingStackSymbol:
    name: str
    offset: int
    generated: bool


@dataclass(frozen=True, slots=True)
class CompilerListingStackLayout:
    prologue_allocation_bytes: int | None
    symbols: tuple[CompilerListingStackSymbol, ...]

    @property
    def distinct_slots(self) -> int:
        return len({symbol.offset for symbol in self.symbols})

    @property
    def reused_slots(self) -> int:
        counts = Counter(symbol.offset for symbol in self.symbols)
        return sum(count > 1 for count in counts.values())

    @property
    def generated_temporaries(self) -> int:
        return sum(symbol.generated for symbol in self.symbols)


@dataclass(frozen=True, slots=True)
class CompilerListingResult:
    listing_path: Path
    metadata_path: Path
    scratch: Path
    function: str
    compiler: str
    cflags: str
    canonical_object: Path
    canonical_object_sha256: str
    diagnostic_object_sha256: str
    function_sha256: str
    function_bytes: int
    relocations: int
    spans: tuple[CompilerListingSpan, ...]
    stack_layout: CompilerListingStackLayout


@dataclass(frozen=True, slots=True)
class CompilerScanRow:
    baseline: ScratchStatus
    best: ScratchStatus
    evaluated_profiles: int

    @property
    def classification(self) -> str:
        if self.best.state == "match" and self.baseline.state != "match":
            return "exact"
        if status_rank(self.best) > status_rank(self.baseline):
            return "improved"
        return "tied"

    @property
    def fuzzy_delta_bytes(self) -> float:
        return self.best.fuzzy_weighted_bytes - self.baseline.fuzzy_weighted_bytes


def load_scratch_config(directory: Path) -> ScratchConfig:
    values: dict[str, str] = {}
    for token in shlex.split((directory / "scratch.conf").read_text(encoding="utf-8"), comments=True):
        key, separator, value = token.partition("=")
        if not separator or not key:
            raise ValueError(
                f"{directory}/scratch.conf has invalid assignment {token!r}",
            )
        if key not in SCRATCH_CONFIG_KEYS:
            allowed = ", ".join(sorted(SCRATCH_CONFIG_KEYS))
            raise ValueError(
                f"{directory}/scratch.conf has unknown field {key!r}; use {allowed}",
            )
        if value:
            values[key] = value
    if "FUNCTION" not in values:
        raise ValueError(f"{directory}/scratch.conf must set FUNCTION")

    reference_aliases: list[tuple[str, str]] = []
    for mapping in values.get("REFERENCE_ALIASES", "").split(","):
        if not mapping:
            continue
        object_symbol, separator, target_symbol = mapping.partition(":")
        if not separator or not object_symbol or not target_symbol:
            raise ValueError(
                f"{directory}/scratch.conf has invalid REFERENCE_ALIASES entry {mapping!r}",
            )
        reference_aliases.append((object_symbol, target_symbol))

    recovery = values.get("RECOVERY")
    if recovery is not None and recovery not in RECOVERY_VALUES:
        allowed = ", ".join(sorted(RECOVERY_VALUES))
        raise ValueError(f"{directory}/scratch.conf has invalid RECOVERY={recovery!r}; use {allowed}")
    residuals = tuple(
        dict.fromkeys(
            value.strip()
            for value in values.get("RESIDUAL", "").split(",")
            if value.strip()
        ),
    )
    unknown_residuals = set(residuals) - RESIDUAL_VALUES
    if unknown_residuals:
        allowed = ", ".join(sorted(RESIDUAL_VALUES))
        unknown = ", ".join(sorted(unknown_residuals))
        raise ValueError(f"{directory}/scratch.conf has invalid RESIDUAL values {unknown}; use {allowed}")

    auto_inline_off = tuple(
        dict.fromkeys(
            value.strip()
            for value in values.get("AUTO_INLINE_OFF", "").split(",")
            if value.strip()
        ),
    )
    invalid_auto_inline = [
        value
        for value in auto_inline_off
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None
    ]
    if invalid_auto_inline:
        invalid = ", ".join(repr(value) for value in invalid_auto_inline)
        raise ValueError(
            f"{directory}/scratch.conf has invalid AUTO_INLINE_OFF identifiers {invalid}",
        )

    disproven_compilers = tuple(
        dict.fromkeys(
            value.strip()
            for value in values.get("DISPROVEN_COMPILERS", "").split(",")
            if value.strip()
        ),
    )
    invalid_disproven_compilers = [
        value
        for value in disproven_compilers
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", value) is None
    ]
    if invalid_disproven_compilers:
        invalid = ", ".join(repr(value) for value in invalid_disproven_compilers)
        raise ValueError(
            f"{directory}/scratch.conf has invalid DISPROVEN_COMPILERS values {invalid}",
        )

    archive = values.get("ARCHIVE")
    archive_member = values.get("ARCHIVE_MEMBER")
    archive_sha256 = values.get("ARCHIVE_SHA256")
    archive_extent = values.get("ARCHIVE_EXTENT", "symbol")
    archive_end_symbol = values.get("ARCHIVE_END_SYMBOL")
    archive_size = parse_int(values["ARCHIVE_SIZE"]) if "ARCHIVE_SIZE" in values else None
    import_thunk = values.get("IMPORT_THUNK")
    if import_thunk is not None:
        unexpected = sorted(
            key
            for key in (
                "ARCHIVE",
                "ARCHIVE_END_SYMBOL",
                "ARCHIVE_EXTENT",
                "ARCHIVE_MEMBER",
                "ARCHIVE_SHA256",
                "ARCHIVE_SIZE",
                "AUTO_INLINE_OFF",
                "CFLAGS",
                "COMPILER",
                "REFERENCE_ALIASES",
                "SOURCE",
                "SYMBOL",
            )
            if key in values
        )
        if unexpected:
            joined = ", ".join(unexpected)
            raise ValueError(f"{directory}/scratch.conf cannot combine IMPORT_THUNK and {joined}")
        if "\x00" in import_thunk or re.search(r"\s", import_thunk):
            raise ValueError(f"{directory}/scratch.conf IMPORT_THUNK must be one import symbol")
    if archive is None:
        unexpected = sorted(
            key
            for key in (
                "ARCHIVE_END_SYMBOL",
                "ARCHIVE_EXTENT",
                "ARCHIVE_MEMBER",
                "ARCHIVE_SHA256",
                "ARCHIVE_SIZE",
            )
            if key in values
        )
        if unexpected:
            joined = ", ".join(unexpected)
            raise ValueError(f"{directory}/scratch.conf sets {joined} without ARCHIVE")
    else:
        if auto_inline_off:
            raise ValueError(
                f"{directory}/scratch.conf cannot combine ARCHIVE and AUTO_INLINE_OFF",
            )
        missing = [
            key
            for key in ("ARCHIVE_MEMBER", "ARCHIVE_SHA256", "SYMBOL")
            if key not in values
        ]
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"{directory}/scratch.conf archive scratch must set {joined}")
        if "SOURCE" in values:
            raise ValueError(f"{directory}/scratch.conf cannot combine ARCHIVE and SOURCE")
        if archive_sha256 is None or re.fullmatch(r"[0-9a-fA-F]{64}", archive_sha256) is None:
            raise ValueError(f"{directory}/scratch.conf ARCHIVE_SHA256 must be 64 hexadecimal characters")
        if archive_extent not in ARCHIVE_EXTENT_VALUES:
            allowed = ", ".join(sorted(ARCHIVE_EXTENT_VALUES))
            raise ValueError(
                f"{directory}/scratch.conf has invalid ARCHIVE_EXTENT={archive_extent!r}; use {allowed}",
            )
        if archive_end_symbol is not None:
            if archive_extent != "symbol":
                raise ValueError(
                    f"{directory}/scratch.conf cannot combine ARCHIVE_END_SYMBOL "
                    "and non-symbol ARCHIVE_EXTENT",
                )
            if "\x00" in archive_end_symbol or re.search(r"\s", archive_end_symbol):
                raise ValueError(
                    f"{directory}/scratch.conf ARCHIVE_END_SYMBOL must be one COFF symbol",
                )
        if archive_size is not None:
            if archive_extent != "symbol":
                raise ValueError(
                    f"{directory}/scratch.conf cannot combine ARCHIVE_SIZE "
                    "and non-symbol ARCHIVE_EXTENT",
                )
            if archive_end_symbol is not None:
                raise ValueError(
                    f"{directory}/scratch.conf cannot combine ARCHIVE_SIZE "
                    "and ARCHIVE_END_SYMBOL",
                )
            if archive_size <= 0:
                raise ValueError(f"{directory}/scratch.conf ARCHIVE_SIZE must be positive")

    return ScratchConfig(
        directory=directory,
        function=values["FUNCTION"],
        image=values.get("IMAGE", DEFAULT_SCRATCH_IMAGE),
        compiler=("linker-import" if import_thunk is not None else values.get("COMPILER", DEFAULT_SCRATCH_COMPILER)),
        cflags=("" if import_thunk is not None else values.get("CFLAGS", DEFAULT_SCRATCH_CFLAGS)),
        source=(values.get("SOURCE", "scratch.cpp") if archive is None and import_thunk is None else ""),
        end_va=int(values["END"], 0) if "END" in values else None,
        symbol=values.get("SYMBOL"),
        note=values.get("NOTE", ""),
        reference_aliases=tuple(reference_aliases),
        recovery=recovery,
        residuals=residuals,
        archive=archive,
        archive_member=archive_member,
        archive_sha256=archive_sha256.lower() if archive_sha256 is not None else None,
        archive_extent=archive_extent,
        archive_end_symbol=archive_end_symbol,
        archive_size=archive_size,
        import_thunk=import_thunk,
        auto_inline_off=auto_inline_off,
        disproven_compilers=disproven_compilers,
    )


FORBIDDEN_SOURCE_PATTERNS = (
    re.compile(r"\b__asm\b"),
    re.compile(r"\b_asm\b"),
    re.compile(r"__declspec\s*\(\s*naked\s*\)", re.IGNORECASE),
)


def _validate_scratch_source_text(text: str, source: Path) -> None:
    for pattern in FORBIDDEN_SOURCE_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"{source}: inline assembly/naked functions are not allowed in scratches (no fakematching)",
            )


def validate_scratch_source(source: Path) -> None:
    _validate_scratch_source_text(source.read_text(encoding="latin1"), source)


def _matching_c_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    if start >= len(text) or text[start] != opening:
        raise ValueError(f"expected {opening!r} at source offset {start}")
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated block comment in scratch source")
            index = end + 2
            continue
        if char in {'"', "'"}:
            quote = char
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            else:
                raise ValueError("unterminated string or character literal in scratch source")
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError(f"unmatched {opening!r} in scratch source")


def _skip_c_trivia(text: str, start: int) -> int:
    index = start
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated block comment in scratch source")
            index = end + 2
            continue
        break
    return index


def _apply_auto_inline_boundaries(
    source_text: str,
    symbols: Collection[str],
    *,
    source: Path,
) -> str:
    insertions: list[tuple[int, str]] = []
    for symbol in symbols:
        pattern = re.compile(rf"(?m)^(?P<indent>[ \t]*){re.escape(symbol)}[ \t]*\(")
        definitions: list[tuple[re.Match[str], int]] = []
        for match in pattern.finditer(source_text):
            opening = source_text.find("(", match.start(), match.end())
            signature_end = _matching_c_delimiter(source_text, opening, "(", ")")
            body_start = _skip_c_trivia(source_text, signature_end + 1)
            if body_start < len(source_text) and source_text[body_start] == "{":
                definitions.append((match, body_start))
        if len(definitions) != 1:
            raise ValueError(
                f"{source}: AUTO_INLINE_OFF={symbol} must identify exactly one "
                f"line-leading function definition, found {len(definitions)}",
            )
        match, body_start = definitions[0]
        body_end = _matching_c_delimiter(source_text, body_start, "{", "}")
        declaration_start = match.start()
        if declaration_start > 0:
            previous_end = declaration_start - 1
            previous_start = source_text.rfind("\n", 0, previous_end) + 1
            previous_line = source_text[previous_start:previous_end].strip()
            if re.fullmatch(r"(?:LOCAL|METHODDEF|GLOBAL)\s*\([^\n)]*\)", previous_line):
                declaration_start = previous_start
        insertions.extend(
            (
                (declaration_start, "#pragma auto_inline(off)\n"),
                (body_end + 1, "\n#pragma auto_inline(on)"),
            ),
        )
    transformed = source_text
    for offset, replacement in sorted(insertions, reverse=True):
        transformed = transformed[:offset] + replacement + transformed[offset:]
    return transformed


def _scratch_archive_path(config: ScratchConfig) -> Path:
    if config.archive is None:
        raise ValueError(f"{config.directory}/scratch.conf does not configure ARCHIVE")
    path = Path(config.archive)
    if not path.is_absolute():
        path = config.directory / path
    return path.resolve()


def _mtime_ns(path: Path) -> int | None:
    return path.stat().st_mtime_ns if path.exists() else None


class _ScratchIncludeResolver:
    def __init__(self, match_root: Path, *, repo_root: Path = REPO_ROOT) -> None:
        self.include_dirs = (
            match_root / "include",
            repo_root / "third_party" / "headers",
        )
        self._direct_dependencies: dict[tuple[Path, bool, tuple[Path, ...], str | None], tuple[Path, ...]] = {}

    def direct_dependencies(
        self,
        including_path: Path,
        *,
        source: bool,
        include_dirs: tuple[Path, ...] | None = None,
    ) -> tuple[Path, ...]:
        search_dirs = include_dirs if include_dirs is not None else self.include_dirs
        cache_key = (including_path, source, search_dirs, match_toolchain.file_sha256(including_path))
        if cache_key in self._direct_dependencies:
            return self._direct_dependencies[cache_key]
        try:
            text = including_path.read_text(encoding="latin1")
        except OSError:
            self._direct_dependencies[cache_key] = ()
            return ()
        dependencies: list[Path] = []
        seen: set[Path] = set()
        for match in LOCAL_INCLUDE_RE.finditer(text):
            include_name = Path(match.group(1).replace("\\", "/"))
            candidates = [include_dir / include_name for include_dir in search_dirs]
            if not source:
                candidates.insert(0, including_path.parent / include_name)
            dependency = next((candidate for candidate in candidates if candidate.is_file()), None)
            if dependency is None:
                continue
            dependency = dependency.resolve()
            if dependency not in seen:
                seen.add(dependency)
                dependencies.append(dependency)
        resolved = tuple(dependencies)
        self._direct_dependencies[cache_key] = resolved
        return resolved


def _scratch_include_headers(
    config: ScratchConfig,
    match_root: Path,
    *,
    resolver: _ScratchIncludeResolver | None = None,
) -> tuple[Path, ...]:
    if config.archive is not None or config.import_thunk is not None:
        return ()
    resolver = resolver or _ScratchIncludeResolver(match_root)
    search_dirs = (_compiler_executable_path(config, match_root).parent.parent / "Include", *resolver.include_dirs)
    if config.include_overlay is not None:
        search_dirs = (config.include_overlay, *search_dirs)
    source = config.directory / config.source
    pending = [source]
    visited = {source}
    headers: set[Path] = set()
    while pending:
        including_path = pending.pop()
        for dependency in resolver.direct_dependencies(
            including_path, source=including_path == source, include_dirs=search_dirs,
        ):
            if dependency in visited:
                continue
            visited.add(dependency)
            headers.add(dependency)
            pending.append(dependency)
    return tuple(sorted(headers))


def _compiler_executable_path(config: ScratchConfig, match_root: Path) -> Path:
    configured_root = os.environ.get("CRIMSON_MSVC_ROOT")
    roots: list[Path] = []
    if configured_root:
        root = Path(configured_root)
        roots.extend((root, root / config.compiler))
    roots.extend(
        (
            match_root / "compilers" / config.compiler,
            REPO_ROOT.parent / "snail-mail" / "tools" / "match" / "compilers" / config.compiler,
        ),
    )
    for root in roots:
        for name in ("CL.EXE", "cl.exe"):
            candidate = root / "Bin" / name
            if candidate.is_file():
                return candidate
    return match_root / "compilers" / config.compiler / "Bin" / "CL.EXE"


def _scratch_compile_argv(config: ScratchConfig, match_root: Path) -> tuple[str, ...]:
    return (str(match_root / "cl.sh"), "/c", *shlex.split(config.cflags), Path(config.source).name)


def _scratch_build_dependencies(
    config: ScratchConfig,
    match_root: Path,
    *,
    include_resolver: _ScratchIncludeResolver | None = None,
) -> tuple[Path, ...]:
    if config.import_thunk is not None:
        return (
            config.directory / "scratch.conf",
            default_functions_path(config.image).with_name("imports.json"),
        )
    if config.archive is not None:
        return (
            _scratch_archive_path(config),
            config.directory / "scratch.conf",
        )
    return (
        config.directory / config.source,
        config.directory / "scratch.conf",
        match_root / "cl.sh",
        _compiler_executable_path(config, match_root),
        *_scratch_include_headers(config, match_root, resolver=include_resolver),
    )


def _experiment_epoch_path_label(path: Path, match_root: Path) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(match_root):
        return f"match/{resolved.relative_to(match_root).as_posix()}"
    if resolved.is_relative_to(REPO_ROOT):
        return f"repo/{resolved.relative_to(REPO_ROOT).as_posix()}"
    return f"external/{resolved.name}"


def source_probe_tree_fingerprint(
    config: ScratchConfig,
    source_text: str,
    match_root: Path = DEFAULT_MATCH_ROOT,
) -> tuple[str, tuple[str, ...]]:
    """Hash a probe wrapper together with every resolved local include.

    Probe sources are often one-line translation-unit wrappers.  Hashing only
    that wrapper makes two experiments look identical when an included source
    or header changes, so retain both the direct source hash and this complete
    dependency-tree fingerprint.
    """

    match_root = match_root.resolve()
    resolver = _ScratchIncludeResolver(match_root)
    include_dirs = (_compiler_executable_path(config, match_root).parent.parent / "Include", *resolver.include_dirs)

    def direct_dependencies(
        text: str,
        *,
        including_parent: Path | None,
        source: bool,
    ) -> tuple[Path, ...]:
        dependencies: list[Path] = []
        seen: set[Path] = set()
        for match in LOCAL_INCLUDE_RE.finditer(text):
            include_name = Path(match.group(1).replace("\\", "/"))
            candidates = [include_dir / include_name for include_dir in include_dirs]
            if not source and including_parent is not None:
                candidates.insert(0, including_parent / include_name)
            dependency = next((candidate for candidate in candidates if candidate.is_file()), None)
            if dependency is None:
                continue
            resolved = dependency.resolve()
            if resolved not in seen:
                seen.add(resolved)
                dependencies.append(resolved)
        return tuple(dependencies)

    pending = list(
        direct_dependencies(
            source_text,
            including_parent=None,
            source=True,
        ),
    )
    dependencies: set[Path] = set()
    while pending:
        dependency = pending.pop()
        if dependency in dependencies:
            continue
        dependencies.add(dependency)
        try:
            dependency_text = dependency.read_text(encoding="latin1")
        except OSError:
            continue
        pending.extend(
            direct_dependencies(
                dependency_text,
                including_parent=dependency.parent,
                source=False,
            ),
        )

    digest = hashlib.sha256(b"crimson-source-probe-tree-v1\0")
    digest.update(Path(config.source).name.encode())
    digest.update(b"\0source\0")
    digest.update(source_text.encode())
    labels: list[str] = []
    for dependency in sorted(
        dependencies,
        key=lambda value: _experiment_epoch_path_label(value, match_root),
    ):
        label = _experiment_epoch_path_label(dependency, match_root)
        labels.append(label)
        digest.update(b"\0path\0")
        digest.update(label.encode())
        digest.update(b"\0sha256\0")
        try:
            digest.update(hashlib.sha256(dependency.read_bytes()).hexdigest().encode())
        except OSError:
            digest.update(b"missing")
    return digest.hexdigest(), tuple(labels)


def scratch_experiment_epoch(
    config: ScratchConfig,
    match_root: Path = DEFAULT_MATCH_ROOT,
) -> str:
    """Hash the canonical inputs that determine an experiment baseline."""

    match_root = match_root.resolve()
    digest = hashlib.sha256(b"crimson-scratch-experiment-epoch-v2\0")
    profile = {
        "archive": config.archive,
        "archive_end_symbol": config.archive_end_symbol,
        "archive_extent": config.archive_extent,
        "archive_member": config.archive_member,
        "archive_sha256": config.archive_sha256,
        "archive_size": config.archive_size,
        "auto_inline_off": list(config.auto_inline_off),
        "cflags": config.cflags,
        "compiler": config.compiler,
        "end_va": config.end_va,
        "function": config.function,
        "image": config.image,
        "import_thunk": config.import_thunk,
        "reference_aliases": [list(alias) for alias in config.reference_aliases],
        "source": config.source,
        "symbol": config.symbol,
        "version": DEFAULT_VERSION,
    }
    if config.archive is None and config.import_thunk is None:
        profile["toolchain"] = match_toolchain.scratch_toolchain_fingerprint(
            _compiler_executable_path(config, match_root),
            match_root,
        )
    digest.update(json.dumps(profile, separators=(",", ":"), sort_keys=True).encode())

    compiler_path = _compiler_executable_path(config, match_root).resolve()
    config_path = (config.directory / "scratch.conf").resolve()
    dependencies = {
        path.resolve()
        for path in _scratch_build_dependencies(config, match_root)
        if path.resolve() not in {compiler_path, config_path}
    }
    image_path, functions_path, metadata_path = _paths_for_image(config.image)
    dependencies.update(
        {
            image_path.resolve(),
            functions_path.resolve(),
            metadata_path.resolve(),
            functions_path.with_name("imports.json").resolve(),
            DEFAULT_DATA_MAP_PATH.resolve(),
            DEFAULT_NAME_MAP_PATH.resolve(),
            Path(__file__).resolve(),
            Path(match_toolchain.__file__).resolve(),
            Path(match_process.__file__).resolve(),
        },
    )
    for path in sorted(dependencies, key=lambda value: _experiment_epoch_path_label(value, match_root)):
        label = _experiment_epoch_path_label(path, match_root)
        digest.update(b"\0path\0")
        digest.update(label.encode())
        sha256 = (
            native_json_program_sha256(path, config.image)
            if path in {DEFAULT_NAME_MAP_PATH.resolve(), DEFAULT_DATA_MAP_PATH.resolve()} and path.exists()
            else match_toolchain.file_sha256(path)
        )
        digest.update(b"\0sha256\0")
        digest.update(sha256.encode() if sha256 is not None else b"missing")
    return digest.hexdigest()


def _verified_native_experiment_epochs(image: str) -> dict[Path, str]:
    statuses = collect_native_link_statuses(images=(image,), allow_absent_toolchain=True)
    if len(statuses) != 1 or statuses[0].artifact_state != "current":
        return {}
    payload = json.loads((DEFAULT_NATIVE_ANALYSIS_ROOT / image / "objects.json").read_text())
    return {
        (REPO_ROOT / row["canonical_scratch"]).resolve(): epoch
        for obj in payload["objects"]
        for row in obj["functions"]
        if isinstance(epoch := row.get("experiment_epoch"), str) and re.fullmatch(r"[0-9a-f]{64}", epoch)
    }


def scratch_experiment_epochs(
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    directories: Collection[Path] | None = None,
) -> dict[Path, str]:
    """Return canonical experiment epochs keyed by resolved scratch directory."""

    match_root = match_root.resolve()
    selected = {directory.resolve() for directory in directories} if directories is not None else None
    epochs: dict[Path, str] = {}
    recorded_by_image: dict[str, dict[Path, str]] = {}
    for conf_path in sorted(match_root.glob("scratches/*/scratch.conf")):
        directory = conf_path.parent.resolve()
        if selected is not None and directory not in selected:
            continue
        config = load_scratch_config(directory)
        compiler_root = _compiler_executable_path(config, match_root).parent.parent
        if (
            match_root == DEFAULT_MATCH_ROOT.resolve()
            and config.archive is None
            and config.import_thunk is None
            and (
                not _compiler_executable_path(config, match_root).is_file()
                or not (compiler_root / "Include").is_dir()
                or match_toolchain.resolve_wibo_path(match_root, required=False) is None
            )
        ):
            if config.image not in recorded_by_image:
                recorded_by_image[config.image] = _verified_native_experiment_epochs(config.image)
            if recorded := recorded_by_image[config.image].get(directory):
                epochs[directory] = recorded
                continue
        epochs[directory] = scratch_experiment_epoch(config, match_root)
    return epochs


def _scratch_build_key(
    config: ScratchConfig,
    match_root: Path,
    *,
    include_resolver: _ScratchIncludeResolver | None = None,
) -> dict[str, Any]:
    dependencies = _scratch_build_dependencies(config, match_root, include_resolver=include_resolver)
    pipeline = [
        match_toolchain.file_sha256(path)
        for path in (
            Path(__file__),
            Path(match_toolchain.__file__),
            Path(match_process.__file__),
        )
    ]
    if config.import_thunk is not None:
        return {
            "pipeline_sha256": pipeline,
            "import_thunk": config.import_thunk,
            "dependencies": [
                [
                    str(path.relative_to(match_root) if path.is_relative_to(match_root) else path),
                    match_toolchain.file_sha256(path),
                ]
                for path in dependencies
            ],
        }
    if config.archive is not None:
        return {
            "pipeline_sha256": pipeline,
            "archive": config.archive,
            "archive_end_symbol": config.archive_end_symbol,
            "archive_extent": config.archive_extent,
            "archive_member": config.archive_member,
            "archive_sha256": config.archive_sha256,
            "archive_size": config.archive_size,
            "symbol": config.symbol,
            "dependencies": [
                [
                    str(path.relative_to(match_root) if path.is_relative_to(match_root) else path),
                    match_toolchain.file_sha256(path),
                ]
                for path in dependencies
            ],
        }
    key: dict[str, Any] = {
        "toolchain": match_toolchain.scratch_toolchain_fingerprint(
            _compiler_executable_path(config, match_root),
            match_root,
        ),
        "pipeline_sha256": pipeline,
        "compiler": config.compiler,
        "argv": list(_scratch_compile_argv(config, match_root)),
        "auto_inline_off": list(config.auto_inline_off),
        "dependencies": [
            [
                str(path.relative_to(match_root) if path.is_relative_to(match_root) else path),
                match_toolchain.file_sha256(path),
            ]
            for path in dependencies
        ],
    }
    if config.include_overlay is not None:
        key["include_overlay"] = str(config.include_overlay.resolve())
    return key


def _scratch_profile_digest(config: ScratchConfig) -> str:
    if config.import_thunk is not None:
        payload = {
            "import_thunk": config.import_thunk,
            "image": config.image,
            "function": config.function,
            "end_va": config.end_va,
        }
    elif config.archive is not None:
        payload = {
            "archive": config.archive,
            "archive_end_symbol": config.archive_end_symbol,
            "archive_extent": config.archive_extent,
            "archive_member": config.archive_member,
            "archive_sha256": config.archive_sha256,
            "archive_size": config.archive_size,
            "image": config.image,
            "function": config.function,
            "end_va": config.end_va,
            "symbol": config.symbol,
        }
    else:
        payload = {
            "compiler": config.compiler,
            "cflags": shlex.split(config.cflags),
            "source": config.source,
            "auto_inline_off": list(config.auto_inline_off),
            "image": config.image,
            "function": config.function,
            "end_va": config.end_va,
            "symbol": config.symbol,
        }
        if config.include_overlay is not None:
            payload["include_overlay"] = str(config.include_overlay.resolve())
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _scratch_build_directory(config: ScratchConfig) -> Path:
    profile = (
        "import"
        if config.import_thunk is not None
        else "archive"
        if config.archive is not None
        else config.compiler
    )
    return config.directory / "build" / profile / _scratch_profile_digest(config)


def _scratch_object_path(config: ScratchConfig) -> Path:
    build_dir = _scratch_build_directory(config)
    if config.import_thunk is not None:
        return build_dir / "import-thunk.obj"
    if config.archive is not None:
        member_name = Path((config.archive_member or "candidate.obj").replace("\\", "/")).name
        obj_name = member_name if member_name.casefold().endswith(".obj") else "candidate.obj"
        return build_dir / obj_name
    return build_dir / Path(config.source).with_suffix(".obj").name


def _write_text_atomic(path: Path, text: str) -> None:
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(text)
        temp_path = Path(handle.name)
    try:
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(data)
        temp_path = Path(handle.name)
    try:
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _archive_scratch_object_bytes(config: ScratchConfig) -> bytes:
    from .library_match import parse_coff_archive

    archive_path = _scratch_archive_path(config)
    archive_data = archive_path.read_bytes()
    observed_sha256 = hashlib.sha256(archive_data).hexdigest()
    if observed_sha256 != config.archive_sha256:
        raise ValueError(
            f"{archive_path}: archive SHA-256 mismatch: "
            f"expected {config.archive_sha256}, got {observed_sha256}",
        )

    archive_members = parse_coff_archive(archive_data)
    members = tuple(
        member
        for member in archive_members
        if member.name == config.archive_member
    )
    if len(members) != 1:
        raise ValueError(
            f"{archive_path}: expected exactly one archive member "
            f"{config.archive_member!r}, found {len(members)}",
        )
    obj_data = members[0].data
    try:
        obj = parse_coff_object(obj_data)
    except (IndexError, struct.error, ValueError) as exc:
        raise ValueError(
            f"{archive_path}:{config.archive_member}: archive member is not a valid COFF object",
        ) from exc
    if config.symbol is None:
        raise ValueError(f"{config.directory}/scratch.conf archive scratch must set SYMBOL")
    try:
        extract_object_function(
            obj,
            config.symbol,
            extent=config.archive_extent,
            end_symbol=config.archive_end_symbol,
            size=config.archive_size,
        )
    except ValueError as exc:
        defining_members: list[str] = []
        for candidate in archive_members:
            if candidate.name in {"/", "//", config.archive_member}:
                continue
            try:
                candidate_obj = parse_coff_object(candidate.data)
                extract_object_function(
                    candidate_obj,
                    config.symbol,
                    extent=config.archive_extent,
                    end_symbol=config.archive_end_symbol,
                    size=config.archive_size,
                )
            except (IndexError, struct.error, ValueError):
                continue
            defining_members.append(candidate.name)
        hint = (
            "; defining archive members: "
            + ", ".join(repr(name) for name in defining_members)
            if defining_members
            else ""
        )
        raise ValueError(
            f"{archive_path}:{config.archive_member}: "
            f"missing function symbol {config.symbol!r}{hint}",
        ) from exc
    return obj_data


def _import_thunk_object_bytes(import_name: str) -> bytes:
    """Materialize the canonical x86 linker thunk for one imported symbol."""

    symbol_name = f"__imp_{import_name}"
    encoded_name = symbol_name.encode("latin1")
    if not encoded_name or b"\x00" in encoded_name:
        raise ValueError("import thunk symbol must be non-empty and NUL-free")

    header_size = 20
    section_header_size = 40
    code = bytes.fromhex("ff2500000000")
    code_offset = header_size + section_header_size
    relocation_offset = code_offset + len(code)
    symtab_offset = relocation_offset + 10
    symbol_count = 2
    header = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_I386,
        1,
        0,
        symtab_offset,
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
        1,
        0,
        0x60000020,
    )
    relocation = struct.pack("<IIH", 2, 1, 0x0006)
    function_symbol = struct.pack("<8sIhHBB", b"_thunk", 0, 1, SYM_TYPE_FUNCTION, 2, 0)
    import_symbol = struct.pack("<IIIhHBB", 0, 4, 0, 0, 0, 2, 0)
    string_table = struct.pack("<I", 5 + len(encoded_name)) + encoded_name + b"\x00"
    return header + section + code + relocation + function_symbol + import_symbol + string_table


def validate_scratch_config(config: ScratchConfig) -> None:
    if config.import_thunk is not None:
        obj = parse_coff_object(_import_thunk_object_bytes(config.import_thunk))
        extract_object_function(obj)
        return
    if config.archive is not None:
        _archive_scratch_object_bytes(config)
        return
    source = config.directory / config.source
    validate_scratch_source(source)
    if config.auto_inline_off:
        transformed = _apply_auto_inline_boundaries(
            source.read_bytes().decode("latin1"),
            config.auto_inline_off,
            source=source,
        )
        _validate_scratch_source_text(transformed, source)


def _scratch_object_is_current(
    obj_path: Path,
    config: ScratchConfig,
    match_root: Path,
    *,
    include_resolver: _ScratchIncludeResolver | None = None,
) -> bool:
    if not obj_path.exists():
        return False
    obj_mtime = obj_path.stat().st_mtime_ns
    dependencies = _scratch_build_dependencies(config, match_root, include_resolver=include_resolver)
    if any((mtime := _mtime_ns(path)) is None or mtime > obj_mtime for path in dependencies):
        return False
    key_path = obj_path.parent / "scratch-build.json"
    try:
        cached = json.loads(key_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return cached.get("key") == _scratch_build_key(config, match_root, include_resolver=include_resolver)


def compile_scratch(
    config: ScratchConfig,
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    include_resolver: _ScratchIncludeResolver | None = None,
    force: bool = False,
    deadline: float | None = None,
) -> Path:
    import tempfile

    match_root = match_root.resolve()
    if config.import_thunk is not None:
        obj_path = _scratch_object_path(config)
        build_dir = obj_path.parent
        if not force and _scratch_object_is_current(
            obj_path,
            config,
            match_root,
            include_resolver=include_resolver,
        ):
            return obj_path
        _write_bytes_atomic(obj_path, _import_thunk_object_bytes(config.import_thunk))
        _write_text_atomic(
            build_dir / "scratch-build.json",
            json.dumps({"key": _scratch_build_key(config, match_root, include_resolver=include_resolver)}),
        )
        return obj_path
    if config.archive is not None:
        obj_path = _scratch_object_path(config)
        build_dir = obj_path.parent
        if not force and _scratch_object_is_current(
            obj_path,
            config,
            match_root,
            include_resolver=include_resolver,
        ):
            return obj_path
        obj_data = _archive_scratch_object_bytes(config)
        _write_bytes_atomic(obj_path, obj_data)
        _write_text_atomic(
            build_dir / "scratch-build.json",
            json.dumps({"key": _scratch_build_key(config, match_root, include_resolver=include_resolver)}),
        )
        return obj_path

    source = config.directory / config.source
    validate_scratch_source(source)
    staged_source_text = _apply_auto_inline_boundaries(
        source.read_bytes().decode("latin1"),
        config.auto_inline_off,
        source=source,
    )
    _validate_scratch_source_text(staged_source_text, source)
    obj_path = _scratch_object_path(config)
    build_dir = obj_path.parent
    obj_name = obj_path.name
    if not force and _scratch_object_is_current(
        obj_path,
        config,
        match_root,
        include_resolver=include_resolver,
    ):
        return obj_path

    build_dir.parent.mkdir(parents=True, exist_ok=True)
    command = list(_scratch_compile_argv(config, match_root))
    with tempfile.TemporaryDirectory(dir=build_dir.parent, prefix=f".{build_dir.name}.") as temp_name:
        temp_dir = Path(temp_name)
        temp_source = temp_dir / Path(config.source).name
        temp_obj = temp_dir / obj_name
        temp_source.write_bytes(staged_source_text.encode("latin1"))
        environment: dict[str, str] = dict(os.environ)
        environment["MSVC_VER"] = config.compiler
        environment.pop("CRIMSON_MATCH_INCLUDE_OVERLAY", None)
        if config.include_overlay is not None:
            environment["CRIMSON_MATCH_INCLUDE_OVERLAY"] = str(
                config.include_overlay.resolve(),
            )
        completed = run_compiler(
            command,
            cwd=temp_dir,
            env=environment,
            deadline=deadline,
        )
        if completed.returncode != 0 or not temp_obj.exists():
            raise RuntimeError(f"cl failed:\n{completed.stdout}{completed.stderr}")
        build_dir.mkdir(parents=True, exist_ok=True)
        os.replace(temp_source, build_dir / Path(config.source).name)
        os.replace(temp_obj, obj_path)
    _write_text_atomic(
        build_dir / "scratch-build.json",
        json.dumps({"key": _scratch_build_key(config, match_root, include_resolver=include_resolver)}),
    )
    return obj_path


_COMPILER_LISTING_SOURCE_RE = re.compile(r"^;\s*(\d+)\s+:")
_COMPILER_LISTING_INSTRUCTION_RE = re.compile(r"^\s*([0-9A-Fa-f]{5,8})\t")
_COMPILER_LISTING_PROC_RE = re.compile(r"^(\S+)\s+PROC\b")
_COMPILER_LISTING_STACK_SYMBOL_RE = re.compile(r"^(\S+)\s*=\s*(-\d+)\s*$")
_COMPILER_LISTING_STACK_ALLOCATION_RE = re.compile(
    r"\bsub\s+esp,\s+(\d+|0[0-9A-Fa-f]+H)\b",
    re.IGNORECASE,
)


def parse_compiler_listing_spans(text: str) -> tuple[CompilerListingSpan, ...]:
    source_lines: list[int] = []
    instruction_offsets: list[int] = []
    spans: list[CompilerListingSpan] = []

    def flush() -> None:
        if instruction_offsets:
            spans.append(
                CompilerListingSpan(
                    source_lines=tuple(dict.fromkeys(source_lines)),
                    instruction_offsets=tuple(instruction_offsets),
                ),
            )
            instruction_offsets.clear()
            source_lines.clear()

    for line in text.splitlines():
        if source_match := _COMPILER_LISTING_SOURCE_RE.match(line):
            if instruction_offsets:
                flush()
            source_lines.append(int(source_match.group(1)))
            continue
        if instruction_match := _COMPILER_LISTING_INSTRUCTION_RE.match(line):
            instruction_offsets.append(int(instruction_match.group(1), 16))
    flush()
    return tuple(spans)


def parse_compiler_listing_stack_layout(
    text: str,
    *,
    symbol: str,
) -> CompilerListingStackLayout:
    """Recover the candidate compiler's stack aliases without claiming native names."""

    lines = text.splitlines()
    accepted_symbols = {symbol, symbol.removeprefix("_")}
    accepted_symbols |= {f"_{value}" for value in accepted_symbols}
    proc_index: int | None = None
    for index, line in enumerate(lines):
        match = _COMPILER_LISTING_PROC_RE.match(line)
        if match and match.group(1) in accepted_symbols:
            proc_index = index
            break
    if proc_index is None:
        return CompilerListingStackLayout(None, ())

    segment_index = max(
        (
            index
            for index, line in enumerate(lines[:proc_index])
            if line.rstrip().endswith("SEGMENT")
        ),
        default=proc_index,
    )
    symbols = tuple(
        CompilerListingStackSymbol(
            name=match.group(1),
            offset=int(match.group(2)),
            generated=match.group(1).startswith("$T"),
        )
        for line in lines[segment_index + 1 : proc_index]
        if (match := _COMPILER_LISTING_STACK_SYMBOL_RE.match(line))
    )

    allocation: int | None = None
    for line in lines[proc_index + 1 : proc_index + 41]:
        if match := _COMPILER_LISTING_STACK_ALLOCATION_RE.search(line):
            token = match.group(1)
            allocation = int(token[:-1], 16) if token.upper().endswith("H") else int(token)
            break
    return CompilerListingStackLayout(allocation, symbols)


def generate_compiler_listing(
    config: ScratchConfig,
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    output: Path | None = None,
) -> CompilerListingResult:
    """Generate a VC source/assembly listing and prove its function object is unchanged."""

    import tempfile

    if config.archive is not None or config.import_thunk is not None:
        raise ValueError("compiler listings require a source-backed scratch")
    match_root = match_root.resolve()
    source = config.directory / config.source
    validate_scratch_source(source)
    staged_source_text = _apply_auto_inline_boundaries(
        source.read_bytes().decode("latin1"),
        config.auto_inline_off,
        source=source,
    )
    _validate_scratch_source_text(staged_source_text, source)
    canonical_path = compile_scratch(config, match_root)
    canonical_object_data = canonical_path.read_bytes()
    canonical_object = parse_coff_object(canonical_object_data)
    canonical_function = extract_object_function(
        canonical_object,
        config.symbol,
        extent=config.archive_extent,
        end_symbol=config.archive_end_symbol,
        size=config.archive_size,
    )
    source_sha256 = hashlib.sha256(staged_source_text.encode("latin1")).hexdigest()
    if output is None:
        output = (
            match_root
            / ".cache"
            / "listings"
            / config.directory.name
            / f"{_scratch_profile_digest(config)}-{source_sha256[:12]}"
            / Path(config.source).with_suffix(".cod").name
        )
    output = output.resolve()
    metadata_path = output.with_suffix(".json")

    with tempfile.TemporaryDirectory(prefix=f"crimson-listing-{config.directory.name}-") as temp_name:
        temp = Path(temp_name)
        temp_source = temp / Path(config.source).name
        temp_object = temp / Path(config.source).with_suffix(".obj").name
        temp_listing = temp / "listing.cod"
        temp_source.write_bytes(staged_source_text.encode("latin1"))
        command = [
            str(match_root / "cl.sh"),
            "/c",
            *shlex.split(config.cflags),
            "/FAsc",
            f"/Fa{temp_listing.name}",
            temp_source.name,
        ]
        environment = dict(os.environ)
        environment["MSVC_VER"] = config.compiler
        environment.pop("CRIMSON_MATCH_INCLUDE_OVERLAY", None)
        if config.include_overlay is not None:
            environment["CRIMSON_MATCH_INCLUDE_OVERLAY"] = str(config.include_overlay.resolve())
        completed = run_compiler(
            command,
            cwd=temp,
            env=environment,

        )
        if completed.returncode != 0 or not temp_object.is_file() or not temp_listing.is_file():
            raise RuntimeError(f"listing compile failed:\n{completed.stdout}{completed.stderr}")
        diagnostic_object_data = temp_object.read_bytes()
        diagnostic_function = extract_object_function(
            parse_coff_object(diagnostic_object_data),
            config.symbol,
            extent=config.archive_extent,
            end_symbol=config.archive_end_symbol,
            size=config.archive_size,
        )
        if diagnostic_function != canonical_function:
            raise ValueError(
                "listing compile changed the extracted object function; refusing misleading diagnostics",
            )
        listing_data = temp_listing.read_bytes()

    listing_text = listing_data.decode("latin1")
    spans = parse_compiler_listing_spans(listing_text)
    stack_layout = parse_compiler_listing_stack_layout(
        listing_text,
        symbol=config.symbol or config.function,
    )
    _write_bytes_atomic(output, listing_data)
    payload = {
        "schema": 1,
        "kind": "crimson-compiler-listing",
        "scratch": str(config.directory.resolve()),
        "function": config.function,
        "source": config.source,
        "source_sha256": source_sha256,
        "compiler": config.compiler,
        "cflags": config.cflags,
        "listing_flags": ["/FAsc"],
        "listing_sha256": hashlib.sha256(listing_data).hexdigest(),
        "canonical_object": str(canonical_path.resolve()),
        "canonical_object_sha256": hashlib.sha256(canonical_object_data).hexdigest(),
        "diagnostic_object_sha256": hashlib.sha256(diagnostic_object_data).hexdigest(),
        "object_function_equivalent": True,
        "function_sha256": hashlib.sha256(canonical_function.data).hexdigest(),
        "function_bytes": len(canonical_function.data),
        "relocations": len(canonical_function.relocation_references),
        "spans": [
            {
                "source_lines": list(span.source_lines),
                "instruction_offsets": list(span.instruction_offsets),
            }
            for span in spans
        ],
        "stack_layout": {
            "prologue_allocation_bytes": stack_layout.prologue_allocation_bytes,
            "symbol_count": len(stack_layout.symbols),
            "distinct_slots": stack_layout.distinct_slots,
            "reused_slots": stack_layout.reused_slots,
            "generated_temporaries": stack_layout.generated_temporaries,
            "symbols": [
                {
                    "name": symbol.name,
                    "offset": symbol.offset,
                    "generated": symbol.generated,
                }
                for symbol in stack_layout.symbols
            ],
        },
        "caveat": (
            "Source-line scheduling comes from the reconstructed source and selected compiler; "
            "stack symbols and aliases describe only that candidate compilation. This does not "
            "recover original local names or prove native variable lifetimes."
        ),
    }
    _write_text_atomic(metadata_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return CompilerListingResult(
        listing_path=output,
        metadata_path=metadata_path,
        scratch=config.directory,
        function=config.function,
        compiler=config.compiler,
        cflags=config.cflags,
        canonical_object=canonical_path,
        canonical_object_sha256=hashlib.sha256(canonical_object_data).hexdigest(),
        diagnostic_object_sha256=hashlib.sha256(diagnostic_object_data).hexdigest(),
        function_sha256=hashlib.sha256(canonical_function.data).hexdigest(),
        function_bytes=len(canonical_function.data),
        relocations=len(canonical_function.relocation_references),
        spans=spans,
        stack_layout=stack_layout,
    )


def compiler_listing_payload(result: CompilerListingResult) -> dict[str, Any]:
    return {
        "listing": str(result.listing_path),
        "metadata": str(result.metadata_path),
        "scratch": str(result.scratch),
        "function": result.function,
        "compiler": result.compiler,
        "cflags": result.cflags,
        "canonical_object": str(result.canonical_object),
        "canonical_object_sha256": result.canonical_object_sha256,
        "diagnostic_object_sha256": result.diagnostic_object_sha256,
        "object_function_equivalent": True,
        "function_sha256": result.function_sha256,
        "function_bytes": result.function_bytes,
        "relocations": result.relocations,
        "source_spans": len(result.spans),
        "machine_rows": sum(len(span.instruction_offsets) for span in result.spans),
        "stack_layout": {
            "prologue_allocation_bytes": result.stack_layout.prologue_allocation_bytes,
            "symbol_count": len(result.stack_layout.symbols),
            "distinct_slots": result.stack_layout.distinct_slots,
            "reused_slots": result.stack_layout.reused_slots,
            "generated_temporaries": result.stack_layout.generated_temporaries,
        },
    }


def render_compiler_listing_result(result: CompilerListingResult) -> str:
    payload = compiler_listing_payload(result)
    return (
        f"listing={payload['listing']} metadata={payload['metadata']}\n"
        f"function={result.function} compiler={result.compiler} cflags={result.cflags}\n"
        f"object_function_equivalent=yes bytes={result.function_bytes} "
        f"relocations={result.relocations} source_spans={payload['source_spans']} "
        f"machine_rows={payload['machine_rows']}\n"
        f"stack-allocation={result.stack_layout.prologue_allocation_bytes} "
        f"symbols={len(result.stack_layout.symbols)} "
        f"slots={result.stack_layout.distinct_slots} "
        f"reused-slots={result.stack_layout.reused_slots} "
        f"generated-temporaries={result.stack_layout.generated_temporaries}"
    )


def _exception_summary(exc: Exception) -> str:
    """Keep one actionable line from an exception for tabular status output."""

    lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
    if not lines:
        return type(exc).__name__
    heading = lines[0]
    if heading.endswith(":") and len(lines) > 1:
        detail = next(
            (line for line in lines[1:] if "error" in line.casefold()),
            lines[1],
        )
        return f"{heading} {detail}"
    return heading


def evaluate_scratch(
    config: ScratchConfig,
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    deadline: float | None = None,
) -> ScratchStatus:
    """Compile and evaluate one explicit scratch configuration."""

    match_root = match_root.resolve()
    image_path, functions_path, metadata_path = _paths_for_image(config.image)
    manifest = load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=config.image,
    )
    address = 0
    target_size = 0
    try:
        function, start, end = resolve_function(manifest, config.function, end_override=config.end_va)
        address = function.address
        image = load_image(image_path, manifest.image_base)
        target_size = len(image.function_bytes(start, end))
        obj_path = compile_scratch(config, match_root, deadline=deadline)
        result = run_match(
            obj_path=obj_path,
            function=config.function,
            image_path=image_path,
            functions_path=functions_path,
            metadata_path=metadata_path,
            symbol_name=config.symbol,
            object_extent=config.archive_extent,
            object_end_symbol=config.archive_end_symbol,
            object_size=config.archive_size,
            end_va=config.end_va,
            reference_aliases=config.reference_aliases,
        )
        return ScratchStatus(
            config=config,
            address=address,
            target_size=target_size,
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
    except Exception as exc:  # noqa: BLE001 - one scratch failure must remain a reportable status
        return ScratchStatus(
            config=config,
            address=address,
            target_size=target_size,
            ratio=None,
            prefix_instructions=0,
            target_instructions=0,
            candidate_instructions=0,
            error=_exception_summary(exc),
        )


def evaluate_source_probe(
    config: ScratchConfig,
    source_text: str,
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
    compiler: str | None = None,
    cflags: str | None = None,
    label: str | None = None,
) -> ProbeResult:
    """Compare a temporary source overlay without modifying the scratch."""

    if config.archive is not None or config.import_thunk is not None:
        raise ValueError("source probes are unavailable for non-source scratches")
    match_root = match_root.resolve()
    baseline_config = replace(
        config,
        compiler=compiler or config.compiler,
        cflags=cflags or config.cflags,
    )
    baseline = evaluate_scratch(baseline_config, match_root)
    probe = evaluate_source_overlay(
        baseline_config,
        source_text,
        match_root=match_root,
    )
    source_tree_sha256, source_dependencies = source_probe_tree_fingerprint(
        baseline_config,
        source_text,
        match_root,
    )
    return ProbeResult(
        baseline=baseline,
        probe=probe,
        source_sha256=hashlib.sha256(source_text.encode()).hexdigest(),
        label=label,
        source_tree_sha256=source_tree_sha256,
        source_dependencies=source_dependencies,
    )


def evaluate_source_overlay(
    config: ScratchConfig,
    source_text: str,
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
    source_path: Path | None = None,
    deadline: float | None = None,
) -> ScratchStatus:
    """Evaluate one temporary source or included-header overlay."""

    import tempfile

    if config.archive is not None or config.import_thunk is not None:
        raise ValueError("source overlays are unavailable for non-source scratches")
    match_root = match_root.resolve()
    source_name = Path(config.source).name
    configured_source_path = (config.directory / config.source).resolve()
    overlay_source_path = (source_path or configured_source_path).resolve()
    if overlay_source_path == configured_source_path:
        overlay_relative_path = Path(source_name)
    else:
        overlay_relative_path = next(
            (
                overlay_source_path.relative_to(root)
                for root in (config.directory.resolve(), match_root / "include")
                if overlay_source_path.is_relative_to(root)
            ),
            None,
        )
        if overlay_relative_path is None:
            raise ValueError(
                "overlay source must be the configured scratch source, a scratch-local file, "
                "or a file under the match include directory",
            )
    with tempfile.TemporaryDirectory(prefix=f"crimson-match-probe-{config.directory.name}-") as temp_name:
        shadow_directory = Path(temp_name)
        (shadow_directory / "scratch.conf").write_text(
            (config.directory / "scratch.conf").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        shadow_source_path = shadow_directory / source_name
        if overlay_source_path != configured_source_path:
            shadow_source_path.write_text(
                configured_source_path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        shadow_overlay_path = shadow_directory / overlay_relative_path
        shadow_overlay_path.parent.mkdir(parents=True, exist_ok=True)
        shadow_overlay_path.write_text(source_text, encoding="utf-8")
        shadow_config = replace(
            config,
            directory=shadow_directory,
            source=source_name,
            include_overlay=(
                shadow_directory
                if overlay_source_path != configured_source_path
                else None
            ),
        )
        return evaluate_scratch(shadow_config, match_root, deadline=deadline)


def available_scratch_compilers(match_root: Path = DEFAULT_MATCH_ROOT) -> tuple[str, ...]:
    roots = (
        match_root.resolve() / "compilers",
        REPO_ROOT.parent / "snail-mail" / "tools" / "match" / "compilers",
    )
    names: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for directory in root.iterdir():
            if directory.is_dir() and any((directory / "Bin" / name).is_file() for name in ("CL.EXE", "cl.exe")):
                names.add(directory.name)
    return tuple(sorted(names))


def evaluate_profile_matrix(
    config: ScratchConfig,
    *,
    compilers: tuple[str, ...],
    cflags: tuple[str, ...],
    match_root: Path = DEFAULT_MATCH_ROOT,
) -> list[ScratchStatus]:
    if config.archive is not None or config.import_thunk is not None:
        raise ValueError("compiler profiles are unavailable for non-source scratches")
    profiles = [
        replace(config, compiler=compiler, cflags=profile_cflags)
        for compiler in dict.fromkeys(compilers)
        for profile_cflags in dict.fromkeys(cflags)
    ]
    return [evaluate_scratch(profile, match_root) for profile in profiles]


def _paths_for_image(image: str) -> tuple[Path, Path, Path]:
    return default_image_path(image), default_functions_path(image), default_metadata_path(image)


def find_scratch_configs_for_target(
    match_root: Path,
    *,
    image: str,
    address: int,
    scope: str = DEFAULT_MATCH_SCOPE,
) -> list[ScratchConfig]:
    _, functions_path, metadata_path = _paths_for_image(image)
    manifest = load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image,
        scope=scope,
    )
    matches: list[ScratchConfig] = []
    for conf_path in sorted(match_root.resolve().glob("scratches/*/scratch.conf")):
        try:
            config = load_scratch_config(conf_path.parent)
            if config.image != image:
                continue
            symbol, _, _ = resolve_function(
                manifest,
                config.function,
                end_override=config.end_va,
            )
        except (OSError, ValueError):
            continue
        if symbol.address == address:
            matches.append(config)
    return matches


def _scratch_has_unconfigured_files(directory: Path) -> bool:
    for child in directory.iterdir():
        if child.name == "build":
            continue
        if child.is_file():
            return True
        if child.is_dir() and any(path.is_file() for path in child.rglob("*")):
            return True
    return False


def _filter_scoped_scratch_configs(
    configs: Collection[ScratchConfig],
    *,
    scope: str | None,
) -> list[ScratchConfig]:
    """Keep every out-of-scope scratch out of the active scoped corpus."""
    if scope is None or scope == "all":
        return list(configs)
    ranges = load_matching_scope(scope)
    dispositions = load_matching_scope_function_dispositions(scope)
    excluded_addresses = {
        image: frozenset(row.address for row in rows)
        for image, rows in dispositions.items()
    }
    manifests: dict[str, FunctionManifest] = {}
    result: list[ScratchConfig] = []
    for config in configs:
        if config.image not in manifests:
            _, functions_path, metadata_path = _paths_for_image(config.image)
            manifests[config.image] = load_function_manifest(
                functions_path,
                metadata_path=metadata_path,
                image_name=config.image,
                scope="all",
            )
        try:
            address = resolve_function(
                manifests[config.image],
                config.function,
                end_override=config.end_va,
            )[0].address
        except ValueError:
            result.append(config)
            continue
        owned = any(row.contains(address) for row in ranges.get(config.image, ()))
        dispositioned = address in excluded_addresses.get(config.image, frozenset())
        if owned and not dispositioned:
            result.append(config)
    return result


def validate_matching_workspace(
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    scope: str = DEFAULT_MATCH_SCOPE,
) -> list[str]:
    """Return configuration and ownership errors without compiling scratches."""
    errors: list[str] = []
    manifests: dict[str, FunctionManifest] = {}
    targets: dict[tuple[str, int], list[ScratchConfig]] = {}
    for scratch_directory in sorted((match_root.resolve() / "scratches").glob("*")):
        if (
            scratch_directory.is_dir()
            and not (scratch_directory / "scratch.conf").exists()
            and _scratch_has_unconfigured_files(scratch_directory)
        ):
            errors.append(f"{scratch_directory.name}: scratch files require scratch.conf")

    configs: list[ScratchConfig] = []
    for conf_path in sorted(match_root.resolve().glob("scratches/*/scratch.conf")):
        try:
            configs.append(load_scratch_config(conf_path.parent))
        except Exception as exc:  # noqa: BLE001 - collect every invalid scratch config in one pass
            errors.append(f"{conf_path.parent.name}: {_exception_summary(exc)}")
    for config in _filter_scoped_scratch_configs(configs, scope=scope):
        try:
            if config.image not in manifests:
                _, functions_path, metadata_path = _paths_for_image(config.image)
                manifests[config.image] = load_function_manifest(
                    functions_path,
                    metadata_path=metadata_path,
                    image_name=config.image,
                    scope=scope,
                )
            symbol, _, _ = resolve_function(
                manifests[config.image],
                config.function,
                end_override=config.end_va,
            )
            targets.setdefault((config.image, symbol.address), []).append(config)
        except Exception as exc:  # noqa: BLE001 - collect every invalid scratch config in one pass
            errors.append(f"{config.directory.name}: {_exception_summary(exc)}")
    for (image, address), configs in sorted(targets.items()):
        if len(configs) < 2:
            continue
        directories = ", ".join(config.directory.name for config in configs)
        errors.append(f"duplicate target {image}:0x{address:08x}: {directories}")
    return errors


def validate_scratch_status_metadata(
    statuses: Collection[ScratchStatus],
) -> list[str]:
    """Return recovery/residual metadata that contradicts compiled status."""

    errors: list[str] = []
    for status in sorted(
        statuses,
        key=lambda value: (value.config.image, value.address, value.config.directory.name),
    ):
        config = status.config
        name = config.directory.name
        if status.state == "match":
            if config.recovery is not None:
                errors.append(
                    f"{name}: exact match must remove RECOVERY={config.recovery}",
                )
            if config.residuals:
                errors.append(
                    f"{name}: exact match must remove RESIDUAL={','.join(config.residuals)}",
                )
            continue
        if status.state == "error":
            continue
        if config.recovery == "semantic-complete" and not config.residuals:
            errors.append(f"{name}: semantic-complete scratch must declare RESIDUAL")
        reference_debt = status.masked_unresolved + status.masked_mismatches
        if reference_debt and "references" not in config.residuals:
            errors.append(
                f"{name}: {reference_debt} unresolved/mismatched references require "
                "RESIDUAL=references",
            )
    return errors


def _analysis_rows(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        rows = payload.get("entries", payload.get("functions", []))
        if isinstance(rows, list):
            return rows
    raise ValueError(f"{path}: expected function rows")


def _analysis_row_at(path: Path, address: int) -> dict[str, Any] | None:
    if not path.exists():
        return None

    def row_address(value: str | int) -> int:
        if isinstance(value, int):
            return value
        text = value.strip()
        return int(text, 0) if text.lower().startswith("0x") else int(text, 16)

    return next(
        (row for row in _analysis_rows(path) if row.get("address") and row_address(row["address"]) == address),
        None,
    )


def _analysis_function_metadata(path: Path, image: str, function: str) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("program") != image:
        return {}
    metadata = payload.get("functions", {}).get(function, {})
    return metadata if isinstance(metadata, dict) else {}


def _scratch_dump_command(config: ScratchConfig) -> str:
    argv = [
        "crimson",
        "match",
        "dump",
        str(_scratch_object_path(config)),
        config.function,
        "--image",
        str(default_image_path(config.image)),
        "--functions",
        str(default_functions_path(config.image)),
        "--metadata",
        str(default_metadata_path(config.image)),
    ]
    if config.symbol is not None:
        argv.extend(("--symbol", config.symbol))
    if config.end_va is not None:
        argv.extend(("--end", f"0x{config.end_va:08x}"))
    if config.archive_extent != "symbol":
        argv.extend(("--object-extent", config.archive_extent))
    if config.archive_end_symbol is not None:
        argv.extend(("--object-end-symbol", config.archive_end_symbol))
    if config.archive_size is not None:
        argv.extend(("--object-size", str(config.archive_size)))
    return shlex.join(argv)


def inspect_match_function(
    query: str,
    *,
    image: str = DEFAULT_IMAGE_NAME,
    scope: str = DEFAULT_MATCH_SCOPE,
    match_root: Path = DEFAULT_MATCH_ROOT,
    statuses: list[ScratchStatus] | None = None,
) -> dict[str, Any]:
    """Resolve one matching target and join its curated and tool-specific views."""
    scratch_directory = Path(query)
    if not (scratch_directory / "scratch.conf").exists():
        scratch_directory = match_root / "scratches" / query
    selected_config = (
        load_scratch_config(scratch_directory.resolve())
        if (scratch_directory / "scratch.conf").exists()
        else None
    )
    if selected_config is not None:
        image = selected_config.image
        query = selected_config.function

    _, functions_path, metadata_path = _paths_for_image(image)
    manifest = load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image,
        scope=scope,
    )
    try:
        symbol, _, _ = resolve_function(manifest, query)
    except ValueError:
        name_rows = _analysis_rows(DEFAULT_NAME_MAP_PATH)
        mapped = next(
            (
                row
                for row in name_rows
                if row.get("program") == image
                and query in (str(row.get("name", "")), *(str(alias) for alias in row.get("aliases", [])))
            ),
            None,
        )
        if mapped is None:
            raise
        symbol, _, _ = resolve_function(manifest, f"0x{parse_int(mapped['address']):08x}")

    address = symbol.address
    name_row = _analysis_row_at(DEFAULT_NAME_MAP_PATH, address)
    ida_path = default_functions_path(image)
    ghidra_path = REPO_ROOT / "analysis" / "ghidra" / "raw" / f"{image}_functions.json"
    observed = {
        "ida": {"path": str(ida_path.relative_to(REPO_ROOT)), "function": _analysis_row_at(ida_path, address)},
        "ghidra": {
            "path": str(ghidra_path.relative_to(REPO_ROOT)),
            "function": _analysis_row_at(ghidra_path, address),
        },
    }
    matching_statuses = [
        status
        for status in statuses or []
        if status.config.image == image and status.address == address
    ]
    matching_statuses = sorted(matching_statuses, key=status_rank, reverse=True)
    annotations = _analysis_function_metadata(
        REPO_ROOT / "analysis" / "annotations" / "functions.json",
        image,
        symbol.name,
    )
    ghidra_overlay = _analysis_function_metadata(
        REPO_ROOT / "analysis" / "overlays" / "ghidra_local_renames.json",
        image,
        symbol.name,
    )
    scratch_payloads = []
    for status in matching_statuses:
        scratch_payload = scratch_status_payload(status)
        scratch_payload["candidate_object"] = str(_scratch_object_path(status.config))
        scratch_payload["commands"] = {
            "dump": _scratch_dump_command(status.config),
        }
        scratch_payloads.append(scratch_payload)

    return {
        "scope": scope,
        "image": image,
        "function": symbol.name,
        "address": address,
        "end": symbol.end,
        "size": symbol.size,
        "canonical": name_row,
        "annotations": annotations,
        "ghidra_overlay": ghidra_overlay,
        "binary_ninja": {
            "target": f"{image}.bndb",
            "commands": {
                "decompile": f"bn decompile 0x{address:08x} --target {image}.bndb",
                "il": f"bn il 0x{address:08x} --target {image}.bndb",
                "disasm": f"bn disasm 0x{address:08x} --target {image}.bndb",
                "bundle": f"bn bundle function 0x{address:08x} --target {image}.bndb",
            },
        },
        "observed": observed,
        "scratches": scratch_payloads,
        "selected_scratch": str(selected_config.directory) if selected_config is not None else None,
    }


def _manifest_digest(manifest: FunctionManifest) -> str:
    payload = {
        "image": manifest.image_name,
        "image_base": manifest.image_base,
        "functions": [[function.address, function.end, function.name] for function in manifest.functions],
    }
    return hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest()


def _scratch_cache_path(config: ScratchConfig) -> Path:
    return _scratch_build_directory(config) / "match-cache.json"


def _scratch_cache_key(
    config: ScratchConfig,
    image_path: Path,
    manifest: FunctionManifest,
    match_root: Path,
    *,
    include_resolver: _ScratchIncludeResolver,
) -> dict[str, Any]:
    return {
        "version": CACHE_VERSION,
        "build": _scratch_build_key(config, match_root, include_resolver=include_resolver),
        "match": {
            "image": config.image,
            "function": config.function,
            "end_va": config.end_va,
            "symbol": config.symbol,
            "import_thunk": config.import_thunk,
            "reference_aliases": [list(alias) for alias in config.reference_aliases],
        },
        "imports_sha256": match_toolchain.file_sha256(default_functions_path(config.image).with_name("imports.json")),
        "image_sha256": match_toolchain.file_sha256(image_path),
        "matcher_sha256": match_toolchain.file_sha256(Path(__file__)),
        "manifest": _manifest_digest(manifest),
        "data_map_sha256": match_toolchain.file_sha256(DEFAULT_DATA_MAP_PATH),
        "name_map_sha256": match_toolchain.file_sha256(DEFAULT_NAME_MAP_PATH),
    }


def _masked_reference_payload(reference: MaskedReference) -> dict[str, Any]:
    return {
        "operand_index": reference.operand_index,
        "kind": reference.kind,
        "source": reference.source,
        "value": reference.value,
        "text": reference.text,
        "keys": list(reference.keys),
        "explained": reference.explained,
    }


def _masked_reference_from_payload(payload: dict[str, Any]) -> MaskedReference:
    return MaskedReference(
        operand_index=int(payload["operand_index"]),
        kind=str(payload["kind"]),
        source=str(payload["source"]),
        value=int(payload["value"]) if payload["value"] is not None else None,
        text=str(payload["text"]),
        keys=tuple(str(key) for key in payload["keys"]),
        explained=bool(payload["explained"]),
    )


def _audit_payload(audit: MaskedOperandAudit) -> list[dict[str, Any]]:
    return [
        {
            "target_index": entry.target_index,
            "candidate_index": entry.candidate_index,
            "target_offset": entry.target_offset,
            "candidate_offset": entry.candidate_offset,
            "target_address": entry.target_address,
            "candidate_address": entry.candidate_address,
            "instruction": entry.instruction,
            "target_references": [_masked_reference_payload(reference) for reference in entry.target_references],
            "candidate_references": [_masked_reference_payload(reference) for reference in entry.candidate_references],
            "status": entry.status,
        }
        for entry in audit.entries
    ]


def _audit_from_payload(payload: list[dict[str, Any]]) -> MaskedOperandAudit:
    return MaskedOperandAudit(
        tuple(
            MaskedOperandAuditEntry(
                target_index=int(entry["target_index"]),
                candidate_index=int(entry["candidate_index"]),
                target_offset=int(entry["target_offset"]),
                candidate_offset=int(entry["candidate_offset"]),
                target_address=int(entry["target_address"]),
                candidate_address=int(entry["candidate_address"]),
                instruction=str(entry["instruction"]),
                target_references=tuple(
                    _masked_reference_from_payload(reference) for reference in entry["target_references"]
                ),
                candidate_references=tuple(
                    _masked_reference_from_payload(reference) for reference in entry["candidate_references"]
                ),
                status=str(entry["status"]),
            )
            for entry in payload
        ),
    )


def _load_cached_status(
    config: ScratchConfig,
    *,
    address: int,
    image_path: Path,
    manifest: FunctionManifest,
    match_root: Path,
    include_resolver: _ScratchIncludeResolver,
) -> ScratchStatus | None:
    try:
        payload = json.loads(_scratch_cache_path(config).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("key") != _scratch_cache_key(
        config,
        image_path,
        manifest,
        match_root,
        include_resolver=include_resolver,
    ):
        return None
    try:
        fields = payload["status"]
        audit = _audit_from_payload(payload["audit"])
        return ScratchStatus(config=config, address=address, audit=audit, **fields)
    except (KeyError, TypeError, ValueError):
        return None


def _store_cached_status(
    status: ScratchStatus,
    *,
    image_path: Path,
    manifest: FunctionManifest,
    match_root: Path,
    include_resolver: _ScratchIncludeResolver,
) -> None:
    cache_path = _scratch_cache_path(status.config)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    fields = {
        "body_byte_exact": status.body_byte_exact,
        "target_padding_bytes": status.target_padding_bytes,
        "candidate_padding_bytes": status.candidate_padding_bytes,
        "target_size": status.target_size,
        "ratio": status.ratio,
        "prefix_instructions": status.prefix_instructions,
        "target_instructions": status.target_instructions,
        "candidate_instructions": status.candidate_instructions,
        "error": status.error,
        "masked_ok": status.masked_ok,
        "masked_unresolved": status.masked_unresolved,
        "masked_mismatches": status.masked_mismatches,
        "first_target_mismatch_offset": status.first_target_mismatch_offset,
        "first_candidate_mismatch_offset": status.first_candidate_mismatch_offset,
    }
    _write_text_atomic(
        cache_path,
        json.dumps(
            {
                "key": _scratch_cache_key(
                    status.config,
                    image_path,
                    manifest,
                    match_root,
                    include_resolver=include_resolver,
                ),
                "status": fields,
                "audit": _audit_payload(status.audit),
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def collect_scratch_statuses(
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    compiler: str | None = None,
    cflags: str | None = None,
    jobs: int = DEFAULT_MATCH_JOBS,
    scope: str | None = None,
    directories: Collection[Path] | None = None,
    force: bool = False,
) -> list[ScratchStatus]:
    if jobs < 1:
        raise ValueError("jobs must be positive")
    match_root = match_root.resolve()
    selected_directories = (
        {directory.resolve() for directory in directories}
        if directories is not None
        else None
    )

    configs: list[ScratchConfig] = []
    for conf_path in sorted(match_root.glob("scratches/*/scratch.conf")):
        if selected_directories is not None and conf_path.parent.resolve() not in selected_directories:
            continue
        config = load_scratch_config(conf_path.parent)
        if compiler is not None or cflags is not None:
            config = replace(config, compiler=compiler or config.compiler, cflags=cflags or config.cflags)
        configs.append(config)
    configs = _filter_scoped_scratch_configs(configs, scope=scope)

    manifest_cache: dict[str, FunctionManifest] = {}
    catalog_cache: dict[str, ReferenceCatalog] = {}
    for image_name in {config.image for config in configs}:
        _, functions_path, metadata_path = _paths_for_image(image_name)
        manifest_cache[image_name] = load_function_manifest(
            functions_path,
            metadata_path=metadata_path,
            image_name=image_name,
            scope=scope,
        )
        catalog_cache[image_name] = load_reference_catalog(manifest_cache[image_name])

    include_resolver = _ScratchIncludeResolver(match_root)
    statuses_by_directory: dict[Path, ScratchStatus] = {}
    uncached: list[ScratchConfig] = []
    for config in configs:
        manifest = manifest_cache[config.image]
        image_path, _, _ = _paths_for_image(config.image)
        try:
            function, _, _ = resolve_function(manifest, config.function, end_override=config.end_va)
            address = function.address
        except ValueError:
            address = 0
        cached = (
            None
            if force
            else _load_cached_status(
                config,
                address=address,
                image_path=image_path,
                manifest=manifest,
                match_root=match_root,
                include_resolver=include_resolver,
            )
        )
        if cached is not None:
            statuses_by_directory[config.directory] = cached
        else:
            uncached.append(config)

    image_cache = {
        image_name: load_image(_paths_for_image(image_name)[0], manifest_cache[image_name].image_base)
        for image_name in {config.image for config in uncached}
    }

    def match_config(config: ScratchConfig) -> ScratchStatus:
        manifest = manifest_cache[config.image]
        image = image_cache[config.image]
        image_path, _, _ = _paths_for_image(config.image)
        try:
            function, start, end = resolve_function(manifest, config.function, end_override=config.end_va)
            target_data = image.function_bytes(start, end)
            obj_path = compile_scratch(
                config,
                match_root,
                include_resolver=include_resolver,
                force=force,
            )
            obj = parse_coff_object(obj_path.read_bytes())
            candidate = extract_object_function(
                obj,
                config.symbol,
                extent=config.archive_extent,
                end_symbol=config.archive_end_symbol,
                size=config.archive_size,
            )
            result = match_function(
                target_data,
                candidate,
                image=image,
                target_va=start,
                reference_catalog=catalog_cache[config.image].with_object_aliases(
                    config.reference_aliases,
                ),
            )
            status = ScratchStatus(
                config=config,
                address=function.address,
                target_size=len(target_data),
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
            _store_cached_status(
                status,
                image_path=image_path,
                manifest=manifest,
                match_root=match_root,
                include_resolver=include_resolver,
            )
            return status
        except Exception as exc:  # noqa: BLE001 - one scratch failure must not cancel the worker batch
            try:
                address = resolve_function(manifest, config.function, end_override=config.end_va)[0].address
            except ValueError:
                address = 0
            return ScratchStatus(
                config=config,
                address=address,
                target_size=0,
                ratio=None,
                prefix_instructions=0,
                target_instructions=0,
                candidate_instructions=0,
                error=_exception_summary(exc),
            )

    if jobs == 1 or len(uncached) < 2:
        matched = list(map(match_config, uncached))
    else:
        with ThreadPoolExecutor(max_workers=min(jobs, len(uncached))) as executor:
            matched = list(executor.map(match_config, uncached))
    for status in matched:
        statuses_by_directory[status.config.directory] = status
    return [statuses_by_directory[config.directory] for config in configs]


def is_analyzer_placeholder(name: str) -> bool:
    """Return whether ``name`` is only an analyzer-generated identity."""

    return ANALYZER_PLACEHOLDER_RE.fullmatch(name) is not None


def _is_placeholder_note(note: str) -> bool:
    """Return whether a note admits missing identity rather than naming real behavior."""

    return note.casefold() in {"empty-nullsub", "tail-thunk-to-nullsub"} or (
        re.search(
            r"(?:^|[-_ ])unknown[-_ ]+"
            r"(?:provider|library|libname|function|identity|name)(?:$|[-_ ])",
            note,
            re.IGNORECASE,
        )
        is not None
    )


def _status_canonical_name(
    status: ScratchStatus,
    name_rows: dict[tuple[str, int], dict[str, Any]],
) -> str:
    row = name_rows.get((status.config.image, status.address))
    return str(row["name"]) if row is not None else status.config.function


def _archive_provider_key(status: ScratchStatus) -> tuple[str, str] | None:
    if status.config.archive_sha256 is None or status.config.symbol is None:
        return None
    return status.config.archive_sha256, status.config.symbol


def _snake_case_provider_name(name: str) -> str:
    """Normalize one exact provider operation without preserving COFF decoration."""

    name = re.sub(r"@\d+$", "", name).lstrip("_")
    special_names = {
        "CIacos": "ci_acos",
        "CPtoLCID": "cp_to_lcid",
        "png_get_tRNS": "png_get_trns",
    }
    if name in special_names:
        return special_names[name]
    snake = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", snake)
    return re.sub(r"_+", "_", snake).strip("_").lower()


def _d3dx_provider_symbol_suggestion(status: ScratchStatus) -> str | None:
    """Derive the repository's canonical name from an exact D3DX helper symbol."""

    member = (status.config.archive_member or "").replace("\\", "/").rsplit("/", 1)[-1]
    symbol = status.config.symbol or ""
    if member.casefold() == "cd3dximage.obj":
        if symbol == "??_GCD3DXImage@@QAEPAXI@Z":
            return "d3dx_image_scalar_deleting_dtor"
        if symbol.startswith("?d3dx_png_read_fn@@"):
            return "d3dx_png_read_fn"
        image_match = re.fullmatch(r"\?Load([A-Z0-9]*)@CD3DXImage@@.+", symbol)
        if image_match is None:
            return None
        suffix = image_match.group(1).lower()
        return f"d3dx_image_load_{suffix}" if suffix else "d3dx_image_load"
    if member.casefold() in {"jdapimin.obj", "jdapistd.obj"}:
        jpeg_match = re.fullmatch(r"\?([A-Za-z0-9_]+)@D3DX@@.+", symbol)
        if jpeg_match is None:
            return None
        operation = jpeg_match.group(1).replace(
            "jpeg_CreateDecompress",
            "jpeg_create_decompress",
        ).lower()
        if not operation.startswith("jpeg_"):
            operation = f"jpeg_{operation}"
        return f"d3dx_{operation}"
    if member.casefold() == "cd3dxfile.obj":
        file_symbols = {
            "??0CD3DXFile@@QAE@XZ": "d3dx_file_ctor",
            "??1CD3DXFile@@QAE@XZ": "d3dx_file_dtor",
            "?Close@CD3DXFile@@QAEJXZ": "d3dx_file_close",
            "?Create@CD3DXFile@@QAEJPBXH@Z": "d3dx_file_create",
            "?Open@CD3DXFile@@QAEJPBXH@Z": "d3dx_file_open",
        }
        return file_symbols.get(symbol)
    if member.casefold().startswith("png"):
        png_match = re.fullmatch(r"\?([A-Za-z0-9_]+)@D3DX@@.+", symbol)
        if png_match is None:
            return None
        operation = png_match.group(1)
        if not operation.startswith("png_"):
            return None
        return f"d3dx_{_snake_case_provider_name(operation)}"
    if member.casefold() == "jutils.obj" and symbol == "?IsMMX@D3DX@@YAHXZ":
        return "d3dx_jpeg_is_mmx"
    if member.casefold() == "cd3dxcodec.obj":
        if symbol == "??_GCD3DXCodec@@UAEPAXI@Z":
            return "d3dx_codec_scalar_deleting_dtor"
        codec_match = re.fullmatch(
            r"\?Encode@CD3DXCodec_([A-Z0-9_]+)@@UAEXIIPAUD3DXCOLOR@@@Z",
            symbol,
        )
        if codec_match is None:
            return None
        pixel_format = codec_match.group(1).removeprefix("D3DX_").lower()
        return f"d3dx_pixel_encode_{pixel_format}"
    if member.casefold() not in {
        "d3dxmath.obj",
        "d3dxmathsse.obj",
        "d3dxmathsse2.obj",
        "d3dxmathx86.obj",
        "d3dxquatsse.obj",
        "d3dxquatsse2.obj",
    }:
        return None
    match = re.fullmatch(r"\?(init|c|sse|sse2|x86)_D3DX([A-Za-z0-9]+)(\$\$1)?@@.+", symbol)
    if match is None:
        return None
    family, operation, implementation_marker = match.groups()
    operation = operation.replace("BaryCentric", "Barycentric")
    snake = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", operation)
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", snake).lower()
    implementation_suffix = "_impl" if implementation_marker is not None else ""
    return f"d3dx_{family}_{snake}{implementation_suffix}"


def _crt_provider_symbol_suggestion(status: ScratchStatus) -> str | None:
    """Derive canonical CRT helper names from selected exact VC6 symbols."""

    member = (status.config.archive_member or "").replace("\\", "/").rsplit("/", 1)[-1]
    symbol = status.config.symbol or ""
    decorated_match = re.match(r"^\?([^@]+)@@", symbol)
    decorated_operation = decorated_match.group(1) if decorated_match is not None else None
    decorated_names = {
        "trnsctrl.obj": {
            "_CallCatchBlock2": "crt_call_catch_block_2",
            "_CallMemberFunction0": "crt_call_member_function_0",
            "_CallMemberFunction2": "crt_call_member_function_2",
            "_CallSETranslator": "crt_call_se_translator",
            "_UnwindNestedFrames": "crt_unwind_nested_frames",
            "CatchGuardHandler": "crt_catch_guard_handler",
            "TranslatorGuardHandler": "crt_translator_guard_handler",
        },
        "frame.obj": {
            "_DestructExceptionObject": "crt_destruct_exception_object",
            "BuildCatchObject": "crt_build_catch_object",
            "CallCatchBlock": "crt_call_catch_block",
            "CatchIt": "crt_catch_it",
            "FindHandler": "crt_find_handler",
            "TypeMatch": "crt_type_match",
        },
        "unhandld.obj": {
            "__CxxRestoreUnhandledExceptionFilter": (
                "crt_cxx_restore_unhandled_exception_filter"
            ),
            "__CxxSetUnhandledExceptionFilter": "crt_cxx_set_unhandled_exception_filter",
            "__CxxUnhandledExceptionFilter": "crt_cxx_unhandled_exception_filter",
        },
    }
    if decorated_operation is not None:
        suggestion = decorated_names.get(member.casefold(), {}).get(decorated_operation)
        if suggestion is not None:
            return suggestion
    if member.casefold() == "sbheap.obj" and symbol in {
        "___old_sbh_alloc_block",
        "___old_sbh_alloc_block_from_page",
        "___old_sbh_decommit_pages",
        "___old_sbh_free_block",
        "___old_sbh_release_region",
        "___old_sbh_resize_block",
        "___sbh_alloc_block",
        "___sbh_alloc_new_region",
    }:
        return f"crt_{symbol.lstrip('_')}"
    if member.casefold() == "cprintf.obj" and symbol in {
        "_get_int64_arg",
        "_get_int_arg",
        "_get_short_arg",
    }:
        return f"crt_printf_{symbol.lstrip('_')}"
    if member.casefold() == "intrncvt.obj" and symbol in {
        "__CopyMan",
        "__FillZeroMan",
        "__IncMan",
        "__IsZeroMan",
        "__RoundMan",
        "__ShrMan",
        "__ZeroTail",
        "__atodbl",
        "__atoflt",
        "__ld12cvt",
        "__ld12tod",
        "__ld12tof",
    }:
        return f"crt_{_snake_case_provider_name(symbol)}"

    contextual_names = {
        ("87except.obj", "__87except"): "crt_x87_exception",
        ("_file.obj", "___endstdio"): "crt_end_stdio",
        ("_file.obj", "___initstdio"): "crt_init_stdio",
        ("calloc.obj", "$L17381"): "crt_calloc_sbh_unlock_cleanup",
        ("calloc.obj", "$L17385"): "crt_calloc_old_sbh_unlock_cleanup",
        ("common.obj", "__convertTOStoQNaN"): "crt_convert_tos_to_qnan",
        ("crt0dat.obj", "__exit"): "crt_immediate_exit",
        ("free.obj", "$L17371"): "crt_free_sbh_unlock_cleanup",
        ("free.obj", "$L17375"): "crt_free_old_sbh_unlock_cleanup",
        ("fflush.obj", "_flsall"): "crt_flsall",
        ("fp8.obj", "__setdefaultprecision"): "crt_set_default_precision",
        ("input.obj", "__inc"): "crt_scan_inc",
        ("input.obj", "__input"): "crt_scan_input",
        ("input.obj", "__un_inc"): "crt_scan_un_inc",
        ("input.obj", "__whiteout"): "crt_scan_whiteout",
        ("ismbbyte.obj", "_x_ismbbtype"): "crt_ismbbtype",
        ("malloc.obj", "$L17390"): "crt_heap_alloc_sbh_unlock_cleanup",
        ("malloc.obj", "$L17394"): "crt_heap_alloc_old_sbh_unlock_cleanup",
        ("msize.obj", "$L17132"): "crt_msize_sbh_unlock_cleanup",
        ("msize.obj", "$L17136"): "crt_msize_old_sbh_unlock_cleanup",
        ("onexit.obj", "___onexitinit"): "crt_onexit_init",
        ("realloc.obj", "$L17775"): "crt_realloc_sbh_unlock_cleanup",
        ("realloc.obj", "$L17779"): "crt_realloc_old_sbh_unlock_cleanup",
        ("trnsctrl.obj", "___CxxFrameHandler"): "crt_cxx_frame_handler_entry",
        ("tzset.obj", "__isindst"): "crt_is_in_dst",
        ("tzset.obj", "__isindst_lk"): "crt_is_in_dst_lk",
        ("x10fout.obj", "_$I10_OUTPUT"): "crt_i10_output",
    }
    suggestion = contextual_names.get((member.casefold(), symbol))
    if suggestion is not None:
        return suggestion

    member_path = (status.config.archive_member or "").replace("\\", "/").casefold()
    weak_function = is_analyzer_placeholder(
        status.config.function,
    ) or status.config.function.startswith("_")
    if (
        not weak_function
        or not symbol.startswith("_")
        or (
            "build/intel/mt_obj/" not in member_path
            and "build/intel/dll_obj/" not in member_path
        )
    ):
        return None

    operation = re.sub(r"@\d+$", "", symbol).lstrip("_")
    if operation.casefold().startswith("crt") and len(operation) > 3:
        operation = operation[3:].lstrip("_")
    return f"crt_{_snake_case_provider_name(operation)}"


def _zlib_provider_symbol_suggestion(status: ScratchStatus) -> str | None:
    """Derive canonical names from the pinned plain-C zlib provider."""

    member = (status.config.archive_member or "").replace("\\", "/").rsplit("/", 1)[-1]
    symbol = status.config.symbol or ""
    if member.casefold() == "trees.obj" and symbol == "_tr_static_init":
        return "zlib_tr_static_init"
    return None


def _source_provider_symbol_suggestion(status: ScratchStatus) -> str | None:
    """Derive contextual identities from exact, versioned third-party source."""

    source = status.config.source.replace("\\", "/").casefold()
    symbol = status.config.symbol or ""
    scratch_name = status.config.directory.name.casefold()
    repo_source_symbols = {
        "shared/grim_jpeg_source_callbacks.cpp": {
            "grim_jpeg_destroy_decompress",
            "grim_jpeg_fill_input_buffer",
            "grim_jpeg_skip_input_data",
            "grim_jpeg_source_noop",
        },
        "shared/grim_png_callbacks.cpp": {"grim_png_error_longjmp"},
    }
    for source_suffix, symbols in repo_source_symbols.items():
        if source.endswith(source_suffix) and symbol in symbols:
            return symbol
    if (
        source.endswith("shared/grim_vertex_space_converter.cpp")
        and symbol.startswith("?noop@grim_vertex_space_converter_t@@")
    ):
        return "grim_vertex_space_converter_noop"
    if (
        status.config.image == "grim.dll"
        and source.endswith("third_party/sources/ijg-libjpeg-6a/jdapistd.c")
        and scratch_name.startswith("grim_jaz_")
        and symbol in {"jpeg_read_scanlines", "jpeg_start_decompress", "output_pass_setup"}
    ):
        operation = symbol if symbol.startswith("jpeg_") else f"jpeg_{symbol}"
        return f"grim_jaz_{operation}"
    if (
        status.config.image == "grim.dll"
        and source.endswith("third_party/sources/ijg-libjpeg-6a/jdapimin.c")
        and symbol
        in {
            "default_decompress_parms",
            "jpeg_CreateDecompress",
            "jpeg_consume_input",
            "jpeg_finish_decompress",
            "jpeg_read_header",
        }
    ):
        operation = symbol.replace("jpeg_CreateDecompress", "jpeg_create_decompress").lower()
        if not operation.startswith("jpeg_"):
            operation = f"jpeg_{operation}"
        return f"grim_jaz_{operation}"
    return None


def collect_naming_debt(
    statuses: Collection[ScratchStatus],
    *,
    name_map_path: Path = DEFAULT_NAME_MAP_PATH,
    naming_hints_path: Path = DEFAULT_NAMING_HINTS_PATH,
    data_map_path: Path | None = None,
) -> list[NamingDebtRow]:
    """Find recovered identities and curated maps that expose weaker analyzer names.

    Suggestions are deliberately conservative: an exact archive scratch receives a
    proposed name when another exact scratch from the same hash-pinned archive symbol
    has one unique canonical identity, or when a recognized D3DX helper's decorated
    COFF symbol directly encodes the repository's canonical helper name. Placeholder
    aliases in either curated map are reported even when no exact scratch owns the row.
    """

    exact_statuses = [status for status in statuses if status.state == "match"]
    name_rows = {
        (str(row.get("program", "")), parse_int(row["address"])): row
        for row in load_name_map_rows(name_map_path)
    }
    naming_hints = load_naming_hints(naming_hints_path)
    canonical_names = {
        id(status): _status_canonical_name(status, name_rows)
        for status in exact_statuses
    }
    raw_name_addresses: dict[str, dict[str, tuple[int, ...]]] = {}
    for image in {status.config.image for status in exact_statuses}:
        functions_path = default_functions_path(image)
        addresses: dict[str, list[int]] = defaultdict(list)
        if functions_path.exists():
            for entry in json.loads(functions_path.read_text(encoding="utf-8")):
                name = str(entry.get("name", ""))
                address = parse_int(entry["address"])
                if name and address not in addresses[name.casefold()]:
                    addresses[name.casefold()].append(address)
        raw_name_addresses[image] = {
            name: tuple(values)
            for name, values in addresses.items()
        }
    provider_peers: dict[tuple[str, str], list[ScratchStatus]] = defaultdict(list)
    for status in exact_statuses:
        key = _archive_provider_key(status)
        if key is not None:
            provider_peers[key].append(status)

    rows: list[NamingDebtRow] = []
    audited_function_rows: set[tuple[str, int, str]] = set()
    for status in exact_statuses:
        canonical = canonical_names[id(status)]
        map_row = name_rows.get((status.config.image, status.address), {})
        if map_row:
            audited_function_rows.add(
                (status.config.image, status.address, str(map_row.get("name", canonical))),
            )
        archive_symbol_suggestion = (
            _d3dx_provider_symbol_suggestion(status)
            or _crt_provider_symbol_suggestion(status)
            or _zlib_provider_symbol_suggestion(status)
        )
        source_symbol_suggestion = _source_provider_symbol_suggestion(status)
        symbol_suggestion = archive_symbol_suggestion or source_symbol_suggestion
        naming_hint = naming_hints.get((status.config.image, status.address))
        if (
            naming_hint is not None
            and symbol_suggestion is not None
            and naming_hint.name != symbol_suggestion
        ):
            raise ValueError(
                f"{naming_hints_path}: {status.config.image}:0x{status.address:08x} "
                f"hint {naming_hint.name!r} conflicts with exact provider suggestion "
                f"{symbol_suggestion!r}",
            )
        identity_suggestion = naming_hint.name if naming_hint is not None else symbol_suggestion
        placeholder_aliases = tuple(
            str(alias)
            for alias in map_row.get("aliases", ())
            if is_analyzer_placeholder(str(alias))
        )
        placeholder_references = tuple(
            target
            for _, target in status.config.reference_aliases
            if is_analyzer_placeholder(target)
        )
        placeholder_comment_tokens = tuple(
            dict.fromkeys(
                ANALYZER_PLACEHOLDER_TOKEN_RE.findall(str(map_row.get("comment", ""))),
            ),
        )
        reference_suggestions: list[tuple[str, str, str]] = []
        for object_symbol, target in status.config.reference_aliases:
            if not is_analyzer_placeholder(target):
                continue
            address_match = ANALYZER_ADDRESS_NAME_RE.fullmatch(target)
            candidate_addresses = (
                (int(address_match.group(1), 16),)
                if address_match is not None
                else raw_name_addresses.get(status.config.image, {}).get(target.casefold(), ())
            )
            if len(candidate_addresses) != 1:
                continue
            target_row = name_rows.get((status.config.image, candidate_addresses[0]))
            if target_row is None or bool(target_row.get("exclude")):
                continue
            target_name = str(target_row["name"])
            if is_analyzer_placeholder(target_name) or target_name.casefold() == target.casefold():
                continue
            reference_suggestions.append((object_symbol, target, target_name))
        issues: list[str] = []
        if is_analyzer_placeholder(canonical) or is_analyzer_placeholder(status.config.function):
            issues.append("placeholder-function")
        address_suffixed_directory = status.config.directory.name.casefold() in {
            f"{canonical}_{status.address:x}".casefold(),
            f"{canonical}_{status.address:08x}".casefold(),
            f"{status.config.function}_{status.address:x}".casefold(),
            f"{status.config.function}_{status.address:08x}".casefold(),
        }
        if is_analyzer_placeholder(status.config.directory.name):
            issues.append("placeholder-directory")
        elif (
            address_suffixed_directory
            and not is_analyzer_placeholder(canonical)
            and (identity_suggestion is None or identity_suggestion == canonical)
        ):
            issues.append("address-suffixed-directory")
        elif identity_suggestion is not None:
            expected_directories = {
                identity_suggestion.casefold(),
                f"{_scratch_image_prefix(status.config.image)}_{identity_suggestion}".casefold(),
            }
            if status.config.directory.name.casefold() not in expected_directories:
                issues.append(
                    "curated-directory-conflict"
                    if naming_hint is not None
                    else "provider-directory-conflict",
                )
        if placeholder_aliases:
            issues.append("placeholder-alias")
        if placeholder_references:
            issues.append("placeholder-reference")
        if _is_placeholder_note(status.config.note):
            issues.append("placeholder-note")
        if placeholder_comment_tokens:
            issues.append("placeholder-comment")
        if (
            identity_suggestion is not None
            and not is_analyzer_placeholder(canonical)
            and not is_analyzer_placeholder(status.config.function)
            and (
                canonical != identity_suggestion
                or status.config.function != identity_suggestion
            )
        ):
            issues.append(
                "curated-name-conflict"
                if naming_hint is not None
                else "provider-name-conflict",
            )
        if not issues:
            continue

        suggestion: str | None = None
        suggestion_sources: tuple[str, ...] = ()
        suggestion_comment: str | None = None
        key = _archive_provider_key(status)
        if (
            "placeholder-function" in issues
            or "address-suffixed-directory" in issues
            or "provider-name-conflict" in issues
            or "provider-directory-conflict" in issues
            or "curated-name-conflict" in issues
            or "curated-directory-conflict" in issues
            or ("placeholder-note" in issues and identity_suggestion is not None)
        ):
            if naming_hint is not None:
                suggestion = naming_hint.name
                suggestion_sources = (f"curated-hint:{naming_hint.evidence}",)
                suggestion_comment = naming_hint.comment
            elif symbol_suggestion is not None:
                suggestion = symbol_suggestion
                source_kind = (
                    "provider-symbol"
                    if archive_symbol_suggestion is not None
                    else "source-symbol"
                )
                suggestion_sources = (f"{source_kind}:{status.config.symbol}",)
            elif key is not None:
                peers = [
                    peer
                    for peer in provider_peers[key]
                    if peer.config.image != status.config.image
                    and not is_analyzer_placeholder(canonical_names[id(peer)])
                ]
                peer_names = {canonical_names[id(peer)] for peer in peers}
                if len(peer_names) == 1:
                    candidate = next(iter(peer_names))
                    if candidate != canonical:
                        suggestion = candidate
                        suggestion_sources = tuple(
                            sorted(
                                {
                                    f"{peer.config.image}:0x{peer.address:08x}"
                                    for peer in peers
                                    if canonical_names[id(peer)] == candidate
                                },
                            ),
                        )
            if suggestion is None and "address-suffixed-directory" in issues:
                suggestion = canonical
                suggestion_sources = (f"canonical-identity:{status.config.image}:0x{status.address:08x}",)

        try:
            scratch = status.config.directory.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            scratch = status.config.directory.as_posix()
        rows.append(
            NamingDebtRow(
                image=status.config.image,
                address=status.address,
                function=canonical,
                configured_function=status.config.function,
                scratch=scratch,
                issues=tuple(issues),
                placeholder_aliases=placeholder_aliases,
                placeholder_references=placeholder_references,
                reference_suggestions=tuple(reference_suggestions),
                provider_symbol=status.config.symbol,
                provider_member=status.config.archive_member,
                suggestion=suggestion,
                suggestion_sources=suggestion_sources,
                suggestion_comment=suggestion_comment,
                placeholder_comment_tokens=placeholder_comment_tokens,
            ),
        )

    try:
        name_map_display = name_map_path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        name_map_display = name_map_path.as_posix()
    for map_row in name_rows.values():
        image = str(map_row.get("program", ""))
        address = parse_int(map_row["address"])
        canonical = str(map_row.get("name", ""))
        key = (image, address, canonical)
        if key in audited_function_rows:
            continue
        placeholder_aliases = tuple(
            str(alias)
            for alias in map_row.get("aliases", ())
            if is_analyzer_placeholder(str(alias))
        )
        placeholder_comment_tokens = tuple(
            dict.fromkeys(
                ANALYZER_PLACEHOLDER_TOKEN_RE.findall(str(map_row.get("comment", ""))),
            ),
        )
        map_issues = tuple(
            issue
            for issue, present in (
                ("placeholder-alias", bool(placeholder_aliases)),
                ("placeholder-comment", bool(placeholder_comment_tokens)),
            )
            if present
        )
        if not map_issues:
            continue
        rows.append(
            NamingDebtRow(
                image=image,
                address=address,
                function=canonical,
                configured_function=canonical,
                scratch=name_map_display,
                issues=map_issues,
                placeholder_aliases=placeholder_aliases,
                placeholder_references=(),
                reference_suggestions=(),
                provider_symbol=None,
                provider_member=None,
                suggestion=None,
                suggestion_sources=(),
                placeholder_comment_tokens=placeholder_comment_tokens,
            ),
        )

    if data_map_path is not None and data_map_path.exists():
        payload = json.loads(data_map_path.read_text(encoding="utf-8"))
        raw_entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(raw_entries, list):
            raise TypeError(f"{data_map_path}: data map must contain an entries array")
        try:
            data_map_display = data_map_path.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            data_map_display = data_map_path.as_posix()
        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                raise TypeError(f"{data_map_path}: data-map row {index} must be an object")
            map_row = cast(dict[str, Any], raw_entry)
            placeholder_aliases = tuple(
                str(alias)
                for alias in map_row.get("aliases", ())
                if is_analyzer_placeholder(str(alias))
            )
            placeholder_comment_tokens = tuple(
                dict.fromkeys(
                    ANALYZER_PLACEHOLDER_TOKEN_RE.findall(str(map_row.get("comment", ""))),
                ),
            )
            map_issues = tuple(
                issue
                for issue, present in (
                    ("placeholder-alias", bool(placeholder_aliases)),
                    ("placeholder-comment", bool(placeholder_comment_tokens)),
                )
                if present
            )
            if not map_issues:
                continue
            canonical = str(map_row.get("name", ""))
            rows.append(
                NamingDebtRow(
                    image=str(map_row.get("program", "")),
                    address=parse_int(map_row["address"]),
                    function=canonical,
                    configured_function=canonical,
                    scratch=data_map_display,
                    issues=map_issues,
                    placeholder_aliases=placeholder_aliases,
                    placeholder_references=(),
                    reference_suggestions=(),
                    provider_symbol=None,
                    provider_member=None,
                    suggestion=None,
                    suggestion_sources=(),
                    map_kind="data",
                    placeholder_comment_tokens=placeholder_comment_tokens,
                ),
            )
    return sorted(rows, key=lambda row: (row.image, row.address, row.map_kind, row.scratch))


def _resolved_name_audit_files(repo_root: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for relative_root in ("analysis", "crimson-zig", "docs", "src", "scripts", "tools"):
        source_root = repo_root / relative_root
        if not source_root.is_dir():
            continue
        for current_root, directories, filenames in os.walk(source_root):
            analysis_only_pruned = (
                {"binary_ninja", "native", "raw"}
                if relative_root == "analysis"
                else set()
            )
            directories[:] = sorted(
                directory
                for directory in directories
                if directory not in RESOLVED_NAME_AUDIT_PRUNED_DIRECTORIES
                and directory not in analysis_only_pruned
            )
            current_path = Path(current_root)
            for filename in sorted(filenames):
                path = current_path / filename
                if path.name == "STATUS.md" or path.suffix.casefold() not in RESOLVED_NAME_AUDIT_SUFFIXES:
                    continue
                files.append(path)
    return tuple(files)


def _stronger_identity_names(
    names: Collection[str],
    *,
    token: str,
) -> tuple[str, ...]:
    folded_token = token.casefold()
    return tuple(
        dict.fromkeys(
            name
            for name in names
            if name.casefold() != folded_token and ADDRESS_DERIVED_IDENTITY_RE.fullmatch(name) is None
        ),
    )


def collect_resolved_name_references(
    *,
    repo_root: Path = REPO_ROOT,
    name_map_path: Path = DEFAULT_NAME_MAP_PATH,
    data_map_path: Path = DEFAULT_DATA_MAP_PATH,
) -> list[ResolvedNameReferenceRow]:
    """Find analyzer identities whose addresses now have stronger curated names."""

    function_names: dict[tuple[str, int], list[str]] = defaultdict(list)
    function_aliases: dict[tuple[str, int], set[str]] = defaultdict(set)
    function_identifiers: dict[str, set[str]] = defaultdict(set)
    for row in load_name_map_rows(name_map_path):
        key = (str(row.get("program", "")), parse_int(row["address"]))
        name = str(row.get("name", ""))
        aliases = {
            str(alias).casefold()
            for alias in row.get("aliases", ())
            if isinstance(alias, str)
        }
        function_names[key].append(name)
        function_aliases[key].update(aliases)
        function_identifiers[key[0]].add(name.casefold())
        function_identifiers[key[0]].update(aliases)

    data_payload = json.loads(data_map_path.read_text(encoding="utf-8"))
    raw_data_rows = data_payload.get("entries") if isinstance(data_payload, dict) else None
    if not isinstance(raw_data_rows, list):
        raise TypeError(f"{data_map_path}: data map must contain an entries array")
    data_names: dict[tuple[str, int], list[str]] = defaultdict(list)
    for index, raw_row in enumerate(raw_data_rows):
        if not isinstance(raw_row, dict):
            raise TypeError(f"{data_map_path}: data-map row {index} must be an object")
        row = cast(dict[str, Any], raw_row)
        data_names[(str(row.get("program", "")), parse_int(row["address"]))].append(
            str(row.get("name", "")),
        )

    function_by_address: dict[int, list[tuple[str, tuple[str, ...]]]] = defaultdict(list)
    for (image, address), names in function_names.items():
        function_by_address[address].append((image, tuple(names)))
    data_by_address: dict[int, list[tuple[str, tuple[str, ...]]]] = defaultdict(list)
    for (image, address), names in data_names.items():
        data_by_address[address].append((image, tuple(names)))

    superseded_function_names: dict[
        str,
        list[tuple[str, str, int, tuple[str, ...]]],
    ] = defaultdict(list)
    raw_functions_root = repo_root / "analysis" / "ida" / "raw"
    for image in sorted({image for image, _ in function_names}):
        functions_path = raw_functions_root / image / "functions.json"
        if not functions_path.is_file():
            continue
        payload = json.loads(functions_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise TypeError(f"{functions_path}: raw functions must contain a list")
        for index, raw_row in enumerate(payload):
            if not isinstance(raw_row, dict):
                raise TypeError(f"{functions_path}: function row {index} must be an object")
            token = str(raw_row.get("name", ""))
            if IDENTIFIER_TOKEN_RE.fullmatch(token) is None:
                continue
            if token.casefold() in function_identifiers[image]:
                continue
            raw_address = raw_row.get("address")
            if not isinstance(raw_address, (str, int)):
                raise TypeError(f"{functions_path}: function row {index} has invalid address")
            address = parse_int(raw_address)
            key = (image, address)
            names = function_names.get(key, ())
            canonical_names = _stronger_identity_names(names, token=token)
            if not canonical_names:
                continue
            superseded_function_names[token.casefold()].append(
                (token, image, address, canonical_names),
            )

    rows: list[ResolvedNameReferenceRow] = []
    seen: set[tuple[str, int, str, str, int]] = set()
    native_definitions_root = repo_root / "tools" / "native" / "data_definitions"

    def append_row(
        *,
        path: Path,
        line: int,
        source: str,
        token: str,
        image: str,
        address: int,
        names: Collection[str],
    ) -> None:
        canonical_names = _stronger_identity_names(names, token=token)
        if not canonical_names:
            return
        try:
            display_path = path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            display_path = path.as_posix()
        key = (display_path, line, token, image, address)
        if key in seen:
            return
        seen.add(key)
        rows.append(
            ResolvedNameReferenceRow(
                path=display_path,
                line=line,
                source=source,
                token=token,
                image=image,
                address=address,
                canonical_names=canonical_names,
            ),
        )

    for path in _resolved_name_audit_files(repo_root):
        if path.is_relative_to(native_definitions_root):
            continue
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(contents.splitlines(), start=1):
            for match in ADDRESS_DERIVED_REFERENCE_RE.finditer(line):
                token = match.group("token")
                address = int(match.group("address"), 16)
                prefix = match.group("prefix").casefold()
                candidates = (
                    function_by_address.get(address, ())
                    if prefix in FUNCTION_REFERENCE_PREFIXES
                    else data_by_address.get(address, ())
                )
                for image, names in candidates:
                    append_row(
                        path=path,
                        line=line_number,
                        source="text",
                        token=token,
                        image=image,
                        address=address,
                        names=names,
                    )
            for match in IDENTIFIER_TOKEN_RE.finditer(line):
                for token, image, address, names in superseded_function_names.get(
                    match.group(0).casefold(),
                    (),
                ):
                    append_row(
                        path=path,
                        line=line_number,
                        source="superseded-identity",
                        token=token,
                        image=image,
                        address=address,
                        names=names,
                    )

    if native_definitions_root.is_dir():
        for path in sorted(native_definitions_root.glob("*.json")):
            contents = path.read_text(encoding="utf-8")
            lines = contents.splitlines()
            payload = json.loads(contents)
            image = str(payload.get("image", "")) if isinstance(payload, dict) else ""
            raw_entries = payload.get("entries") if isinstance(payload, dict) else None
            if not isinstance(raw_entries, list):
                raise TypeError(f"{path}: native data definitions require an entries array")
            location_offsets: dict[tuple[str, str], int] = defaultdict(int)
            for entry in raw_entries:
                if not isinstance(entry, dict):
                    continue
                initializer_symbols = entry.get("initializer_symbols", ())
                if not isinstance(initializer_symbols, list):
                    continue
                for raw_symbol in initializer_symbols:
                    if not isinstance(raw_symbol, list) or len(raw_symbol) not in {2, 3}:
                        continue
                    address_text, token = raw_symbol[-2:]
                    if not isinstance(address_text, str) or not isinstance(token, str):
                        continue
                    address = parse_int(address_text)
                    names = function_names.get((image, address), ())
                    if not names:
                        names = data_names.get((image, address), ())
                    if not names:
                        continue
                    is_address_derived = ADDRESS_DERIVED_IDENTITY_RE.fullmatch(token) is not None
                    is_superseded = any(
                        candidate_image == image and candidate_address == address
                        for _, candidate_image, candidate_address, _ in superseded_function_names.get(
                            token.casefold(),
                            (),
                        )
                    )
                    if not is_address_derived and not is_superseded:
                        continue
                    location_key = (address_text.casefold(), token)
                    occurrence = location_offsets[location_key]
                    matching_lines = [
                        index
                        for index, line in enumerate(lines, start=1)
                        if json.dumps(address_text) in line and json.dumps(token) in line
                    ]
                    line_number = (
                        matching_lines[min(occurrence, len(matching_lines) - 1)]
                        if matching_lines
                        else 1
                    )
                    location_offsets[location_key] += 1
                    append_row(
                        path=path,
                        line=line_number,
                        source="native-initializer",
                        token=token,
                        image=image,
                        address=address,
                        names=names,
                    )

    return sorted(rows, key=lambda row: (row.path, row.line, row.token, row.image, row.address))


def rewrite_resolved_name_references(
    rows: Collection[ResolvedNameReferenceRow],
    *,
    repo_root: Path = REPO_ROOT,
) -> dict[str, int]:
    """Replace unambiguous analyzer labels with their curated identities.

    When the canonical identity is already present on the same line, retain the
    useful address as a plain hexadecimal literal instead of duplicating the
    name. Rows with multiple curated identities are left for manual review.
    """

    rows_by_path: dict[str, list[ResolvedNameReferenceRow]] = defaultdict(list)
    for row in rows:
        rows_by_path[row.path].append(row)

    files_updated = 0
    references_updated = 0
    rows_skipped = 0
    for display_path, path_rows in sorted(rows_by_path.items()):
        path = Path(display_path)
        if not path.is_absolute():
            path = repo_root / path
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        rows_by_line: dict[int, list[ResolvedNameReferenceRow]] = defaultdict(list)
        native_rows: list[ResolvedNameReferenceRow] = []
        for row in path_rows:
            if row.source == "native-initializer":
                native_rows.append(row)
            else:
                rows_by_line[row.line].append(row)

        file_updated = False
        for line_number, line_rows in sorted(rows_by_line.items()):
            if line_number < 1 or line_number > len(lines):
                rows_skipped += len(line_rows)
                continue
            original_line = lines[line_number - 1]
            rewritten_line = original_line
            for row in sorted(line_rows, key=lambda candidate: candidate.token):
                if len(row.canonical_names) != 1:
                    rows_skipped += 1
                    continue
                canonical = row.canonical_names[0]
                canonical_pattern = re.compile(
                    rf"(?<![0-9A-Za-z_]){re.escape(canonical)}(?![0-9A-Za-z_])",
                )
                replacement = (
                    f"0x{row.address:08x}"
                    if canonical_pattern.search(original_line) is not None
                    else canonical
                )
                token_pattern = re.compile(
                    rf"(?<![0-9A-Za-z_]){re.escape(row.token)}(?![0-9A-Za-z_])",
                )
                rewritten_line, replacement_count = token_pattern.subn(replacement, rewritten_line)
                if replacement_count == 0:
                    rows_skipped += 1
                    continue
                references_updated += replacement_count
                file_updated = True
            lines[line_number - 1] = rewritten_line
        rewritten_contents = "".join(lines)
        for row in native_rows:
            if len(row.canonical_names) != 1:
                rows_skipped += 1
                continue
            quoted_token = json.dumps(row.token)
            quoted_canonical = json.dumps(row.canonical_names[0])
            replacement_count = rewritten_contents.count(quoted_token)
            if replacement_count == 0:
                rows_skipped += 1
                continue
            rewritten_contents = rewritten_contents.replace(quoted_token, quoted_canonical)
            references_updated += replacement_count
            file_updated = True
        if file_updated:
            path.write_text(rewritten_contents, encoding="utf-8")
            files_updated += 1

    return {
        "files_updated": files_updated,
        "references_updated": references_updated,
        "rows_skipped": rows_skipped,
    }


def _rewrite_superseded_identity_references(
    replacements_by_image: dict[str, dict[str, str]],
    *,
    repo_root: Path,
    match_root: Path,
    excluded_paths: Collection[Path] = (),
) -> int:
    """Rewrite semantic identities while the superseded names are still known."""

    targets_by_token: dict[str, dict[str, str]] = defaultdict(dict)
    spelling_by_token: dict[str, str] = {}
    for image in sorted(replacements_by_image):
        for old_name, canonical_name in sorted(replacements_by_image[image].items()):
            if old_name.casefold() == canonical_name.casefold():
                continue
            folded_old = old_name.casefold()
            spelling_by_token.setdefault(folded_old, old_name)
            targets_by_token[folded_old].setdefault(canonical_name.casefold(), canonical_name)
    global_replacements = {
        spelling_by_token[folded_old]: next(iter(targets.values()))
        for folded_old, targets in targets_by_token.items()
        if len(targets) == 1
    }

    excluded = {path.resolve() for path in excluded_paths}
    scratch_root = (match_root / "scratches").resolve()
    references_updated = 0
    for path in _resolved_name_audit_files(repo_root):
        resolved_path = path.resolve()
        if resolved_path in excluded:
            continue
        replacements = global_replacements
        if resolved_path.is_relative_to(scratch_root):
            relative = resolved_path.relative_to(scratch_root)
            if len(relative.parts) >= 2:
                config_path = scratch_root / relative.parts[0] / "scratch.conf"
                if config_path.is_file():
                    image = load_scratch_config(config_path.parent).image
                    replacements = replacements_by_image.get(image, {})
        if not replacements:
            continue
        original = path.read_text(encoding="utf-8")
        rewritten, count = _replace_identity_tokens(original, replacements)
        if rewritten == original:
            continue
        path.write_text(rewritten, encoding="utf-8")
        references_updated += count
    return references_updated


def apply_naming_suggestions(
    rows: Collection[NamingDebtRow],
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
    name_map_path: Path = DEFAULT_NAME_MAP_PATH,
    matching_scope_path: Path = DEFAULT_MATCHING_SCOPE_PATH,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Apply deterministic naming suggestions across scratches and the curated map.

    Analyzer-generated names are deliberately removed instead of retained as aliases.
    Exact decorated provider symbols remain as useful linkage aliases.
    """

    selected = [row for row in rows if row.suggestion is not None]
    if not selected:
        return {
            "applied": 0,
            "aliases_removed": 0,
            "config_references_updated": 0,
            "directories_renamed": 0,
            "map_rows_added": 0,
            "map_rows_updated": 0,
            "scope_dispositions_updated": 0,
            "text_references_updated": 0,
            "renames": [],
        }

    scratch_root = (match_root / "scratches").resolve()
    if not scratch_root.is_dir():
        raise ValueError(f"missing scratch root: {scratch_root}")

    selected_by_source: dict[Path, NamingDebtRow] = {}
    replacements_by_image: dict[str, dict[str, str]] = defaultdict(dict)
    for row in selected:
        assert row.suggestion is not None
        source = Path(row.scratch)
        if not source.is_absolute():
            source = REPO_ROOT / source
        source = source.resolve()
        if source.parent != scratch_root or not (source / "scratch.conf").is_file():
            raise ValueError(f"naming suggestion scratch is outside {scratch_root}: {source}")
        if source in selected_by_source:
            raise ValueError(f"duplicate naming suggestion for {source}")
        selected_by_source[source] = row

        old_names = {
            row.function,
            row.configured_function,
            source.name,
            *row.placeholder_aliases,
            f"FUN_{row.address:08X}",
            f"sub_{row.address:08X}",
            f"sub_{row.address:X}",
        }
        image_replacements = replacements_by_image[row.image]
        replaces_semantic_name = row.suggestion.casefold() not in {
            row.function.casefold(),
            row.configured_function.casefold(),
        }
        for old_name in old_names:
            if not old_name or (
                not is_analyzer_placeholder(old_name)
                and not replaces_semantic_name
            ):
                continue
            existing = next(
                (value for key, value in image_replacements.items() if key.casefold() == old_name.casefold()),
                None,
            )
            if existing is not None and existing != row.suggestion:
                raise ValueError(
                    f"ambiguous rename for {row.image} {old_name!r}: "
                    f"{existing!r} vs {row.suggestion!r}",
                )
            image_replacements[old_name] = row.suggestion

    ordered_sources = sorted(
        selected_by_source.items(),
        key=lambda item: (
            item[0].name.casefold().startswith(f"{_scratch_image_prefix(item[1].image)}_"),
            item[1].image,
            item[1].address,
        ),
    )
    rename_sources: list[tuple[Path, NamingDebtRow]] = []
    for source, row in ordered_sources:
        old_identities = (row.function.casefold(), row.configured_function.casefold())
        source_identity = source.name.casefold()
        carries_old_identity = any(
            source_identity == old or source_identity.startswith(f"{old}_")
            for old in old_identities
        )
        if (
            "placeholder-directory" not in row.issues
            and "address-suffixed-directory" not in row.issues
            and "provider-directory-conflict" not in row.issues
            and "curated-directory-conflict" not in row.issues
            and not carries_old_identity
        ):
            continue
        assert row.suggestion is not None
        if source.name.casefold() == row.suggestion.casefold():
            continue
        rename_sources.append((source, row))

    planned_destinations: set[Path] = set()
    directory_renames: list[tuple[Path, Path]] = []
    vacated_sources = {source.resolve() for source, _ in rename_sources}
    occupied = {
        path.resolve()
        for path in scratch_root.iterdir()
        if path.is_dir() and path.resolve() not in vacated_sources
    }
    for source, row in rename_sources:
        assert row.suggestion is not None
        destination = scratch_root / row.suggestion
        if destination.resolve() in occupied or destination.resolve() in planned_destinations:
            destination = scratch_root / f"{_scratch_image_prefix(row.image)}_{row.suggestion}"
        resolved_destination = destination.resolve()
        if resolved_destination in occupied or resolved_destination in planned_destinations:
            raise ValueError(f"scratch rename destination already exists: {destination}")
        planned_destinations.add(resolved_destination)
        directory_renames.append((source, destination))
    staging_paths = [
        scratch_root / f".naming-rename-{index:04d}"
        for index in range(len(directory_renames))
    ]
    for staging in staging_paths:
        if staging.exists():
            raise ValueError(f"scratch rename staging path already exists: {staging}")

    suggestion_by_source = {
        source: row.suggestion
        for source, row in selected_by_source.items()
        if row.suggestion is not None
    }
    config_updates: dict[Path, str] = {}
    source_updates: dict[Path, str] = {}
    reference_updates = 0
    text_references_updated = 0
    for config_path in sorted(scratch_root.glob("*/scratch.conf")):
        config = load_scratch_config(config_path.parent)
        original = config_path.read_text(encoding="utf-8")
        updated = original
        selected_row = selected_by_source.get(config_path.parent.resolve())
        suggestion = suggestion_by_source.get(config_path.parent.resolve())
        if suggestion is not None:
            updated = _replace_config_assignment(updated, "FUNCTION", suggestion)
            if (
                config.archive is None
                and config.symbol is not None
                and (
                    is_analyzer_placeholder(config.symbol)
                    or (
                        selected_row is not None
                        and config.symbol.casefold()
                        == selected_row.configured_function.casefold()
                    )
                )
            ):
                updated = _replace_config_assignment(updated, "SYMBOL", suggestion)
            if _is_placeholder_note(config.note):
                note_slug = re.sub(r"[^a-z0-9]+", "-", suggestion.lower()).strip("-")
                note_prefix = "exact-archive" if config.archive is not None else "evidence-backed"
                updated = _replace_config_assignment(updated, "NOTE", f"{note_prefix}-{note_slug}")

        image_replacements = replacements_by_image.get(config.image, {})
        folded_replacements = {key.casefold(): value for key, value in image_replacements.items()}
        rewritten_aliases: list[tuple[str, str]] = []
        for object_symbol, target_symbol in config.reference_aliases:
            replacement = folded_replacements.get(target_symbol.casefold(), target_symbol)
            reference_updates += replacement != target_symbol
            rewritten_aliases.append((object_symbol, replacement))
        if tuple(rewritten_aliases) != config.reference_aliases:
            encoded = ",".join(f"{source}:{target}" for source, target in rewritten_aliases)
            updated = _replace_config_assignment(updated, "REFERENCE_ALIASES", encoded)
        source_replacements = image_replacements
        for source_path in sorted(config_path.parent.iterdir()):
            if (
                not source_replacements
                or not source_path.is_file()
                or source_path.suffix.casefold() not in {".c", ".cc", ".cpp", ".h", ".hpp", ".inc"}
            ):
                continue
            original_source = source_path.read_text(encoding="utf-8")
            updated_source, count = _replace_identity_tokens(
                original_source,
                source_replacements,
            )
            if updated_source != original_source:
                source_updates[source_path] = updated_source
                text_references_updated += count
        if updated != original:
            config_updates[config_path] = updated

    map_rows = [dict(row) for row in load_name_map_rows(name_map_path)]
    map_by_key = {
        (str(row.get("program", "")), parse_int(row["address"])): row
        for row in map_rows
    }
    aliases_removed = 0
    for map_row in map_rows:
        program = str(map_row.get("program", ""))
        replacements = replacements_by_image.get(program, {})
        if not replacements:
            continue
        folded_replacements = {key.casefold() for key in replacements}
        aliases = map_row.get("aliases")
        if isinstance(aliases, list):
            filtered_aliases = [
                alias
                for alias in aliases
                if str(alias).casefold() not in folded_replacements
            ]
            aliases_removed += len(aliases) - len(filtered_aliases)
            if filtered_aliases:
                map_row["aliases"] = filtered_aliases
            else:
                map_row.pop("aliases", None)
        for field_name in ("signature", "comment"):
            value = map_row.get(field_name)
            if isinstance(value, str):
                if field_name == "comment" and value.startswith("Exact archive recovery from "):
                    continue
                replacement, count = _replace_identity_tokens(value, replacements)
                map_row[field_name] = replacement
                text_references_updated += count

    map_rows_added = 0
    map_rows_updated = 0
    for row in selected_by_source.values():
        assert row.suggestion is not None
        key = (row.image, row.address)
        map_row = map_by_key.get(key)
        added_map_row = map_row is None
        if map_row is None:
            new_map_row: dict[str, Any] = {
                "program": row.image,
                "address": f"0x{row.address:08x}",
                "name": row.suggestion,
                "comment": row.suggestion_comment
                or (
                    f"Exact archive recovery from {row.provider_member or 'provider object'} "
                    f"symbol {row.provider_symbol or row.suggestion}."
                ),
                "create": False,
            }
            map_row = new_map_row
            insertion = len(map_rows)
            same_program = False
            for index, candidate in enumerate(map_rows):
                if str(candidate.get("program", "")) != row.image:
                    if same_program:
                        insertion = index
                        break
                    continue
                same_program = True
                insertion = index + 1
                if parse_int(candidate["address"]) > row.address:
                    insertion = index
                    break
            map_rows.insert(insertion, map_row)
            map_by_key[key] = map_row
            map_rows_added += 1
        else:
            map_row["name"] = row.suggestion
            if row.suggestion_comment is not None:
                map_row["comment"] = row.suggestion_comment
            map_rows_updated += 1

        raw_aliases = map_row.get("aliases", ())
        if not isinstance(raw_aliases, list):
            raw_aliases = []
        existing_aliases = [
            str(alias)
            for alias in raw_aliases
            if not is_analyzer_placeholder(str(alias))
        ]
        aliases_removed += len(raw_aliases) - len(existing_aliases)
        if (
            row.provider_symbol is not None
            and row.provider_member is not None
            and row.provider_symbol != row.suggestion
            and row.provider_symbol not in existing_aliases
        ):
            existing_aliases.append(row.provider_symbol)
        if existing_aliases:
            map_row["aliases"] = existing_aliases
        else:
            map_row.pop("aliases", None)

        row_replacements = replacements_by_image[row.image]
        for field_name in ("signature", "comment"):
            if added_map_row and field_name == "comment":
                continue
            value = map_row.get(field_name)
            if isinstance(value, str):
                if field_name == "comment" and value.startswith("Exact archive recovery from "):
                    continue
                replacement, count = _replace_identity_tokens(value, row_replacements)
                map_row[field_name] = replacement
                text_references_updated += count
        map_row.setdefault("create", False)

    scope_dispositions_updated = 0
    scope_payload: dict[str, Any] | None = None
    if matching_scope_path.exists():
        scope_payload = json.loads(matching_scope_path.read_text(encoding="utf-8"))
        selected_by_key = {
            (row.image, row.address): row
            for row in selected_by_source.values()
        }
        for scope_definition in scope_payload.get("scopes", {}).values():
            dispositions = scope_definition.get("function_dispositions", {})
            for image, image_rows in dispositions.items():
                for disposition in image_rows:
                    key = (str(image), parse_int(disposition["address"]))
                    selected_row = selected_by_key.get(key)
                    if selected_row is None:
                        continue
                    assert selected_row.suggestion is not None
                    old_name = str(disposition["name"])
                    if old_name == selected_row.suggestion:
                        continue
                    allowed_old_names = {
                        selected_row.function.casefold(),
                        selected_row.configured_function.casefold(),
                    }
                    if old_name.casefold() not in allowed_old_names:
                        raise ValueError(
                            f"unexpected matching-scope identity for {image}:"
                            f"0x{selected_row.address:08x}: {old_name!r}",
                        )
                    disposition["name"] = selected_row.suggestion
                    scope_dispositions_updated += 1

    for path, contents in config_updates.items():
        path.write_text(contents, encoding="utf-8")
    for path, contents in source_updates.items():
        path.write_text(contents, encoding="utf-8")
    name_map_path.write_text(json.dumps(map_rows, indent=2) + "\n", encoding="utf-8")
    if scope_payload is not None and scope_dispositions_updated:
        matching_scope_path.write_text(
            json.dumps(scope_payload, indent=2) + "\n",
            encoding="utf-8",
        )
    staged_renames: list[tuple[Path, Path]] = []
    for staging, (source, destination) in zip(staging_paths, directory_renames, strict=True):
        source.rename(staging)
        staged_renames.append((staging, destination))
    for staging, destination in staged_renames:
        staging.rename(destination)

    if repository_root is not None:
        text_references_updated += _rewrite_superseded_identity_references(
            replacements_by_image,
            repo_root=repository_root,
            match_root=match_root,
            excluded_paths=(name_map_path, matching_scope_path),
        )

    return {
        "applied": len(selected),
        "aliases_removed": aliases_removed,
        "config_references_updated": reference_updates,
        "directories_renamed": len(directory_renames),
        "map_rows_added": map_rows_added,
        "map_rows_updated": map_rows_updated,
        "scope_dispositions_updated": scope_dispositions_updated,
        "text_references_updated": text_references_updated,
        "renames": [
            {
                "from": source.relative_to(REPO_ROOT).as_posix()
                if source.is_relative_to(REPO_ROOT)
                else source.as_posix(),
                "to": destination.relative_to(REPO_ROOT).as_posix()
                if destination.is_relative_to(REPO_ROOT)
                else destination.as_posix(),
            }
            for source, destination in directory_renames
        ],
    }


def repair_provider_comments(
    statuses: Collection[ScratchStatus],
    *,
    name_map_path: Path = DEFAULT_NAME_MAP_PATH,
) -> dict[str, Any]:
    """Restore exact provider symbols in auto-generated naming-map comments."""

    providers_by_key: dict[tuple[str, int], set[tuple[str, str]]] = defaultdict(set)
    for status in statuses:
        if status.state != "match" or status.config.symbol is None:
            continue
        provider = status.config.archive_member or "provider object"
        providers_by_key[(status.config.image, status.address)].add(
            (provider, status.config.symbol),
        )

    map_rows = [dict(row) for row in load_name_map_rows(name_map_path)]
    repaired_rows: list[dict[str, str]] = []
    for map_row in map_rows:
        key = (str(map_row.get("program", "")), parse_int(map_row["address"]))
        providers = providers_by_key.get(key, set())
        if not providers:
            continue
        comment = str(map_row.get("comment", ""))
        replacements = {
            f"Exact archive recovery from {provider} symbol {symbol}."
            for provider, symbol in providers
        }
        if (
            len(replacements) != 1
            or re.fullmatch(r"Exact archive recovery from .+ symbol .+\.", comment) is None
        ):
            continue
        replacement = replacements.pop()
        if replacement == comment:
            continue
        map_row["comment"] = replacement
        repaired_rows.append(
            {
                "program": key[0],
                "address": f"0x{key[1]:08x}",
                "comment": replacement,
            },
        )

    if repaired_rows:
        name_map_path.write_text(json.dumps(map_rows, indent=2) + "\n", encoding="utf-8")
    return {
        "comments_repaired": len(repaired_rows),
        "rows": repaired_rows,
    }


def rewrite_placeholder_references(
    rows: Collection[NamingDebtRow],
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
) -> dict[str, Any]:
    """Replace unambiguous analyzer targets with canonical mapped identities."""

    replacements_by_image: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
    for row in rows:
        image_replacements = replacements_by_image[row.image]
        for _, old_target, canonical_target in row.reference_suggestions:
            key = old_target.casefold()
            existing = image_replacements.get(key)
            if existing is not None and existing[1] != canonical_target:
                raise ValueError(
                    f"ambiguous reference rename for {row.image} {old_target!r}: "
                    f"{existing[1]!r} vs {canonical_target!r}",
                )
            image_replacements[key] = (old_target, canonical_target)

    scratch_root = (match_root / "scratches").resolve()
    if not scratch_root.is_dir():
        raise ValueError(f"missing scratch root: {scratch_root}")

    configs_updated = 0
    references_updated = 0
    updated_files: list[str] = []
    for config_path in sorted(scratch_root.glob("*/scratch.conf")):
        config = load_scratch_config(config_path.parent)
        image_replacements = replacements_by_image.get(config.image, {})
        if not image_replacements or not config.reference_aliases:
            continue
        rewritten_aliases: list[tuple[str, str]] = []
        config_reference_updates = 0
        for object_symbol, target_symbol in config.reference_aliases:
            replacement = image_replacements.get(target_symbol.casefold())
            if replacement is None:
                rewritten_aliases.append((object_symbol, target_symbol))
                continue
            rewritten_aliases.append((object_symbol, replacement[1]))
            config_reference_updates += replacement[1] != target_symbol
        if not config_reference_updates:
            continue
        original = config_path.read_text(encoding="utf-8")
        encoded = ",".join(f"{source}:{target}" for source, target in rewritten_aliases)
        updated = _replace_config_assignment(original, "REFERENCE_ALIASES", encoded)
        config_path.write_text(updated, encoding="utf-8")
        configs_updated += 1
        references_updated += config_reference_updates
        try:
            updated_files.append(config_path.relative_to(REPO_ROOT).as_posix())
        except ValueError:
            updated_files.append(config_path.as_posix())

    return {
        "configs_updated": configs_updated,
        "references_updated": references_updated,
        "mappings": [
            {
                "image": image,
                "from": old_target,
                "to": canonical_target,
            }
            for image, replacements in sorted(replacements_by_image.items())
            for old_target, canonical_target in sorted(replacements.values())
        ],
        "updated_files": updated_files,
    }


def prune_placeholder_aliases(
    rows: Collection[NamingDebtRow],
    *,
    name_map_path: Path = DEFAULT_NAME_MAP_PATH,
    data_map_path: Path = DEFAULT_DATA_MAP_PATH,
) -> dict[str, Any]:
    """Remove audited analyzer aliases from curated maps, retaining linkage names."""

    aliases_by_kind = {
        map_kind: {
            (row.image, row.address, row.function): {
                alias.casefold() for alias in row.placeholder_aliases
            }
            for row in rows
            if row.map_kind == map_kind and row.placeholder_aliases
        }
        for map_kind in ("function", "data")
    }
    if not any(aliases_by_kind.values()):
        return {"aliases_removed": 0, "rows_pruned": 0}

    def prune_rows(
        map_rows: list[dict[str, Any]],
        *,
        map_kind: str,
        map_path: Path,
    ) -> tuple[int, int]:
        aliases_by_key = aliases_by_kind[map_kind]
        if not aliases_by_key:
            return (0, 0)
        aliases_removed = 0
        rows_pruned = 0
        found: set[tuple[str, int, str]] = set()
        for map_row in map_rows:
            key = (
                str(map_row.get("program", "")),
                parse_int(map_row["address"]),
                str(map_row.get("name", "")),
            )
            stale_aliases = aliases_by_key.get(key)
            if stale_aliases is None:
                continue
            found.add(key)
            aliases = map_row.get("aliases")
            if not isinstance(aliases, list):
                continue
            filtered = [alias for alias in aliases if str(alias).casefold() not in stale_aliases]
            removed = len(aliases) - len(filtered)
            if not removed:
                continue
            aliases_removed += removed
            rows_pruned += 1
            if filtered:
                map_row["aliases"] = filtered
            else:
                map_row.pop("aliases", None)
        missing = sorted(set(aliases_by_key) - found)
        if missing:
            rendered = ", ".join(
                f"{image}:0x{address:08x}:{name}" for image, address, name in missing
            )
            raise ValueError(
                f"audited placeholder aliases disappeared from {map_path}: {rendered}",
            )
        return (aliases_removed, rows_pruned)

    function_rows = [dict(row) for row in load_name_map_rows(name_map_path)]
    function_removed, function_pruned = prune_rows(
        function_rows,
        map_kind="function",
        map_path=name_map_path,
    )
    if function_pruned:
        name_map_path.write_text(json.dumps(function_rows, indent=2) + "\n", encoding="utf-8")

    data_payload: dict[str, Any] | None = None
    data_removed = 0
    data_pruned = 0
    if aliases_by_kind["data"]:
        raw_payload = json.loads(data_map_path.read_text(encoding="utf-8"))
        if not isinstance(raw_payload, dict) or not isinstance(raw_payload.get("entries"), list):
            raise TypeError(f"{data_map_path}: data map must contain an entries array")
        data_payload = cast(dict[str, Any], raw_payload)
        data_rows = [dict(row) for row in data_payload["entries"]]
        data_removed, data_pruned = prune_rows(
            data_rows,
            map_kind="data",
            map_path=data_map_path,
        )
        if data_pruned:
            data_payload["entries"] = data_rows
            data_map_path.write_text(
                json.dumps(data_payload, indent=2) + "\n",
                encoding="utf-8",
            )

    return {
        "aliases_removed": function_removed + data_removed,
        "rows_pruned": function_pruned + data_pruned,
    }


def naming_debt_payload(row: NamingDebtRow) -> dict[str, Any]:
    return {
        "map_kind": row.map_kind,
        "image": row.image,
        "address": row.address,
        "function": row.function,
        "configured_function": row.configured_function,
        "scratch": row.scratch,
        "issues": list(row.issues),
        "placeholder_aliases": list(row.placeholder_aliases),
        "placeholder_comment_tokens": list(row.placeholder_comment_tokens),
        "placeholder_references": list(row.placeholder_references),
        "reference_suggestions": [
            {
                "object_symbol": object_symbol,
                "from": old_target,
                "to": canonical_target,
            }
            for object_symbol, old_target, canonical_target in row.reference_suggestions
        ],
        "provider_symbol": row.provider_symbol,
        "provider_member": row.provider_member,
        "suggestion": row.suggestion,
        "suggestion_sources": list(row.suggestion_sources),
        "suggestion_comment": row.suggestion_comment,
    }


def resolved_name_reference_payload(row: ResolvedNameReferenceRow) -> dict[str, Any]:
    return {
        "path": row.path,
        "line": row.line,
        "source": row.source,
        "token": row.token,
        "image": row.image,
        "address": row.address,
        "canonical_names": list(row.canonical_names),
    }


def resolved_name_reference_summary_payload(
    rows: Collection[ResolvedNameReferenceRow],
) -> dict[str, Any]:
    sources = Counter(row.source for row in rows)
    return {
        "row_count": len(rows),
        "sources": {source: sources[source] for source in sorted(sources)},
    }


def render_resolved_name_reference_summary(
    rows: Collection[ResolvedNameReferenceRow],
) -> str:
    summary = resolved_name_reference_summary_payload(rows)
    return f"rows={summary['row_count']}; sources=" + ",".join(
        f"{source}:{count}" for source, count in summary["sources"].items()
    )


def render_resolved_name_reference_table(
    rows: Collection[ResolvedNameReferenceRow],
) -> str:
    header = ("path", "line", "source", "token", "canonical")
    rendered = [
        header,
        *(
            (
                row.path,
                str(row.line),
                row.source,
                row.token,
                "|".join(row.canonical_names),
            )
            for row in rows
        ),
    ]
    widths = [max(len(row[column]) for row in rendered) for column in range(len(header))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rendered]
    lines.append(f"\n{render_resolved_name_reference_summary(rows)}")
    return "\n".join(lines)


def naming_debt_summary_payload(rows: Collection[NamingDebtRow]) -> dict[str, Any]:
    issue_counts = Counter(issue for row in rows for issue in row.issues)
    return {
        "row_count": len(rows),
        "suggested_count": sum(row.suggestion is not None for row in rows),
        "issues": {issue: issue_counts[issue] for issue in sorted(issue_counts)},
    }


def render_naming_debt_summary(rows: Collection[NamingDebtRow]) -> str:
    summary = naming_debt_summary_payload(rows)
    return (
        f"rows={summary['row_count']}; suggested={summary['suggested_count']}; issues="
        + ",".join(f"{issue}:{count}" for issue, count in summary["issues"].items())
    )


def render_naming_debt_table(rows: Collection[NamingDebtRow]) -> str:
    header = ("image", "address", "function", "suggestion", "issues", "symbol", "scratch")
    rendered = [
        header,
        *(
            (
                row.image,
                f"0x{row.address:08x}",
                row.function,
                row.suggestion or "-",
                ",".join(row.issues),
                row.provider_symbol or "-",
                row.scratch,
            )
            for row in rows
        ),
    ]
    widths = [max(len(row[column]) for row in rendered) for column in range(len(header))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rendered]
    lines.append(f"\n{render_naming_debt_summary(rows)}")
    return "\n".join(lines)


STATUS_HEADER = (
    "state",
    "image",
    "function",
    "address",
    "bytes",
    "fuzzy",
    "gap",
    "insns",
    "match",
    "prefix",
    "refs",
    "build",
    "note",
)
IMAGE_TOTALS_HEADER = (
    "image",
    "exact functions",
    "exact bytes",
    "exact code",
    "fuzzy-weighted bytes",
    "fuzzy code",
    "candidate functions",
    "candidate bytes",
    "candidate code",
    "scratches",
)
TRIAGE_HEADER = (
    "state",
    "image",
    "function",
    "address",
    "bytes",
    "exact",
    "fuzzy",
    "candidate",
    "gap",
    "match",
    "prefix",
    "refs",
    "scratch",
    "search",
    "streak",
    "flags",
    "note",
)
PROFILE_HEADER = (
    "rank",
    "state",
    "compiler",
    "cflags",
    "fuzzy",
    "gap",
    "match",
    "insns",
    "prefix",
    "refs",
    "error",
)


def collect_image_totals(
    statuses: list[ScratchStatus],
    *,
    scope: str | None = None,
) -> list[ImageTotals]:
    totals: list[ImageTotals] = []
    images = sorted(matching_scope_images(scope))
    for image_name in images:
        image_path, functions_path, metadata_path = _paths_for_image(image_name)
        manifest = load_function_manifest(
            functions_path,
            metadata_path=metadata_path,
            image_name=image_name,
            scope=scope,
        )
        image = load_image(image_path, manifest.image_base)
        function_sizes = {
            function.address: len(image.function_bytes(function.address, function.end))
            for function in manifest.functions
        }
        byte_total = sum(function_sizes.values())
        image_statuses = [status for status in statuses if status.config.image == image_name]
        matched_by_function: dict[int, int] = {}
        fuzzy_bytes_by_function: dict[int, float] = {}
        candidate_by_function: dict[int, int] = {}
        for status in image_statuses:
            manifest_size = function_sizes.get(status.address)
            if manifest_size is None:
                continue
            covered_size = min(status.target_size, manifest_size)
            if status.ratio is not None:
                fuzzy_bytes_by_function[status.address] = max(
                    fuzzy_bytes_by_function.get(status.address, 0.0),
                    covered_size * status.ratio,
                )
                candidate_by_function[status.address] = max(
                    candidate_by_function.get(status.address, 0),
                    covered_size,
                )
            if status.state == "match":
                matched_by_function[status.address] = max(
                    matched_by_function.get(status.address, 0),
                    covered_size,
                )
        totals.append(
            ImageTotals(
                image=image_name,
                function_count=len(manifest.functions),
                byte_total=byte_total,
                matched_functions=len(matched_by_function),
                matched_bytes=sum(matched_by_function.values()),
                fuzzy_weighted_bytes=sum(fuzzy_bytes_by_function.values()),
                candidate_functions=len(candidate_by_function),
                candidate_bytes=sum(candidate_by_function.values()),
                scratch_count=len(image_statuses),
                matched_scratches=sum(1 for status in image_statuses if status.state == "match"),
            ),
        )
    return totals


def status_rank(status: ScratchStatus) -> tuple[int, float, int, int, int]:
    state_rank = {"error": 0, "wip": 1, "audit": 2, "match": 3}[status.state]
    return (
        state_rank,
        status.ratio if status.ratio is not None else -1.0,
        -(status.masked_unresolved + status.masked_mismatches),
        status.prefix_instructions,
        -abs(status.candidate_instructions - status.target_instructions),
    )


def status_improves_claim_baseline(
    status: ScratchStatus,
    baseline: dict[str, Any] | None,
) -> bool:
    if not isinstance(baseline, dict):
        return False
    try:
        references = baseline["references"]
        mismatch = baseline["first_mismatch"]
        previous = ScratchStatus(
            config=status.config,
            address=int(baseline["address"]),
            target_size=int(baseline["target_bytes"]),
            ratio=baseline["match_ratio"],
            prefix_instructions=int(baseline["prefix_instructions"]),
            target_instructions=int(baseline["target_instructions"]),
            candidate_instructions=int(baseline["candidate_instructions"]),
            error=baseline["error"],
            masked_ok=int(references["ok"]),
            masked_unresolved=int(references["unresolved"]),
            masked_mismatches=int(references["mismatch"]),
            first_target_mismatch_offset=mismatch["target_offset"],
            first_candidate_mismatch_offset=mismatch["candidate_offset"],
        )
    except (KeyError, TypeError, ValueError):
        return False
    return status_improves(previous, status)


def status_improves(baseline: ScratchStatus, candidate: ScratchStatus) -> bool:
    return (
        candidate.state != "error"
        and candidate.address == baseline.address
        and candidate.target_size == baseline.target_size
        and not fuzzy_score_tradeoffs(baseline, candidate)
        and status_rank(candidate) > status_rank(baseline)
    )


def collect_triage_rows(
    statuses: list[ScratchStatus],
    *,
    images: tuple[str, ...] | None = None,
    scope: str | None = None,
) -> list[TriageRow]:
    """Join scratch coverage to native functions by image and address."""

    selected_images = images or tuple(sorted(matching_scope_images(scope)))
    statuses_by_address: dict[tuple[str, int], list[ScratchStatus]] = {}
    for status in statuses:
        if status.address:
            statuses_by_address.setdefault((status.config.image, status.address), []).append(status)

    rows: list[TriageRow] = []
    for image_name in selected_images:
        image_path, functions_path, metadata_path = _paths_for_image(image_name)
        manifest = load_function_manifest(
            functions_path,
            metadata_path=metadata_path,
            image_name=image_name,
            scope=scope,
        )
        image = load_image(image_path, manifest.image_base)
        for function in manifest.functions:
            target_size = len(image.function_bytes(function.address, function.end))
            function_statuses = statuses_by_address.get((image_name, function.address), [])
            usable = [status for status in function_statuses if status.ratio is not None]
            best_status = max(function_statuses, key=status_rank) if function_statuses else None
            exact_bytes = max(
                (
                    min(status.target_size, target_size)
                    for status in function_statuses
                    if status.state == "match"
                ),
                default=0,
            )
            fuzzy_weighted_bytes = max(
                (
                    min(status.target_size, target_size)
                    * (status.ratio if status.ratio is not None else 0.0)
                    for status in usable
                ),
                default=0.0,
            )
            candidate_bytes = max((status.target_size for status in usable), default=0)
            candidate_bytes = min(candidate_bytes, target_size)
            states = {status.state for status in function_statuses}
            if "match" in states:
                state = "match"
            elif "audit" in states:
                state = "audit"
            elif usable:
                state = "wip"
            elif function_statuses:
                state = "error"
            else:
                state = "missing"
            experiments = triage_experiment_evidence(best_status)
            rows.append(
                TriageRow(
                    image=image_name,
                    function=function.name,
                    address=function.address,
                    target_size=target_size,
                    state=state,
                    exact_bytes=exact_bytes,
                    fuzzy_weighted_bytes=fuzzy_weighted_bytes,
                    candidate_bytes=candidate_bytes,
                    scratch_count=len(function_statuses),
                    best_status=best_status,
                    experiments=experiments,
                ),
            )
    return rows


def triage_experiment_evidence(status: ScratchStatus | None) -> TriageExperimentEvidence:
    if status is None:
        return TriageExperimentEvidence()
    path = status.config.directory / match_experiments.EXPERIMENT_FILE
    if not path.is_file():
        return TriageExperimentEvidence()
    row, errors = match_experiments.summarize_experiment_log(
        path,
        match_root=status.config.directory.parent.parent,
        current_epoch=scratch_experiment_epoch(
            status.config,
            status.config.directory.parent.parent,
        ),
        classify_epochs=True,
    )
    return TriageExperimentEvidence(
        records=int(row["records"]),
        current_records=int(row["current_records"]),
        historical_records=int(row["historical_records"]),
        unversioned_records=int(row["unversioned_records"]),
        mutation_sweeps=int(row["mutation_sweeps"]),
        probes=int(row["probes"]),
        evaluated_variants=int(row["evaluated_variants"]),
        unique_variants=int(row["unique_variants"]),
        unique_specs=int(row["unique_specs"]),
        no_improvement_streak=int(row["no_improvement_streak"]),
        current_inconclusive_sweeps=int(row["current_inconclusive_sweeps"]),
        current_errored_variants=int(row["current_errored_variants"]),
        audited_errored_variants=int(row["audited_errored_variants"]),
        mutation_error_audits=int(row["mutation_error_audits"]),
        strict_errors=int(row["strict_errors"]),
        flags=tuple(str(flag) for flag in row["flags"]),
        errors=len(errors),
    )


def _safe_scratch_name(function: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]+", "_", function).strip("_")
    return name or "target"


def _file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _jsonl_record_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(bool(line.strip()) for line in path.read_text(encoding="utf-8").splitlines())


def scratch_claim_baseline(status: ScratchStatus) -> dict[str, Any]:
    source_path = status.config.directory / status.config.source
    experiments_path = status.config.directory / "experiments.jsonl"
    payload = scratch_status_payload(status)
    payload["scratch"] = status.config.directory.name
    payload["source_sha256"] = _file_sha256(source_path)
    payload["experiments_sha256"] = _file_sha256(experiments_path)
    payload["experiment_records"] = _jsonl_record_count(experiments_path)
    return payload


def build_match_shard_plan(
    rows: Collection[TriageRow],
    *,
    workers: int,
    scope: str,
    base_commit: str,
    match_root: Path = DEFAULT_MATCH_ROOT,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministically balance independent targets by fuzzy-gap bytes."""
    if workers < 1:
        raise ValueError("workers must be positive")
    match_root = match_root.resolve()
    ranked = sorted(
        rows,
        key=lambda row: (
            -row.fuzzy_gap_bytes,
            -row.target_size,
            row.image,
            row.address,
            row.function,
        ),
    )
    width = max(2, len(str(workers)))
    assignments: list[dict[str, Any]] = [
        {
            "worker": f"worker-{index + 1:0{width}d}",
            "claim": f"worker-{index + 1:0{width}d}.json",
            "estimated_gap_bytes": 0.0,
            "targets": [],
        }
        for index in range(workers)
    ]
    used_scratches = {
        str(row.best_status.config.directory.resolve().relative_to(match_root))
        for row in ranked
        if row.best_status is not None
    }
    for row in ranked:
        assignment = min(
            enumerate(assignments),
            key=lambda item: (
                item[1]["estimated_gap_bytes"],
                len(item[1]["targets"]),
                item[0],
            ),
        )[1]
        if row.best_status is not None:
            scratch = str(row.best_status.config.directory.resolve().relative_to(match_root))
        else:
            scratch = f"scratches/{_safe_scratch_name(row.function)}"
            if scratch in used_scratches:
                scratch = f"{scratch}_{row.address:08x}"
            used_scratches.add(scratch)
        target = {
            "image": row.image,
            "function": row.function,
            "address": row.address,
            "target_bytes": row.target_size,
            "state": row.state,
            "fuzzy_gap_bytes": row.fuzzy_gap_bytes,
            "scratch": scratch,
        }
        if row.best_status is not None:
            target["baseline"] = scratch_claim_baseline(row.best_status)
        assignment["targets"].append(target)
        assignment["estimated_gap_bytes"] += row.fuzzy_gap_bytes
    plan = {
        "schema": SHARD_SCHEMA,
        "kind": SHARD_PLAN_KIND,
        "scope": scope,
        "base_commit": base_commit,
        "workers": workers,
        "target_count": len(ranked),
        "filters": filters or {},
        "assignments": assignments,
    }
    plan["batch_id"] = hashlib.sha256(
        json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
    ).hexdigest()[:16]
    return plan


def write_match_json(path: Path, payload: dict[str, Any]) -> None:
    _write_text_atomic(
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def write_match_shard_plan(
    plan: dict[str, Any],
    output_directory: Path,
) -> tuple[Path, list[Path]]:
    output_directory.mkdir(parents=True, exist_ok=True)
    plan_path = output_directory / "plan.json"
    claim_paths: list[Path] = []
    expected_claim_names = {
        str(assignment["claim"])
        for assignment in plan["assignments"]
    }
    for stale_claim in output_directory.glob("worker-*.json"):
        if stale_claim.is_file() and stale_claim.name not in expected_claim_names:
            stale_claim.unlink()
    for assignment in plan["assignments"]:
        claim_path = output_directory / str(assignment["claim"])
        write_match_json(
            claim_path,
            {
                "schema": SHARD_SCHEMA,
                "kind": WORKER_CLAIM_KIND,
                "batch_id": plan.get("batch_id"),
                "scope": plan["scope"],
                "base_commit": plan["base_commit"],
                "worker": assignment["worker"],
                "targets": assignment["targets"],
            },
        )
        claim_paths.append(claim_path)
    write_match_json(plan_path, plan)
    return plan_path, claim_paths


def load_match_claim(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{path}: expected an object")
    return payload


def match_claim_targets(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    kind = payload.get("kind")
    if kind == WORKER_CLAIM_KIND:
        worker = str(payload.get("worker", ""))
        targets = payload.get("targets", [])
        if not isinstance(targets, list):
            raise TypeError("worker claim targets must be a list")
        if any(not isinstance(target, dict) for target in targets):
            raise TypeError(f"{worker or '<unnamed>'} targets must contain objects")
        return [(worker, target) for target in targets]
    if kind == SHARD_PLAN_KIND:
        assignments = payload.get("assignments", [])
        if not isinstance(assignments, list):
            raise TypeError("shard plan assignments must be a list")
        targets: list[tuple[str, dict[str, Any]]] = []
        for assignment in assignments:
            if not isinstance(assignment, dict):
                raise TypeError("shard plan assignments must contain objects")
            worker = str(assignment.get("worker", ""))
            worker_targets = assignment.get("targets", [])
            if not isinstance(worker_targets, list):
                raise TypeError(f"{worker or '<unnamed>'} targets must be a list")
            if any(not isinstance(target, dict) for target in worker_targets):
                raise TypeError(f"{worker or '<unnamed>'} targets must contain objects")
            targets.extend((worker, target) for target in worker_targets)
        return targets
    raise ValueError(f"unsupported claim kind {kind!r}")


def validate_match_claim(
    payload: dict[str, Any],
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
    scope: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != SHARD_SCHEMA:
        errors.append(f"unsupported claim schema {payload.get('schema')!r}")
    batch_id = payload.get("batch_id")
    if batch_id is not None and (
        not isinstance(batch_id, str)
        or re.fullmatch(r"[0-9a-f]{16}", batch_id) is None
    ):
        errors.append("claim batch_id must be 16 lowercase hexadecimal characters")
    claim_scope = str(payload.get("scope", ""))
    if scope is not None and claim_scope != scope:
        errors.append(f"claim scope {claim_scope!r} does not match checkpoint scope {scope!r}")
    base_commit = payload.get("base_commit")
    if not isinstance(base_commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", base_commit) is None:
        errors.append("claim requires a full lowercase hexadecimal base_commit")
    if payload.get("kind") == SHARD_PLAN_KIND:
        assignments = payload.get("assignments", [])
        if isinstance(assignments, list):
            if payload.get("workers") != len(assignments):
                errors.append("plan worker count does not match assignments")
            worker_ids = [
                str(assignment.get("worker", ""))
                for assignment in assignments
                if isinstance(assignment, dict)
            ]
            if (
                len(worker_ids) != len(assignments)
                or any(not worker for worker in worker_ids)
                or len(set(worker_ids)) != len(worker_ids)
            ):
                errors.append("plan worker identifiers must be unique and non-empty")
    elif payload.get("kind") == WORKER_CLAIM_KIND and not str(payload.get("worker", "")):
        errors.append("worker claim requires a non-empty worker identifier")
    try:
        claimed = match_claim_targets(payload)
    except (TypeError, ValueError) as exc:
        return [*errors, str(exc)]
    if payload.get("kind") == SHARD_PLAN_KIND and payload.get("target_count") != len(claimed):
        errors.append("plan target count does not match assignments")

    target_owners: dict[tuple[str, int], str] = {}
    scratch_owners: dict[str, str] = {}
    manifests: dict[str, FunctionManifest] = {}
    match_root = match_root.resolve()
    for worker, target in claimed:
        try:
            image = str(target["image"])
            function = str(target["function"])
            address = int(target["address"])
            scratch = str(target["scratch"])
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"{worker or '<unnamed>'}: malformed target: {exc}")
            continue
        if not worker:
            errors.append(f"{image}:0x{address:08x}: empty worker identifier")
        scratch_parts = Path(scratch).parts
        if (
            Path(scratch).is_absolute()
            or len(scratch_parts) != 2
            or scratch_parts[0] != "scratches"
            or scratch_parts[1] in {".", ".."}
        ):
            errors.append(
                f"{worker or '<unnamed>'}: invalid scratch claim {scratch!r}; "
                "expected scratches/<directory>",
            )
            continue
        key = (image, address)
        if owner := target_owners.get(key):
            errors.append(
                f"duplicate claim {image}:0x{address:08x}: {owner}, {worker}",
            )
        else:
            target_owners[key] = worker
        if owner := scratch_owners.get(scratch):
            errors.append(f"duplicate scratch claim {scratch}: {owner}, {worker}")
        else:
            scratch_owners[scratch] = worker
        try:
            if image not in manifests:
                _, functions_path, metadata_path = _paths_for_image(image)
                manifests[image] = load_function_manifest(
                    functions_path,
                    metadata_path=metadata_path,
                    image_name=image,
                    scope=claim_scope,
                )
            symbol, _, _ = resolve_function(manifests[image], f"0x{address:08x}")
            if symbol.name != function:
                errors.append(
                    f"{worker}: target drift at {image}:0x{address:08x}: "
                    f"{function!r} != {symbol.name!r}",
                )
            scratch_directory = match_root / scratch
            config_path = scratch_directory / "scratch.conf"
            if (
                scratch_directory.is_dir()
                and not config_path.exists()
                and _scratch_has_unconfigured_files(scratch_directory)
            ):
                errors.append(f"{worker}: {scratch} contains files but no scratch.conf")
            elif config_path.exists():
                config = load_scratch_config(scratch_directory)
                if config.image != image:
                    errors.append(
                        f"{worker}: {scratch} resolves to "
                        f"{config.image}, expected {image}:0x{address:08x}",
                    )
                else:
                    resolved, _, _ = resolve_function(
                        manifests[config.image],
                        config.function,
                        end_override=config.end_va,
                    )
                    if resolved.address != address:
                        errors.append(
                            f"{worker}: {scratch} resolves to "
                            f"{config.image}:0x{resolved.address:08x}, expected "
                            f"{image}:0x{address:08x}",
                        )
        except Exception as exc:  # noqa: BLE001 - collect every invalid worker claim in one pass
            errors.append(f"{worker}: {image}:0x{address:08x}: {_exception_summary(exc)}")
    return errors


def claimed_scratch_paths(payload: dict[str, Any]) -> set[str]:
    return {
        str(target["scratch"])
        for _worker, target in match_claim_targets(payload)
        if target.get("scratch")
    }


def validate_claimed_changes(
    payload: dict[str, Any],
    changed_paths: Collection[str],
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
    allowed_paths: Collection[str] = (),
) -> list[str]:
    expected = claimed_scratch_paths(payload)
    try:
        prefix = match_root.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        prefix = None
    allowed = {Path(path).as_posix().removeprefix("./") for path in allowed_paths}
    changed_scratches: set[str] = set()
    outside_paths: set[str] = set()
    for raw_path in changed_paths:
        normalized = Path(raw_path).as_posix().removeprefix("./")
        if normalized in allowed:
            continue
        if prefix is not None:
            match_prefix = f"{prefix}/"
            if not normalized.startswith(match_prefix):
                outside_paths.add(normalized)
                continue
            path = normalized.removeprefix(match_prefix)
        else:
            path = normalized
        parts = Path(path).parts
        if len(parts) >= 2 and parts[0] == "scratches":
            changed_scratches.add(f"scratches/{parts[1]}")
        else:
            outside_paths.add(normalized)
    return [
        f"scratch change outside claims: {scratch}"
        for scratch in sorted(changed_scratches - expected)
    ] + [
        f"change outside claims: {path}"
        for path in sorted(outside_paths)
    ]


def sort_scratch_statuses(statuses: list[ScratchStatus], *, sort_by: str = "address") -> list[ScratchStatus]:
    if sort_by not in {"address", "fuzzy-gap", "size", "match"}:
        raise ValueError(f"unknown status sort {sort_by!r}")

    def key(status: ScratchStatus) -> tuple[Any, ...]:
        if sort_by == "address":
            return (status.config.image, status.address, status.config.function)
        if sort_by == "fuzzy-gap":
            return (
                status.fuzzy_gap_bytes,
                status.target_size,
                status.ratio if status.ratio is not None else -1.0,
            )
        if sort_by == "size":
            return (status.target_size, status.fuzzy_gap_bytes)
        return (
            status.ratio if status.ratio is not None else -1.0,
            -status.fuzzy_gap_bytes,
        )

    return sorted(statuses, key=key, reverse=sort_by != "address")


def sort_triage_rows(rows: list[TriageRow], *, sort_by: str = "address") -> list[TriageRow]:
    if sort_by not in {"address", "fuzzy-gap", "size", "fuzzy", "unexplored"}:
        raise ValueError(f"unknown triage sort {sort_by!r}")

    def key(row: TriageRow) -> tuple[Any, ...]:
        if sort_by == "address":
            return (row.image, row.address, row.function)
        if sort_by == "fuzzy-gap":
            return (row.fuzzy_gap_bytes, row.target_size, -row.fuzzy_weighted_bytes)
        if sort_by == "size":
            return (row.target_size, row.fuzzy_gap_bytes)
        if sort_by == "unexplored":
            return (
                row.experiments.unique_variants,
                row.experiments.records,
                -row.fuzzy_gap_bytes,
                -row.target_size,
                row.image,
                row.address,
            )
        return (row.fuzzy_weighted_bytes, row.target_size)

    return sorted(rows, key=key, reverse=sort_by not in {"address", "unexplored"})


def scratch_status_payload(status: ScratchStatus) -> dict[str, Any]:
    return {
        "state": status.state,
        "image": status.config.image,
        "function": status.config.function,
        "address": status.address,
        "body_byte_exact": status.body_byte_exact,
        "padding_bytes": {"target": status.target_padding_bytes, "candidate": status.candidate_padding_bytes},
        "target_bytes": status.target_size,
        "fuzzy_weighted_bytes": status.fuzzy_weighted_bytes,
        "fuzzy_gap_bytes": status.fuzzy_gap_bytes,
        "target_instructions": status.target_instructions,
        "candidate_instructions": status.candidate_instructions,
        "match_ratio": status.ratio,
        "prefix_instructions": status.prefix_instructions,
        "first_mismatch": {
            "target_offset": status.first_target_mismatch_offset,
            "candidate_offset": status.first_candidate_mismatch_offset,
        },
        "references": {
            "ok": status.masked_ok,
            "unresolved": status.masked_unresolved,
            "mismatch": status.masked_mismatches,
        },
        "compiler": status.config.compiler,
        "cflags": status.config.cflags,
        "archive": status.config.archive,
        "archive_member": status.config.archive_member,
        "archive_sha256": status.config.archive_sha256,
        "import_thunk": status.config.import_thunk,
        "scratch": str(status.config.directory),
        "recovery": scratch_recovery(status),
        "residuals": list(status.config.residuals),
        "note": status.config.note,
        "error": status.error,
    }


def fuzzy_score_tradeoffs(
    baseline: ScratchStatus,
    candidate: ScratchStatus,
) -> tuple[str, ...]:
    # A byte-neutral result can still be worse: relocation masking may hide a
    # changed reference target from the headline fuzzy score.
    if candidate.fuzzy_weighted_bytes < baseline.fuzzy_weighted_bytes:
        return ()

    warnings: list[str] = []
    baseline_debt = baseline.masked_unresolved + baseline.masked_mismatches
    candidate_debt = candidate.masked_unresolved + candidate.masked_mismatches
    if candidate_debt > baseline_debt:
        warnings.append("reference-debt-increased")
    if candidate.masked_ok < baseline.masked_ok:
        warnings.append("resolved-references-decreased")
    if candidate.prefix_instructions < baseline.prefix_instructions:
        warnings.append("prefix-regressed")
    if (
        baseline.first_target_mismatch_offset is not None
        and candidate.first_target_mismatch_offset is not None
        and candidate.first_target_mismatch_offset < baseline.first_target_mismatch_offset
    ):
        warnings.append("first-mismatch-earlier")
    baseline_instruction_gap = abs(
        baseline.candidate_instructions - baseline.target_instructions,
    )
    candidate_instruction_gap = abs(
        candidate.candidate_instructions - candidate.target_instructions,
    )
    if candidate_instruction_gap > baseline_instruction_gap:
        warnings.append("instruction-count-further-from-target")
    return tuple(warnings)


def parse_worker_hypothesis(value: str) -> dict[str, str]:
    kind, separator, description = value.partition(":")
    kind = kind.strip()
    description = description.strip()
    if not separator or kind not in WORKER_HYPOTHESIS_KINDS or not description:
        allowed = ", ".join(sorted(WORKER_HYPOTHESIS_KINDS))
        raise ValueError(
            f"invalid hypothesis {value!r}; use <kind>:<description> where kind is {allowed}",
        )
    return {"kind": kind, "description": description}


def load_worker_outcomes(directory: Path) -> tuple[list[dict[str, Any]], list[str]]:
    path = directory / WORKER_OUTCOME_FILE
    if not path.is_file():
        return [], []
    outcomes: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:{line_number}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{path}:{line_number}: outcome must be an object")
            continue
        outcome_errors = validate_worker_outcome(payload)
        if outcome_errors:
            errors.extend(f"{path}:{line_number}: {error}" for error in outcome_errors)
            continue
        outcomes.append(payload)
    return outcomes, errors


def validate_worker_outcome(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != SHARD_SCHEMA:
        errors.append(f"unsupported outcome schema {payload.get('schema')!r}")
    if payload.get("kind") != WORKER_OUTCOME_KIND:
        errors.append(f"unsupported outcome kind {payload.get('kind')!r}")
    batch_id = payload.get("batch_id")
    if not isinstance(batch_id, str) or re.fullmatch(r"[0-9a-f]{16}", batch_id) is None:
        errors.append("outcome requires a 16-character lowercase hexadecimal batch_id")
    worker = payload.get("worker")
    if not isinstance(worker, str) or not worker:
        errors.append("outcome requires a worker")
    scratch = payload.get("scratch")
    scratch_parts = Path(scratch).parts if isinstance(scratch, str) else ()
    if (
        not isinstance(scratch, str)
        or Path(scratch).is_absolute()
        or len(scratch_parts) != 2
        or scratch_parts[0] != "scratches"
        or scratch_parts[1] in {".", ".."}
    ):
        errors.append("outcome scratch must be scratches/<directory>")
    disposition = payload.get("disposition")
    if disposition not in WORKER_OUTCOME_DISPOSITIONS:
        allowed = ", ".join(sorted(WORKER_OUTCOME_DISPOSITIONS))
        errors.append(f"outcome disposition must be one of {allowed}")
    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        errors.append("outcome requires a non-empty summary")
    hypotheses = payload.get("hypotheses")
    if not isinstance(hypotheses, list):
        errors.append("outcome hypotheses must be an array")
    else:
        for index, hypothesis in enumerate(hypotheses):
            if not isinstance(hypothesis, dict):
                errors.append(f"outcome hypotheses[{index}] must be an object")
                continue
            if hypothesis.get("kind") not in WORKER_HYPOTHESIS_KINDS:
                errors.append(f"outcome hypotheses[{index}] has an invalid kind")
            description = hypothesis.get("description")
            if not isinstance(description, str) or not description.strip():
                errors.append(f"outcome hypotheses[{index}] requires a description")
    evidence = payload.get("evidence")
    if (
        not isinstance(evidence, list)
        or any(not isinstance(item, str) or not item.strip() for item in evidence)
    ):
        errors.append("outcome evidence must be an array of non-empty strings")
    if disposition == "falsified" and not hypotheses:
        errors.append("falsified outcomes require at least one hypothesis")
    if disposition in {"falsified", "blocked"} and not evidence:
        errors.append(f"{disposition} outcomes require at least one evidence item")
    status = payload.get("status")
    if not isinstance(status, dict):
        errors.append("outcome requires a status object")
    elif disposition == "matched" and status.get("state") != "match":
        errors.append("matched outcome requires status.state=match")
    return errors


def worker_outcomes_for_target(
    claim: dict[str, Any],
    target: dict[str, Any],
    *,
    match_root: Path = DEFAULT_MATCH_ROOT,
) -> tuple[list[dict[str, Any]], list[str]]:
    scratch = str(target["scratch"])
    outcomes, errors = load_worker_outcomes(match_root / scratch)
    batch_id = claim.get("batch_id")
    worker = claim.get("worker")
    matching = [
        outcome
        for outcome in outcomes
        if outcome["batch_id"] == batch_id
        and outcome["worker"] == worker
        and outcome["scratch"] == scratch
    ]
    return matching, errors


def write_worker_outcome(directory: Path, payload: dict[str, Any]) -> Path:
    errors = validate_worker_outcome(payload)
    if errors:
        raise ValueError("; ".join(errors))
    path = directory / WORKER_OUTCOME_FILE
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    return path


def probe_result_payload(result: ProbeResult) -> dict[str, Any]:
    baseline = scratch_status_payload(result.baseline)
    probe = scratch_status_payload(result.probe)
    probe["scratch"] = "<shadow>"
    return {
        "label": result.label,
        "source_sha256": result.source_sha256,
        "source_tree_sha256": result.source_tree_sha256 or result.source_sha256,
        "source_dependencies": list(result.source_dependencies),
        "tradeoffs": list(fuzzy_score_tradeoffs(result.baseline, result.probe)),
        "baseline": baseline,
        "probe": probe,
        "delta": {
            "match_ratio": result.ratio_delta,
            "fuzzy_weighted_bytes": result.fuzzy_delta_bytes,
            "candidate_instructions": result.probe.candidate_instructions
            - result.baseline.candidate_instructions,
            "prefix_instructions": result.probe.prefix_instructions
            - result.baseline.prefix_instructions,
            "references": {
                "ok": result.probe.masked_ok - result.baseline.masked_ok,
                "unresolved": result.probe.masked_unresolved - result.baseline.masked_unresolved,
                "mismatch": result.probe.masked_mismatches - result.baseline.masked_mismatches,
            },
        },
    }


def render_probe_result(result: ProbeResult) -> str:
    def status_line(label: str, status: ScratchStatus) -> str:
        if status.ratio is None:
            return f"{label}: state=error error={status.error}"
        return (
            f"{label}: state={status.state} match={status.ratio:.2%} "
            f"fuzzy={status.fuzzy_weighted_bytes:.0f}/{status.target_size} "
            f"insns={status.candidate_instructions}/{status.target_instructions} "
            f"prefix={status.prefix_instructions}/{status.target_instructions} "
            f"refs={status.masked_ok}/{status.masked_unresolved}/{status.masked_mismatches}"
        )

    ratio_delta = f"{result.ratio_delta:+.2%}" if result.ratio_delta is not None else "-"
    tradeoffs = fuzzy_score_tradeoffs(result.baseline, result.probe)
    lines = [
        status_line("baseline", result.baseline),
        status_line("probe", result.probe),
        (f"delta: match={ratio_delta} fuzzy={result.fuzzy_delta_bytes:+.0f} "
            f"insns={result.probe.candidate_instructions - result.baseline.candidate_instructions:+d} "
            f"prefix={result.probe.prefix_instructions - result.baseline.prefix_instructions:+d} "
            f"refs={result.probe.masked_ok - result.baseline.masked_ok:+d}/"
            f"{result.probe.masked_unresolved - result.baseline.masked_unresolved:+d}/"
            f"{result.probe.masked_mismatches - result.baseline.masked_mismatches:+d}"),
        f"source_sha256={result.source_sha256}",
        f"source_tree_sha256={result.source_tree_sha256 or result.source_sha256}",
    ]
    if tradeoffs:
        lines.append(f"warnings={','.join(tradeoffs)}")
    return "\n".join(lines)


def sort_profile_statuses(statuses: list[ScratchStatus]) -> list[ScratchStatus]:
    return sorted(statuses, key=status_rank, reverse=True)


def build_compiler_scan_rows(
    baselines: Collection[ScratchStatus],
    profiles: Collection[ScratchStatus],
) -> list[CompilerScanRow]:
    """Select the strongest compiler result for each canonical scratch baseline."""

    profiles_by_directory: dict[Path, list[ScratchStatus]] = defaultdict(list)
    for status in profiles:
        profiles_by_directory[status.config.directory.resolve()].append(status)

    rows: list[CompilerScanRow] = []
    seen_directories: set[Path] = set()
    for baseline in baselines:
        directory = baseline.config.directory.resolve()
        if directory in seen_directories:
            raise ValueError(f"duplicate compiler-scan baseline: {directory}")
        seen_directories.add(directory)
        evaluated = profiles_by_directory.get(directory, [])
        candidates = [baseline, *evaluated]
        best = max(
            candidates,
            key=lambda status: (
                status_rank(status),
                status.config.compiler == baseline.config.compiler
                and status.config.cflags == baseline.config.cflags,
            ),
        )
        rows.append(
            CompilerScanRow(
                baseline=baseline,
                best=best,
                evaluated_profiles=len(evaluated),
            ),
        )

    classification_rank = {"exact": 0, "improved": 1, "tied": 2}
    return sorted(
        rows,
        key=lambda row: (
            classification_rank[row.classification],
            -row.fuzzy_delta_bytes,
            row.baseline.config.image,
            row.baseline.address,
            row.baseline.config.function,
        ),
    )


def compiler_scan_row_payload(row: CompilerScanRow) -> dict[str, Any]:
    return {
        "classification": row.classification,
        "image": row.baseline.config.image,
        "function": row.baseline.config.function,
        "address": row.baseline.address,
        "evaluated_profiles": row.evaluated_profiles,
        "fuzzy_delta_bytes": row.fuzzy_delta_bytes,
        "baseline": scratch_status_payload(row.baseline),
        "best": scratch_status_payload(row.best),
    }


def compiler_scan_summary(
    rows: Collection[CompilerScanRow],
    profiles: Collection[ScratchStatus],
) -> dict[str, int]:
    classifications = Counter(row.classification for row in rows)
    return {
        "targets": len(rows),
        "profiles": len(profiles),
        "exact": classifications["exact"],
        "improved": classifications["improved"],
        "tied": classifications["tied"],
        "errors": sum(status.state == "error" for status in profiles),
    }


def render_compiler_scan_rows(rows: Collection[CompilerScanRow]) -> str:
    header = (
        "kind",
        "image",
        "function",
        "baseline",
        "best",
        "base match",
        "best match",
        "fuzzy delta",
        "refs",
    )
    rendered: list[tuple[str, ...]] = [header]
    for row in rows:
        baseline = row.baseline
        best = row.best
        rendered.append(
            (
                row.classification,
                baseline.config.image,
                baseline.config.function,
                baseline.config.compiler,
                best.config.compiler,
                f"{baseline.ratio:.2%}" if baseline.ratio is not None else "-",
                f"{best.ratio:.2%}" if best.ratio is not None else "-",
                f"{row.fuzzy_delta_bytes:+.1f}",
                f"{best.masked_ok}/{best.masked_unresolved}/{best.masked_mismatches}",
            ),
        )
    widths = [max(len(row[column]) for row in rendered) for column in range(len(header))]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip()
        for row in rendered
    )


def render_profile_table(statuses: list[ScratchStatus]) -> str:
    rows: list[tuple[str, ...]] = [PROFILE_HEADER]
    for rank, status in enumerate(sort_profile_statuses(statuses), start=1):
        rows.append(
            (
                str(rank),
                status.state,
                status.config.compiler,
                status.config.cflags,
                (
                    f"{status.fuzzy_weighted_bytes:.0f}/{status.target_size}"
                    if status.ratio is not None
                    else "-"
                ),
                f"{status.fuzzy_gap_bytes:.0f}" if status.ratio is not None else "-",
                f"{status.ratio:.2%}" if status.ratio is not None else "-",
                (
                    f"{status.candidate_instructions}/{status.target_instructions}"
                    if status.ratio is not None
                    else "-"
                ),
                (
                    f"{status.prefix_instructions}/{status.target_instructions}"
                    if status.ratio is not None
                    else "-"
                ),
                (
                    f"{status.masked_ok}/{status.masked_unresolved}/{status.masked_mismatches}"
                    if status.ratio is not None
                    else "-"
                ),
                status.error or "",
            ),
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(PROFILE_HEADER))]
    return "\n".join("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows)


def triage_row_payload(row: TriageRow) -> dict[str, Any]:
    return {
        "state": row.state,
        "image": row.image,
        "function": row.function,
        "address": row.address,
        "target_bytes": row.target_size,
        "exact_bytes": row.exact_bytes,
        "fuzzy_weighted_bytes": row.fuzzy_weighted_bytes,
        "fuzzy_gap_bytes": row.fuzzy_gap_bytes,
        "candidate_bytes": row.candidate_bytes,
        "scratch_count": row.scratch_count,
        "experiments": {
            "records": row.experiments.records,
            "current_records": row.experiments.current_records,
            "historical_records": row.experiments.historical_records,
            "unversioned_records": row.experiments.unversioned_records,
            "mutation_sweeps": row.experiments.mutation_sweeps,
            "probes": row.experiments.probes,
            "evaluated_variants": row.experiments.evaluated_variants,
            "unique_variants": row.experiments.unique_variants,
            "unique_specs": row.experiments.unique_specs,
            "no_improvement_streak": row.experiments.no_improvement_streak,
            "current_inconclusive_sweeps": row.experiments.current_inconclusive_sweeps,
            "current_errored_variants": row.experiments.current_errored_variants,
            "audited_errored_variants": row.experiments.audited_errored_variants,
            "mutation_error_audits": row.experiments.mutation_error_audits,
            "strict_errors": row.experiments.strict_errors,
            "flags": list(row.experiments.flags),
            "errors": row.experiments.errors,
        },
        "best_scratch": scratch_status_payload(row.best_status) if row.best_status is not None else None,
    }


def collect_residual_frontier_rows(
    statuses: Collection[ScratchStatus],
) -> list[ResidualFrontierRow]:
    """Select one best non-exact scratch per native target with epoch-aware evidence."""

    best_by_target: dict[tuple[str, int | str], ScratchStatus] = {}
    for status in statuses:
        target: tuple[str, int | str] = (
            status.config.image,
            status.address if status.address else status.config.function,
        )
        best = best_by_target.get(target)
        if best is None or status_rank(status) > status_rank(best):
            best_by_target[target] = status

    rows = [
        ResidualFrontierRow(
            status=status,
            experiments=triage_experiment_evidence(status),
        )
        for status in best_by_target.values()
        if status.state in {"audit", "wip"}
    ]
    return sorted(
        rows,
        key=lambda row: (
            -row.status.fuzzy_gap_bytes,
            -row.status.target_size,
            row.status.config.image,
            row.status.address,
            row.status.config.function,
        ),
    )


def residual_frontier_summary_payload(
    rows: Collection[ResidualFrontierRow],
) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: row.status.fuzzy_gap_bytes, reverse=True)
    total_gap = sum(row.status.fuzzy_gap_bytes for row in ordered)

    def grouped(field: str) -> dict[str, dict[str, float | int]]:
        labels: dict[str, list[ResidualFrontierRow]] = {}
        for row in ordered:
            if field == "evidence":
                values = (row.evidence_state,)
            elif field == "recovery":
                values = (scratch_recovery(row.status),)
            else:
                values = row.status.config.residuals or ("unspecified",)
            for value in values:
                labels.setdefault(value, []).append(row)
        return {
            label: {
                "functions": len(group_rows),
                "fuzzy_gap_bytes": sum(row.status.fuzzy_gap_bytes for row in group_rows),
            }
            for label, group_rows in sorted(labels.items())
        }

    def top_share(limit: int) -> float:
        if not total_gap:
            return 0.0
        return sum(row.status.fuzzy_gap_bytes for row in ordered[:limit]) / total_gap

    return {
        "functions": len(ordered),
        "fuzzy_gap_bytes": total_gap,
        "top_5_gap_share": top_share(5),
        "top_10_gap_share": top_share(10),
        "evidence": grouped("evidence"),
        "recovery": grouped("recovery"),
        "residuals": grouped("residuals"),
    }


def render_residual_frontier_markdown(
    rows: Collection[ResidualFrontierRow],
) -> list[str]:
    if not rows:
        return []
    ordered = sorted(
        rows,
        key=lambda row: (
            -row.status.fuzzy_gap_bytes,
            -row.status.target_size,
            row.status.config.image,
            row.status.address,
        ),
    )
    summary = residual_frontier_summary_payload(ordered)
    evidence = summary["evidence"]

    def evidence_metric(label: str, key: str) -> float | int:
        metrics = evidence.get(label, {})
        return metrics.get(key, 0)

    current_labels = (
        "current-active",
        "current-error",
        "current-inconclusive",
        "current-stalled",
    )
    current_functions = sum(int(evidence_metric(label, "functions")) for label in current_labels)
    current_gap = sum(float(evidence_metric(label, "fuzzy_gap_bytes")) for label in current_labels)
    historical_functions = int(evidence_metric("historical-only", "functions"))
    historical_gap = float(evidence_metric("historical-only", "fuzzy_gap_bytes"))
    unexplored_functions = int(evidence_metric("unexplored", "functions"))
    unexplored_gap = float(evidence_metric("unexplored", "fuzzy_gap_bytes"))

    lines = [
        "## Residual frontier",
        "",
        (
            f"**{summary['functions']}** non-exact scratch-backed functions hold "
            f"**{summary['fuzzy_gap_bytes']:.0f} fuzzy-gap bytes**. The top 5 hold "
            f"**{summary['top_5_gap_share']:.1%}** of that gap; the top 10 hold "
            f"**{summary['top_10_gap_share']:.1%}**."
        ),
        "",
        (
            f"Current-baseline experiments cover **{current_functions} functions / "
            f"{current_gap:.0f} gap bytes**; **{historical_functions} / {historical_gap:.0f}** "
            f"are historical-only; **{unexplored_functions} / {unexplored_gap:.0f}** have no "
            "recorded experiments."
        ),
        "",
        (
            "Evidence labels are baseline-epoch aware. `current-stalled` means at least three "
            "complete, error-free, non-improving mutation sweeps against the current inputs. "
            "`historical-only` is not stalled and must not suppress a fresh source analysis. "
            "Recovery and residual labels describe the present source assessment; they do not "
            "prove that compiler search is exhausted."
        ),
        "",
        (
            "| rank | image | function | fuzzy gap | recovery | residual | evidence | "
            "current/all | streak | flags |"
        ),
        "|---:|---|---|---:|---|---|---|---:|---:|---|",
    ]
    for rank, row in enumerate(ordered, start=1):
        status = row.status
        experiments = row.experiments
        lines.append(
            "| "
            + " | ".join(
                (
                    str(rank),
                    status.config.image,
                    status.config.function,
                    f"{status.fuzzy_gap_bytes:.0f}",
                    scratch_recovery(status),
                    ",".join(status.config.residuals) or "unspecified",
                    row.evidence_state,
                    f"{experiments.current_records}/{experiments.records}",
                    str(experiments.no_improvement_streak),
                    ",".join(experiments.flags) or "-",
                ),
            )
            + " |",
        )
    lines.append("")
    return lines


def render_status_rows(
    statuses: list[ScratchStatus],
    *,
    sort_by: str = "address",
) -> list[tuple[str, ...]]:
    rows = []
    default_build = f"{DEFAULT_SCRATCH_COMPILER} {DEFAULT_SCRATCH_CFLAGS}"
    for status in sort_scratch_statuses(statuses, sort_by=sort_by):
        ratio = f"{status.ratio:.2%}" if status.ratio is not None else "-"
        insns = f"{status.candidate_instructions}/{status.target_instructions}" if status.ratio is not None else "-"
        prefix = f"{status.prefix_instructions}/{status.target_instructions}" if status.ratio is not None else "-"
        fuzzy = (
            f"{status.fuzzy_weighted_bytes:.0f}/{status.target_size}"
            if status.ratio is not None
            else "-"
        )
        gap = f"{status.fuzzy_gap_bytes:.0f}" if status.ratio is not None else "-"
        refs = (
            f"{status.masked_ok}/{status.masked_unresolved}/{status.masked_mismatches}"
            if status.ratio is not None
            else "-"
        )
        if status.config.import_thunk is not None:
            build = f"import:{status.config.import_thunk}"
        elif status.config.archive is not None:
            build = f"archive:{status.config.archive_member}"
            if status.config.archive_extent != "symbol":
                build += f":{status.config.archive_extent}"
            if status.config.archive_end_symbol is not None:
                build += f":until={status.config.archive_end_symbol}"
            if status.config.archive_size is not None:
                build += f":size={status.config.archive_size}"
        else:
            build = f"{status.config.compiler} {status.config.cflags}"
        rows.append(
            (
                status.state,
                status.config.image,
                status.config.function,
                f"0x{status.address:08x}" if status.address else "-",
                str(status.target_size) if status.target_size else "-",
                fuzzy,
                gap,
                insns,
                ratio,
                prefix,
                refs,
                "" if build == default_build else build,
                status.error or status.config.note,
            ),
        )
    return rows


def render_triage_rows(rows: list[TriageRow], *, sort_by: str = "address") -> list[tuple[str, ...]]:
    rendered: list[tuple[str, ...]] = []
    for row in sort_triage_rows(rows, sort_by=sort_by):
        best = row.best_status
        rendered.append(
            (
                row.state,
                row.image,
                row.function,
                f"0x{row.address:08x}",
                str(row.target_size),
                f"{row.exact_bytes}/{row.target_size}",
                f"{row.fuzzy_weighted_bytes:.0f}/{row.target_size}",
                f"{row.candidate_bytes}/{row.target_size}",
                f"{row.fuzzy_gap_bytes:.0f}",
                f"{best.ratio:.2%}" if best is not None and best.ratio is not None else "-",
                (
                    f"{best.prefix_instructions}/{best.target_instructions}"
                    if best is not None and best.ratio is not None
                    else "-"
                ),
                (
                    f"{best.masked_ok}/{best.masked_unresolved}/{best.masked_mismatches}"
                    if best is not None and best.ratio is not None
                    else "-"
                ),
                best.config.directory.name if best is not None else "-",
                (
                    f"{row.experiments.current_records}/"
                    f"{row.experiments.records}/"
                    f"{row.experiments.unique_variants}"
                ),
                str(row.experiments.no_improvement_streak),
                ",".join(row.experiments.flags) or "-",
                (best.error or best.config.note) if best is not None else "",
            ),
        )
    return rendered


def render_triage_table(rows: list[TriageRow], *, sort_by: str = "address") -> str:
    rendered = [TRIAGE_HEADER, *render_triage_rows(rows, sort_by=sort_by)]
    widths = [max(len(row[column]) for row in rendered) for column in range(len(TRIAGE_HEADER))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rendered]
    lines.append(render_triage_summary(rows))
    return "\n".join(lines)


def render_triage_summary(rows: list[TriageRow]) -> str:
    summary = triage_summary_payload(rows)
    target_bytes = summary["target_bytes"]
    exact_bytes = summary["exact_bytes"]
    fuzzy_bytes = summary["fuzzy_weighted_bytes"]
    candidate_bytes = summary["candidate_bytes"]
    states = summary["states"]

    def percentage(value: float) -> float:
        return value / target_bytes if target_bytes else 0.0

    return (
        f"\nrows={summary['row_count']} states="
        + "/".join(f"{state}:{count}" for state, count in states.items())
        + f"; exact={exact_bytes}/{target_bytes} ({percentage(exact_bytes):.1%}); "
        f"fuzzy={fuzzy_bytes:.0f}/{target_bytes} ({percentage(fuzzy_bytes):.1%}); "
        f"candidate={candidate_bytes}/{target_bytes} ({percentage(candidate_bytes):.1%})"
    )


def triage_summary_payload(rows: list[TriageRow]) -> dict[str, Any]:
    return {
        "row_count": len(rows),
        "target_bytes": sum(row.target_size for row in rows),
        "exact_bytes": sum(row.exact_bytes for row in rows),
        "fuzzy_weighted_bytes": sum(row.fuzzy_weighted_bytes for row in rows),
        "candidate_bytes": sum(row.candidate_bytes for row in rows),
        "states": {
            state: sum(row.state == state for row in rows)
            for state in ("match", "audit", "wip", "error", "missing")
        },
    }


def render_image_total_rows(totals: list[ImageTotals]) -> list[tuple[str, ...]]:
    return [
        (
            total.image,
            f"{total.matched_functions}/{total.function_count}",
            f"{total.matched_bytes}/{total.byte_total}",
            f"{total.byte_percentage:.1%}",
            f"{total.fuzzy_weighted_bytes:.0f}/{total.byte_total}",
            f"{total.fuzzy_byte_percentage:.1%}",
            f"{total.candidate_functions}/{total.function_count}",
            f"{total.candidate_bytes}/{total.byte_total}",
            f"{total.candidate_byte_percentage:.1%}",
            f"{total.matched_scratches}/{total.scratch_count}",
        )
        for total in totals
    ]


def image_totals_payload(total: ImageTotals) -> dict[str, Any]:
    return {
        "image": total.image,
        "function_count": total.function_count,
        "byte_total": total.byte_total,
        "exact_functions": total.matched_functions,
        "exact_bytes": total.matched_bytes,
        "fuzzy_weighted_bytes": total.fuzzy_weighted_bytes,
        "candidate_functions": total.candidate_functions,
        "candidate_bytes": total.candidate_bytes,
        "scratch_count": total.scratch_count,
        "exact_scratches": total.matched_scratches,
    }


def _overall_totals(totals: list[ImageTotals]) -> ImageTotals:
    return ImageTotals(
        image="all",
        function_count=sum(total.function_count for total in totals),
        byte_total=sum(total.byte_total for total in totals),
        matched_functions=sum(total.matched_functions for total in totals),
        matched_bytes=sum(total.matched_bytes for total in totals),
        fuzzy_weighted_bytes=sum(total.fuzzy_weighted_bytes for total in totals),
        candidate_functions=sum(total.candidate_functions for total in totals),
        candidate_bytes=sum(total.candidate_bytes for total in totals),
        scratch_count=sum(total.scratch_count for total in totals),
        matched_scratches=sum(total.matched_scratches for total in totals),
    )


_NATIVE_ARTIFACT_FILES = ("objects.json", "closure.json", "data.json")
_NATIVE_ARTIFACT_KINDS = {
    "objects.json": "crimson-native-object-manifest",
    "closure.json": "crimson-native-symbol-closure",
    "data.json": "crimson-native-data-manifest",
}
_NATIVE_ARTIFACT_SCHEMAS = {
    "objects.json": 2,
    "closure.json": 2,
    "data.json": 1,
}


def _native_required_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _native_required_int(mapping: dict[str, Any], key: str, label: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label}.{key} must be an integer")
    return value


def _native_required_bool(mapping: dict[str, Any], key: str, label: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"{label}.{key} must be a boolean")
    return value


def _native_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


NATIVE_JSON_PROGRAM_PROJECTION = "json-program-v1"


def native_json_program_sha256(path: Path, program: str) -> str:
    """Hash only the rows consumed for one image from a shared JSON map."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        projected: Any = [
            row
            for row in payload
            if isinstance(row, dict) and row.get("program") == program
        ]
    elif isinstance(payload, dict):
        raw_entries = payload.get("entries")
        if not isinstance(raw_entries, list):
            raise TypeError(f"{path}: projected JSON object must contain an entries array")
        projected = {
            **payload,
            "entries": [
                row
                for row in raw_entries
                if isinstance(row, dict) and row.get("program") == program
            ],
        }
    else:
        raise TypeError(f"{path}: projected JSON input must be an array or object")
    return hashlib.sha256(
        json.dumps(projected, separators=(",", ":"), sort_keys=True).encode(),
    ).hexdigest()


def _native_tree_set_sha256(root: Path, trees: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    files: list[Path] = []
    for tree_name in trees:
        tree = root / tree_name
        if not tree.is_dir():
            raise FileNotFoundError(tree)
        files.extend(candidate for candidate in tree.rglob("*") if candidate.is_file())
    for path in sorted(files):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        contents = path.read_bytes()
        digest.update(len(contents).to_bytes(8, "little"))
        digest.update(contents)
    return digest.hexdigest()


def _native_input_records(
    objects: dict[str, Any],
    closure: dict[str, Any],
    data: dict[str, Any],
) -> tuple[
    list[tuple[str, str, bool, tuple[str, str] | None]],
    list[tuple[str, tuple[str, ...], str]],
]:
    files: list[tuple[str, str, bool, tuple[str, str] | None]] = []

    def projection_from_row(
        row: dict[str, Any],
        key: str,
        label: str,
    ) -> tuple[str, str] | None:
        raw_projection = row.get(key)
        if raw_projection is None:
            return None
        projection = _native_required_mapping(raw_projection, f"{label}.{key}")
        kind = projection.get("kind")
        program = projection.get("program")
        if kind != NATIVE_JSON_PROGRAM_PROJECTION:
            raise ValueError(
                f"{label}.{key}.kind must be {NATIVE_JSON_PROGRAM_PROJECTION!r}",
            )
        if not isinstance(program, str) or not program:
            raise ValueError(f"{label}.{key}.program must be a non-empty string")
        return kind, program

    def add_file_rows(rows: Any, label: str) -> None:
        if not isinstance(rows, list):
            raise TypeError(f"{label} must be an array")
        for index, raw_row in enumerate(rows):
            row = _native_required_mapping(raw_row, f"{label}[{index}]")
            path = row.get("path")
            sha256 = row.get("sha256")
            repository_relative = row.get("repository_relative")
            if not isinstance(path, str) or not path:
                raise ValueError(f"{label}[{index}].path must be a non-empty string")
            if not isinstance(sha256, str) or len(sha256) != 64:
                raise ValueError(f"{label}[{index}].sha256 must be a SHA-256 digest")
            if not isinstance(repository_relative, bool):
                raise TypeError(f"{label}[{index}].repository_relative must be a boolean")
            projection = projection_from_row(
                row,
                "projection",
                f"{label}[{index}]",
            )
            files.append((path, sha256, repository_relative, projection))

    def add_direct_file(
        row: dict[str, Any],
        path_key: str,
        sha256_key: str,
        label: str,
    ) -> None:
        path = row.get(path_key)
        sha256 = row.get(sha256_key)
        if not isinstance(path, str) or not path:
            raise ValueError(f"{label}.{path_key} must be a non-empty string")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValueError(f"{label}.{sha256_key} must be a SHA-256 digest")
        projection = projection_from_row(
            row,
            f"{path_key}_projection",
            label,
        )
        files.append((path, sha256, True, projection))

    raw_objects = objects.get("objects")
    if not isinstance(raw_objects, list):
        raise TypeError("objects.json.objects must be an array")
    for index, raw_object in enumerate(raw_objects):
        label = f"objects.json.objects[{index}]"
        row = _native_required_mapping(raw_object, label)
        add_direct_file(row, "source", "source_sha256", label)
        add_direct_file(row, "config", "config_sha256", label)
        add_file_rows(
            row.get("compile_inputs"),
            f"{label}.compile_inputs",
        )
        raw_functions = row.get("functions")
        if not isinstance(raw_functions, list):
            raise TypeError(f"{label}.functions must be an array")
        for function_index, raw_function in enumerate(raw_functions):
            function_label = f"{label}.functions[{function_index}]"
            function = _native_required_mapping(raw_function, function_label)
            add_direct_file(
                function,
                "canonical_source",
                "canonical_source_sha256",
                function_label,
            )
            add_direct_file(
                function,
                "canonical_config",
                "canonical_config_sha256",
                function_label,
            )

    abi = _native_required_mapping(objects.get("abi_assertions"), "objects.json.abi_assertions")
    add_file_rows(abi.get("compile_inputs"), "objects.json.abi_assertions.compile_inputs")
    provenance = _native_required_mapping(objects.get("provenance"), "objects.json.provenance")
    add_file_rows(
        provenance.get("selection_inputs"),
        "objects.json.provenance.selection_inputs",
    )
    toolchain = _native_required_mapping(provenance.get("toolchain"), "objects.json.provenance.toolchain")
    for key in ("cl_wrapper", "wibo"):
        row = _native_required_mapping(toolchain.get(key), f"objects.json.provenance.toolchain.{key}")
        add_file_rows([row], f"objects.json.provenance.toolchain.{key}")

    reference_image = objects.get("reference_image")
    reference_image_sha256 = objects.get("reference_image_sha256")
    if not isinstance(reference_image, str) or not reference_image:
        raise ValueError("objects.json.reference_image must be a non-empty string")
    if not isinstance(reference_image_sha256, str) or len(reference_image_sha256) != 64:
        raise ValueError("objects.json.reference_image_sha256 must be a SHA-256 digest")
    files.append((reference_image, reference_image_sha256, True, None))

    closure_source = _native_required_mapping(closure.get("source"), "closure.json.source")
    add_file_rows(closure_source.get("catalog_inputs"), "closure.json.source.catalog_inputs")

    data_source = _native_required_mapping(data.get("source"), "data.json.source")
    for key in ("data_map", "segments"):
        add_direct_file(
            data_source,
            key,
            f"{key}_sha256",
            "data.json.source",
        )
    if "definitions" in data_source or "definitions_sha256" in data_source:
        path = data_source.get("definitions")
        sha256 = data_source.get("definitions_sha256")
        if not isinstance(path, str) or not path:
            raise ValueError("data.json.source.definitions must be a non-empty string")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValueError(
                "data.json.source.definitions_sha256 must be a SHA-256 digest",
            )
        files.append((path, sha256, True, None))

    raw_bundles = toolchain.get("compiler_bundles")
    if not isinstance(raw_bundles, list):
        raise TypeError("objects.json.provenance.toolchain.compiler_bundles must be an array")
    bundles: list[tuple[str, tuple[str, ...], str]] = []
    for index, raw_bundle in enumerate(raw_bundles):
        bundle = _native_required_mapping(
            raw_bundle,
            f"objects.json.provenance.toolchain.compiler_bundles[{index}]",
        )
        root = bundle.get("root")
        raw_trees = bundle.get("included_trees")
        sha256 = bundle.get("bundle_sha256")
        if not isinstance(root, str) or not root:
            raise ValueError(
                f"objects.json.provenance.toolchain.compiler_bundles[{index}].root "
                "must be a non-empty string",
            )
        if not isinstance(raw_trees, list) or not all(
            isinstance(tree, str) and tree for tree in raw_trees
        ):
            raise ValueError(
                f"objects.json.provenance.toolchain.compiler_bundles[{index}].included_trees "
                "must be an array of strings",
            )
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValueError(
                f"objects.json.provenance.toolchain.compiler_bundles[{index}].bundle_sha256 "
                "must be a SHA-256 digest",
            )
        bundles.append((root, tuple(raw_trees), sha256))
    return files, bundles


def _native_input_staleness(
    objects: dict[str, Any],
    closure: dict[str, Any],
    data: dict[str, Any],
    *,
    repo_root: Path,
    allow_absent_toolchain: bool = False,
) -> list[str]:
    file_rows, bundle_rows = _native_input_records(objects, closure, data)
    expected_files: dict[tuple[str, tuple[str, str] | None], str] = {}
    conflicting_files: set[tuple[str, tuple[str, str] | None]] = set()
    non_repository_files = 0
    for path, sha256, repository_relative, projection in file_rows:
        if not repository_relative:
            non_repository_files += 1
            continue
        key = (path, projection)
        previous = expected_files.setdefault(key, sha256)
        if previous != sha256:
            conflicting_files.add(key)

    root = repo_root.resolve()
    changed_files: list[str] = []
    escaped_files = 0
    for (label, projection), expected_sha256 in sorted(
        expected_files.items(),
        key=lambda item: (item[0][0], item[0][1] or ("", "")),
    ):
        path = (root / label).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            escaped_files += 1
            continue
        try:
            actual_sha256 = (
                _native_file_sha256(path)
                if projection is None
                else native_json_program_sha256(path, projection[1])
            )
        except OSError:
            if (
                allow_absent_toolchain
                and not path.exists()
                and label.startswith(
                    ("tools/match/bin/", "tools/match/compilers/"),
                )
            ):
                continue
            changed_files.append(label)
            continue
        if actual_sha256 != expected_sha256:
            changed_files.append(label)

    expected_bundles: dict[tuple[str, tuple[str, ...]], str] = {}
    conflicting_bundles: set[tuple[str, tuple[str, ...]]] = set()
    for label, trees, sha256 in bundle_rows:
        key = (label, trees)
        previous = expected_bundles.setdefault(key, sha256)
        if previous != sha256:
            conflicting_bundles.add(key)
    changed_bundles = 0
    for (label, trees), expected_sha256 in sorted(expected_bundles.items()):
        path = (root / label).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            changed_bundles += 1
            continue
        try:
            actual_sha256 = _native_tree_set_sha256(path, trees)
        except (OSError, ValueError):
            if (
                allow_absent_toolchain
                and not path.exists()
                and label.startswith("tools/match/compilers/")
            ):
                continue
            changed_bundles += 1
            continue
        if actual_sha256 != expected_sha256:
            changed_bundles += 1

    reasons: list[str] = []
    if changed_files:
        displayed = ", ".join(changed_files[:4])
        if len(changed_files) > 4:
            displayed += f", ... (+{len(changed_files) - 4} more)"
        reasons.append(
            f"{len(changed_files)} recorded file inputs changed or missing: {displayed}",
        )
    if conflicting_files:
        reasons.append(f"{len(conflicting_files)} file inputs have conflicting digests")
    if non_repository_files:
        reasons.append(f"{non_repository_files} file inputs are not repository-relative")
    if escaped_files:
        reasons.append(f"{escaped_files} file inputs escape the repository")
    if changed_bundles:
        reasons.append(f"{changed_bundles} compiler bundles changed or missing")
    if conflicting_bundles:
        reasons.append(f"{len(conflicting_bundles)} compiler bundles have conflicting digests")
    return reasons


def _native_audit_digest(payloads: dict[str, dict[str, Any]]) -> str:
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
    return hashlib.sha256(
        json.dumps(
            digest_payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    ).hexdigest()


def _native_companion_staleness(
    objects: dict[str, Any],
    closure: dict[str, Any],
    *,
    artifact_directory: Path,
) -> list[str]:
    expected_outputs = (
        ("objects.txt", objects.get("object_list_sha256")),
        ("exports.def", closure.get("export_definition_sha256")),
    )
    changed = 0
    for filename, expected_sha256 in expected_outputs:
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise ValueError(f"{filename} audit digest must be a SHA-256 digest")
        try:
            actual_sha256 = _native_file_sha256(artifact_directory / filename)
        except OSError:
            changed += 1
            continue
        if actual_sha256 != expected_sha256:
            changed += 1
    if changed:
        return [f"{changed} generated linker artifacts changed or missing"]
    return []


def collect_native_link_statuses(
    *,
    analysis_root: Path = DEFAULT_NATIVE_ANALYSIS_ROOT,
    repo_root: Path = REPO_ROOT,
    scope: str = DEFAULT_MATCH_SCOPE,
    images: Collection[str] = TRACKED_IMAGE_NAMES,
    allow_absent_toolchain: bool = False,
) -> list[NativeLinkStatus]:
    statuses: list[NativeLinkStatus] = []
    for image in images:
        directory = analysis_root / image
        paths = {name: directory / name for name in _NATIVE_ARTIFACT_FILES}
        missing = [name for name in _NATIVE_ARTIFACT_FILES if not paths[name].is_file()]
        if missing:
            statuses.append(
                NativeLinkStatus(
                    image=image,
                    artifact_state="missing",
                    artifact_note="missing " + ", ".join(missing),
                ),
            )
            continue

        try:
            payloads = {
                name: _native_required_mapping(
                    json.loads(path.read_text(encoding="utf-8")),
                    name,
                )
                for name, path in paths.items()
            }
            for name, payload in payloads.items():
                if payload.get("kind") != _NATIVE_ARTIFACT_KINDS[name]:
                    raise ValueError(f"{name}.kind is not {_NATIVE_ARTIFACT_KINDS[name]!r}")
                if payload.get("schema") != _NATIVE_ARTIFACT_SCHEMAS[name]:
                    raise ValueError(
                        f"{name}.schema is not {_NATIVE_ARTIFACT_SCHEMAS[name]}",
                    )
                if payload.get("image") != image:
                    raise ValueError(f"{name}.image is not {image!r}")

            objects = payloads["objects.json"]
            closure = payloads["closure.json"]
            data = payloads["data.json"]
            closure_summary = _native_required_mapping(
                closure.get("summary"),
                "closure.json.summary",
            )
            data_summary = _native_required_mapping(data.get("summary"), "data.json.summary")
            translation_units = _native_required_mapping(
                objects.get("translation_units"),
                "objects.json.translation_units",
            )
            abi = _native_required_mapping(
                objects.get("abi_assertions"),
                "objects.json.abi_assertions",
            )
            abi_status = abi.get("status")
            if not isinstance(abi_status, str) or not abi_status:
                raise ValueError("objects.json.abi_assertions.status must be a non-empty string")
            raw_categories = _native_required_mapping(
                closure_summary.get("unresolved_by_category"),
                "closure.json.summary.unresolved_by_category",
            )
            categories = {
                str(category): _native_required_int(
                    raw_categories,
                    str(category),
                    "closure.json.summary.unresolved_by_category",
                )
                for category in raw_categories
            }
            categories.setdefault("game_data", 0)

            function_count = _native_required_int(objects, "function_count", "objects.json")
            object_count = _native_required_int(objects, "object_count", "objects.json")
            reasons: list[str] = []
            raw_digests = [payload.get("audit_digest") for payload in payloads.values()]
            if any(
                not isinstance(digest, str) or len(digest) != 64
                for digest in raw_digests
            ):
                raise ValueError("artifact audit digest must be a SHA-256 digest")
            digests = set(raw_digests)
            if len(digests) != 1:
                reasons.append("artifact audit digests disagree")
            elif next(iter(digests)) != _native_audit_digest(payloads):
                reasons.append("artifact content does not match audit digest")
            object_scope = objects.get("scope")
            closure_scope = closure.get("scope")
            if object_scope != scope or closure_scope != scope:
                reasons.append(
                    f"artifact scope is {object_scope!r}/{closure_scope!r}, expected {scope!r}",
                )
            if (
                _native_required_int(closure_summary, "function_count", "closure.json.summary")
                != function_count
                or _native_required_int(closure_summary, "object_count", "closure.json.summary")
                != object_count
            ):
                reasons.append("object and closure counts disagree")
            reasons.extend(
                _native_input_staleness(
                    objects,
                    closure,
                    data,
                    repo_root=repo_root,
                    allow_absent_toolchain=allow_absent_toolchain,
                ),
            )
            reasons.extend(
                _native_companion_staleness(
                    objects,
                    closure,
                    artifact_directory=directory,
                ),
            )
            state = "stale" if reasons else "current"
            if reasons:
                note = "; ".join(reasons)
            elif allow_absent_toolchain:
                note = (
                    "artifact digest and required repository inputs agree; "
                    "toolchain availability not required"
                )
            else:
                note = "audited inputs and artifact digest agree"
            statuses.append(
                NativeLinkStatus(
                    image=image,
                    artifact_state=state,
                    artifact_note=note,
                    function_count=function_count,
                    object_count=object_count,
                    translation_unit_clusters=_native_required_int(
                        translation_units,
                        "cluster_count",
                        "objects.json.translation_units",
                    ),
                    abi_status=abi_status,
                    function_closure=_native_required_bool(
                        closure_summary,
                        "function_closure",
                        "closure.json.summary",
                    ),
                    game_owned_closure=_native_required_bool(
                        closure_summary,
                        "game_owned_closure",
                        "closure.json.summary",
                    ),
                    all_references_closed=_native_required_bool(
                        closure_summary,
                        "all_references_closed",
                        "closure.json.summary",
                    ),
                    hard_duplicate_symbols=_native_required_int(
                        closure_summary,
                        "hard_duplicate_symbols",
                        "closure.json.summary",
                    ),
                    resolved_symbols=_native_required_int(
                        closure_summary,
                        "resolved_symbols",
                        "closure.json.summary",
                    ),
                    unresolved_symbols=_native_required_int(
                        closure_summary,
                        "unresolved_symbols",
                        "closure.json.summary",
                    ),
                    unresolved_by_category=tuple(sorted(categories.items())),
                    data_entries=_native_required_int(
                        data_summary,
                        "entry_count",
                        "data.json.summary",
                    ),
                    typed_data_entries=_native_required_int(
                        data_summary,
                        "typed_entries",
                        "data.json.summary",
                    ),
                    explicit_size_entries=_native_required_int(
                        data_summary,
                        "explicit_size_entries",
                        "data.json.summary",
                    ),
                    explicit_alignment_entries=_native_required_int(
                        data_summary,
                        "explicit_alignment_entries",
                        "data.json.summary",
                    ),
                    explicit_initializer_entries=_native_required_int(
                        data_summary,
                        "explicit_initializer_entries",
                        "data.json.summary",
                    ),
                ),
            )
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            statuses.append(
                NativeLinkStatus(
                    image=image,
                    artifact_state="invalid",
                    artifact_note=str(exc).splitlines()[0],
                ),
            )
    return statuses


def _image_summary(total: ImageTotals) -> str:
    return (
        f"{total.image}: {total.matched_functions}/{total.function_count} functions "
        f"({total.function_percentage:.1%}), "
        f"{total.matched_bytes}/{total.byte_total} bytes "
        f"({total.byte_percentage:.1%}) matched; "
        f"{total.fuzzy_weighted_bytes:.0f}/{total.byte_total} fuzzy-weighted bytes "
        f"({total.fuzzy_byte_percentage:.1%}); "
        f"{total.candidate_functions}/{total.function_count} reproducible candidates covering "
        f"{total.candidate_bytes}/{total.byte_total} bytes "
        f"({total.candidate_byte_percentage:.1%}); "
        f"{total.matched_scratches}/{total.scratch_count} scratches verified"
    )


def render_status_summary(totals: list[ImageTotals]) -> str:
    overall = _overall_totals(totals)
    remaining_functions = overall.function_count - overall.matched_functions
    remaining_bytes = overall.byte_total - overall.matched_bytes
    fuzzy_gap_bytes = overall.byte_total - overall.fuzzy_weighted_bytes
    lines = [
        (f"all images: {overall.matched_functions}/{overall.function_count} functions "
        f"({overall.function_percentage:.1%}), "
        f"{overall.matched_bytes}/{overall.byte_total} bytes "
        f"({overall.byte_percentage:.1%}) matched; "
        f"{overall.fuzzy_weighted_bytes:.0f}/{overall.byte_total} fuzzy-weighted bytes "
        f"({overall.fuzzy_byte_percentage:.1%}); "
        f"{overall.candidate_functions}/{overall.function_count} reproducible candidates covering "
        f"{overall.candidate_bytes}/{overall.byte_total} bytes "
        f"({overall.candidate_byte_percentage:.1%}); "
        f"{overall.matched_scratches}/{overall.scratch_count} scratches verified; "
        f"remaining exact-match debt: {remaining_functions} functions, "
        f"{remaining_bytes} bytes, {fuzzy_gap_bytes:.0f} fuzzy-gap bytes"),
        "by image:",
        *(_image_summary(total) for total in totals),
    ]
    return "\n".join(lines)


def render_status_table(
    statuses: list[ScratchStatus],
    totals: list[ImageTotals],
    *,
    sort_by: str = "address",
) -> str:
    rows = [STATUS_HEADER, *render_status_rows(statuses, sort_by=sort_by)]
    widths = [max(len(row[column]) for row in rows) for column in range(len(STATUS_HEADER))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]
    lines.append(f"\n{render_status_summary(totals)}")
    return "\n".join(lines)


def _native_status_value(value: object | None) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def render_native_link_status_markdown(statuses: Collection[NativeLinkStatus]) -> list[str]:
    if not statuses:
        return []
    ordered = sorted(
        statuses,
        key=lambda status: (
            TRACKED_IMAGE_NAMES.index(status.image)
            if status.image in TRACKED_IMAGE_NAMES
            else len(TRACKED_IMAGE_NAMES),
            status.image,
        ),
    )
    lines = [
        "## Native linking",
        "",
        (
            "Generated from `analysis/native/<image>/{objects,closure,data}.json`. "
            "Artifact state is `current` only when all three reports share and reproduce one "
            "audit digest, their recorded inputs still match the repository, and the generated "
            "`objects.txt` and `exports.def` companions still match their recorded hashes. "
            "Gate values in `stale` rows are historical snapshots, not current pass claims."
        ),
        "",
        (
            "| image | artifacts | functions | objects | TU clusters | ABI | "
            "function closure | game-owned closure | all refs closed | hard duplicates | "
            "resolved | unresolved |"
        ),
        "|---|---|---:|---:|---:|---|---|---|---|---:|---:|---:|",
    ]
    for status in ordered:
        lines.append(
            "| "
            + " | ".join(
                (
                    status.image,
                    status.artifact_state,
                    _native_status_value(status.function_count),
                    _native_status_value(status.object_count),
                    _native_status_value(status.translation_unit_clusters),
                    _native_status_value(status.abi_status),
                    _native_status_value(status.function_closure),
                    _native_status_value(status.game_owned_closure),
                    _native_status_value(status.all_references_closed),
                    _native_status_value(status.hard_duplicate_symbols),
                    _native_status_value(status.resolved_symbols),
                    _native_status_value(status.unresolved_symbols),
                ),
            )
            + " |",
        )
    lines.extend(
        [
            "",
            (
                "| image | unresolved by category | game-data unresolved | data entries | typed | "
                "explicit sizes | explicit alignments | explicit initializers |"
            ),
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ],
    )
    for status in ordered:
        categories = ", ".join(
            f"{category}={count}"
            for category, count in status.unresolved_by_category
        )
        if not categories:
            categories = "unknown"
        game_data = dict(status.unresolved_by_category).get("game_data")
        lines.append(
            "| "
            + " | ".join(
                (
                    status.image,
                    categories,
                    _native_status_value(game_data),
                    _native_status_value(status.data_entries),
                    _native_status_value(status.typed_data_entries),
                    _native_status_value(status.explicit_size_entries),
                    _native_status_value(status.explicit_alignment_entries),
                    _native_status_value(status.explicit_initializer_entries),
                ),
            )
            + " |",
        )
    non_current = [status for status in ordered if status.artifact_state != "current"]
    if non_current:
        lines.extend(["", "Artifact freshness issues:"])
        for status in non_current:
            note = status.artifact_note.replace("|", "\\|")
            lines.append(f"- `{status.image}`: **{status.artifact_state}** — {note}")
    lines.append("")
    return lines


def render_status_markdown(
    statuses: list[ScratchStatus],
    totals: list[ImageTotals],
    *,
    scope: str = DEFAULT_MATCH_SCOPE,
    native_statuses: Collection[NativeLinkStatus] = (),
) -> str:
    overall = _overall_totals(totals)
    dispositions = matching_scope_function_disposition_payloads(scope)
    body_exact = sum(status.body_byte_exact is True for status in statuses)
    body_evaluated = sum(status.body_byte_exact is not None for status in statuses)
    lines = [
        "# Matching Status",
        "",
        (
            f"Relocation-aware encoded-body identity: **{body_exact}/{body_evaluated}** evaluated functions. "
            "Normalized exactness is reported separately below; recognized terminal padding is excluded."
        ),
        "",
        f"Scope: `{scope}` from `analysis/matching_scope.json`.",
        "",
        "Regenerate with `uv run crimson match checkpoint`.",
        "",
        (f"**{overall.matched_functions}/{overall.function_count}** functions matched exactly "
        f"(**{overall.function_percentage:.1%}**), "
        f"**{overall.matched_bytes}/{overall.byte_total}** code bytes "
        f"(**{overall.byte_percentage:.1%}**). Byte totals are manifest function "
        "extents with terminal padding trimmed."),
        "",
        (f"Fuzzy-weighted alignment is **{overall.fuzzy_weighted_bytes:.0f}/"
        f"{overall.byte_total}** code bytes "
        f"(**{overall.fuzzy_byte_percentage:.1%}**)."),
        "",
        (
            f"Remaining exact-match debt is "
            f"**{overall.function_count - overall.matched_functions} functions**, "
            f"**{overall.byte_total - overall.matched_bytes} code bytes**, and "
            f"**{overall.byte_total - overall.fuzzy_weighted_bytes:.0f} fuzzy-gap bytes**."
        ),
        "",
        (f"Reproducible candidates cover **{overall.candidate_functions}/{overall.function_count}** "
        f"functions and **{overall.candidate_bytes}/{overall.byte_total}** code bytes "
        f"(**{overall.candidate_byte_percentage:.1%}**). Candidate coverage includes exact "
        "matches and WIPs; it does not claim byte identity."),
        "",
    ]
    lines.extend(render_native_link_status_markdown(native_statuses))
    lines.extend(
        render_residual_frontier_markdown(
            collect_residual_frontier_rows(statuses),
        ),
    )
    if dispositions:
        disposition_counts = Counter(row["disposition"] for row in dispositions)
        disposition_summary = ", ".join(
            f"{count} {disposition}"
            for disposition, count in sorted(disposition_counts.items())
        )
        lines.extend(
            [
                "## Function dispositions",
                "",
                (
                    f"{len(dispositions)} audited functions ({disposition_summary}) are omitted "
                    "from this score and from default shards. Their analysis and archived "
                    "scratches remain available with `--scope all`."
                ),
                "",
                "| image | function | address | disposition | reason |",
                "|---|---|---:|---|---|",
            ],
        )
        for row in dispositions:
            lines.append(
                f"| {row['image']} | {row['function']} | 0x{row['address']:08x} | "
                f"{row['disposition']} | {row['reason']} |",
            )
        lines.append("")
    lines.extend(
        [
            "## Images",
            "",
            "| " + " | ".join(IMAGE_TOTALS_HEADER) + " |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ],
    )
    for row in render_image_total_rows(totals):
        lines.append("| " + " | ".join(row) + " |")
    for total in totals:
        image_statuses = [status for status in statuses if status.config.image == total.image]
        lines.extend(
            [
                "",
                f"## {total.image}",
                "",
                (f"**{total.matched_functions}/{total.function_count}** functions "
                f"(**{total.function_percentage:.1%}**), "
                f"**{total.matched_bytes}/{total.byte_total}** bytes "
                f"(**{total.byte_percentage:.1%}**), "
                f"**{total.fuzzy_weighted_bytes:.0f}/{total.byte_total}** fuzzy-weighted bytes "
                f"(**{total.fuzzy_byte_percentage:.1%}**), "
                f"**{total.candidate_functions}/{total.function_count}** reproducible candidates covering "
                f"**{total.candidate_bytes}/{total.byte_total}** bytes "
                f"(**{total.candidate_byte_percentage:.1%}**), "
                f"**{total.matched_scratches}/{total.scratch_count}** scratches verified."),
                "",
                "| state | function | address | bytes | fuzzy bytes | fuzzy gap | insns | match | prefix | refs ok/?/! | build | note |",
                "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|",
            ],
        )
        for row in render_status_rows(image_statuses):
            lines.append("| " + " | ".join((row[0], *row[2:])) + " |")
        if not image_statuses:
            lines.append("| - | - | - | - | - | - | - | - | - | - | - | no scratches |")
    lines.append("")
    return "\n".join(lines)
