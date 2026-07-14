from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shlex
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

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
DEFAULT_MATCH_JOBS = min(8, max(1, os.cpu_count() or 1))
CACHE_VERSION = 1

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SCN_CNT_CODE = 0x00000020
SYM_TYPE_FUNCTION = 0x20
PADDING_BYTES = b"\xcc\x90"
PADDING_LINE_TEXT = {
    "add byte [eax], al",
    "int3",
    "lea ecx, dword [ecx]",
    "nop",
}
BRANCH_TARGET_RE = re.compile(r"\bL([0-9a-f]+)\b")
LOCAL_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"\r\n]+)"', re.MULTILINE)
VC6_SINGLE_DELETE_UNWIND_KEY = "compiler:vc6-cxx-frame-handler:single-delete-unwind"
VC6_LOCAL_JUMP_TABLE_KEY = "compiler:vc6-local-jump-table"


def parse_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 0)


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
class ReferenceCatalog:
    names_by_address: dict[int, tuple[str, ...]]
    addresses_by_name: dict[str, tuple[int, ...]] = field(default_factory=dict)
    import_addresses: frozenset[int] = frozenset()

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
        addresses = self._addresses_for_name(
            lookup_name,
            imported=_is_import_symbol(symbol_name),
        )
        if len(addresses) == 1:
            keys.append(f"address:0x{addresses[0] + addend:08x}")
        return tuple(dict.fromkeys(keys))

    def knows_name(self, symbol_name: str) -> bool:
        return (
            len(
                self._addresses_for_name(
                    _symbol_lookup_name(symbol_name),
                    imported=_is_import_symbol(symbol_name),
                ),
            )
            == 1
        )

    def _addresses_for_name(self, name: str, *, imported: bool) -> tuple[int, ...]:
        addresses = self.addresses_by_name.get(name)
        if addresses is None:
            addresses = tuple(
                address
                for address, names in self.names_by_address.items()
                if any(_symbol_lookup_name(candidate) == name for candidate in names)
            )
        return tuple(address for address in addresses if (address in self.import_addresses) == imported)


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
    for function in manifest.functions:
        names.setdefault(function.address, []).append(function.name)
    raw_functions_path = functions_path or default_functions_path(manifest.image_name)
    if raw_functions_path.exists():
        for entry in json.loads(raw_functions_path.read_text(encoding="utf-8")):
            address = parse_int(entry["address"])
            name = str(entry["name"])
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
    if name_map_path is not None and name_map_path.exists():
        for entry in json.loads(name_map_path.read_text(encoding="utf-8")):
            if entry.get("program") != manifest.image_name:
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
            addresses_by_name.setdefault(_symbol_lookup_name(name), []).append(address)
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
) -> FunctionManifest:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    resolved_image_name = image_name or Path(path).parent.name
    name_overrides: dict[int, str] = {}
    if name_map_path is not None and name_map_path.exists():
        name_rows = json.loads(name_map_path.read_text(encoding="utf-8"))
        for row in name_rows:
            if row.get("program") != resolved_image_name:
                continue
            name_overrides[parse_int(row["address"])] = str(row["name"])
    functions: list[FunctionSymbol] = []
    for row in rows:
        if bool(row.get("external")) or bool(row.get("library")):
            continue
        address = parse_int(row["address"])
        end = parse_int(row["end"])
        functions.append(
            FunctionSymbol(
                name=name_overrides.get(address, str(row["name"])),
                address=address,
                end=end,
                size=int(row.get("size") or max(0, end - address)),
            ),
        )
    return FunctionManifest(
        image_name=resolved_image_name,
        image_base=_load_image_base(metadata_path),
        functions=tuple(sorted(functions, key=lambda function: function.address)),
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


@dataclass(frozen=True, slots=True)
class CoffSymbol:
    raw_index: int
    name: str
    value: int
    section_number: int
    symbol_type: int
    storage_class: int


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

    @property
    def target_span(self) -> str:
        return f"{self.target_start}:{self.target_end}"

    @property
    def candidate_span(self) -> str:
        return f"{self.candidate_start}:{self.candidate_end}"


@dataclass(frozen=True, slots=True)
class MatchDump:
    target_lines: tuple[DisassemblyLine, ...]
    candidate_lines: tuple[DisassemblyLine, ...]


def parse_coff_object(data: bytes) -> CoffObject:
    machine, section_count, _, symtab_offset, symbol_count, optional_header_size, _ = struct.unpack_from(
        "<HHIIIHH",
        data,
        0,
    )
    if machine != IMAGE_FILE_MACHINE_I386:
        raise ValueError(f"expected i386 COFF object, got machine 0x{machine:x}")

    string_table_offset = symtab_offset + symbol_count * 18

    def symbol_name(raw: bytes) -> str:
        if raw[:4] == b"\x00\x00\x00\x00":
            offset = string_table_offset + struct.unpack_from("<I", raw, 4)[0]
            end = data.index(b"\x00", offset)
            return data[offset:end].decode("latin1")
        return raw.rstrip(b"\x00").decode("latin1")

    symbols: list[CoffSymbol] = []
    index = 0
    while index < symbol_count:
        record = data[symtab_offset + index * 18 : symtab_offset + (index + 1) * 18]
        value, section_number, symbol_type, storage_class, aux_count = struct.unpack_from("<IhHBB", record, 8)
        symbols.append(
            CoffSymbol(
                raw_index=index,
                name=symbol_name(record[:8]),
                value=value,
                section_number=section_number,
                symbol_type=symbol_type,
                storage_class=storage_class,
            ),
        )
        index += 1 + aux_count

    sections: list[CoffSection] = []
    for section_index in range(section_count):
        header_offset = 20 + optional_header_size + section_index * 40
        name_raw = data[header_offset : header_offset + 8]
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
        relocations = tuple(
            CoffRelocation(*struct.unpack_from("<IIH", data, reloc_offset + i * 10)) for i in range(reloc_count)
        )
        sections.append(
            CoffSection(
                name=name_raw.rstrip(b"\x00").decode("latin1"),
                data=data[raw_offset : raw_offset + raw_size],
                characteristics=characteristics,
                relocations=relocations,
            ),
        )
    return CoffObject(sections=tuple(sections), symbols=tuple(symbols))


def _is_function_symbol(symbol: CoffSymbol) -> bool:
    return (
        symbol.section_number > 0
        and symbol.symbol_type & SYM_TYPE_FUNCTION != 0
        and symbol.storage_class in (IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC)
    )


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


def _local_jump_table_key(offsets: list[int]) -> str | None:
    if len(offsets) < 2:
        return None
    return f"{VC6_LOCAL_JUMP_TABLE_KEY}:" + ",".join(f"0x{offset:x}" for offset in offsets)


def _coff_local_jump_table_key(
    obj: CoffObject,
    function: CoffSymbol,
    table: CoffSymbol,
    addend: int = 0,
) -> str | None:
    """Describe a compiler-local absolute switch table by its function-relative targets."""

    if (
        not table.name.startswith("$L")
        or function.section_number <= 0
        or table.section_number != function.section_number
    ):
        return None
    section = obj.sections[table.section_number - 1]
    table_start = table.value + addend
    if table_start < function.value or table_start >= len(section.data):
        return None

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
    return _local_jump_table_key(offsets)


def _image_local_jump_table_key(
    image: LoadedImage | None,
    table_address: int,
    function_start: int,
    function_end: int,
) -> str | None:
    """Describe a linked absolute switch table by its function-relative targets."""

    if image is None or function_end <= function_start:
        return None
    offsets: list[int] = []
    for index in range(256):
        raw = _image_bytes(image, table_address + index * 4, 4)
        if raw is None:
            break
        destination = struct.unpack("<I", raw)[0]
        if destination < function_start or destination >= function_end:
            break
        offsets.append(destination - function_start)
    return _local_jump_table_key(offsets)


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


def extract_object_function(obj: CoffObject, name: str | None = None) -> ObjectFunction:
    candidates = [symbol for symbol in obj.symbols if _is_function_symbol(symbol)]
    if name is not None:
        candidates = [symbol for symbol in candidates if _symbol_matches(symbol.name, name)]
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
        if _is_function_symbol(symbol)
        and symbol.section_number == target.section_number
        and symbol.value > target.value
    )
    end = siblings[0] if siblings else len(section.data)
    symbols_by_raw_index = {symbol.raw_index: symbol for symbol in obj.symbols}
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
        if compiler_key := _coff_vc6_single_delete_unwind_key(obj, symbol):
            key = compiler_key
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
            ),
        )
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


def _printable_string_key(data: bytes) -> str | None:
    end = data.find(b"\x00", 0, 161)
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


def _format_memory_operand(insn, operand, masked_disp: bool) -> str:
    mem = operand.mem
    parts: list[str] = []
    if mem.base != 0:
        parts.append(insn.reg_name(mem.base))
    if mem.index != 0:
        parts.append(f"{insn.reg_name(mem.index)}*{mem.scale}")
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
        explained = reference.explained
        symbol_data = reference.symbol_data or b""
        if reference.symbol_name.startswith("??_C@") and (string_key := _printable_string_key(symbol_data)):
            keys = (string_key,)
            explained = True
        elif reference.symbol_name.startswith("__real@") and len(symbol_data) >= byte_count:
            keys = (f"bytes{byte_count}:{symbol_data[:byte_count].hex()}",)
            explained = True
        elif reference.key is not None and reference.key.startswith("compiler:vc6-"):
            pass
        elif reference_catalog is not None:
            if reference_catalog.knows_name(reference.symbol_name):
                keys = reference_catalog.keys_for_object_reference(
                    reference.symbol_name,
                    reference.addend or 0,
                )
            else:
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
        if image is not None:
            available = image.mapped[value - image.image_base :] if image.image_base <= value else b""
            if string_key := _printable_string_key(available):
                keys.append(string_key)
            if byte_count is not None and (raw := _image_bytes(image, value, byte_count)) is not None:
                keys.append(f"bytes{byte_count}:{raw.hex()}")
        if compiler_key := _image_vc6_single_delete_unwind_key(image, reference_catalog, value):
            keys.append(compiler_key)
        if jump_table_key := _image_local_jump_table_key(
            image,
            value,
            base_address,
            base_address + len(data),
        ):
            keys.append(jump_table_key)
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
    for insn in md.disasm(data, base_address):
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
                if imm_masked:
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
                masked_references=tuple(masked_references),
            ),
        )
    return _strip_trailing_padding_lines(tuple(lines))


def _strip_trailing_padding_lines(lines: tuple[DisassemblyLine, ...]) -> tuple[DisassemblyLine, ...]:
    trim_start = len(lines)
    while trim_start > 0 and lines[trim_start - 1].text in PADDING_LINE_TEXT:
        trim_start -= 1
    if trim_start == len(lines) or trim_start == 0:
        return lines
    if not lines[trim_start - 1].text.startswith("ret"):
        return lines

    padding_offsets = {line.offset for line in lines[trim_start:]}
    for line in lines[:trim_start]:
        targets = {int(match.group(1), 16) for match in BRANCH_TARGET_RE.finditer(line.text)}
        if targets & padding_offsets:
            return lines
    return lines[:trim_start]


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


def match_function(
    target_data: bytes,
    candidate: ObjectFunction,
    *,
    image: LoadedImage,
    target_va: int,
    reference_catalog: ReferenceCatalog | None = None,
) -> MatchResult:
    address_range = (image.image_base, image.image_base + image.size_of_image)
    target_disassembly = disassemble_normalized_function(
        target_data,
        address_range=address_range,
        base_address=target_va,
        reference_catalog=reference_catalog,
        image=image,
    )
    candidate_disassembly = disassemble_normalized_function(
        candidate.data,
        relocation_offsets=candidate.relocation_offsets,
        relocation_references=candidate.relocation_references,
        address_range=address_range,
        reference_catalog=reference_catalog,
        image=image,
    )
    target_lines = tuple(line.text for line in target_disassembly)
    candidate_lines = tuple(line.text for line in candidate_disassembly)
    ratio = difflib.SequenceMatcher(a=target_lines, b=candidate_lines, autojunk=False).ratio()
    return MatchResult(
        ratio=ratio,
        prefix_instructions=common_prefix_length(target_lines, candidate_lines),
        target_lines=target_lines,
        candidate_lines=candidate_lines,
        target_disassembly=target_disassembly,
        candidate_disassembly=candidate_disassembly,
        masked_operand_audit=audit_masked_operands(target_disassembly, candidate_disassembly),
    )


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
            ),
        )
    return regions


def run_match(
    *,
    obj_path: Path,
    function: str,
    image_path: Path = DEFAULT_IMAGE_PATH,
    functions_path: Path = DEFAULT_FUNCTIONS_PATH,
    metadata_path: Path | None = DEFAULT_METADATA_PATH,
    symbol_name: str | None = None,
    end_va: int | None = None,
) -> MatchResult:
    manifest = load_function_manifest(functions_path, metadata_path=metadata_path, image_name=image_path.name)
    obj = parse_coff_object(Path(obj_path).read_bytes())
    candidate = extract_object_function(obj, symbol_name)
    _, start, end = resolve_function(manifest, function, end_override=end_va)
    image = load_image(image_path, manifest.image_base)
    catalog = load_reference_catalog(manifest, functions_path=functions_path)
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
    end_va: int | None = None,
) -> MatchDump:
    manifest = load_function_manifest(functions_path, metadata_path=metadata_path, image_name=image_path.name)
    obj = parse_coff_object(Path(obj_path).read_bytes())
    candidate = extract_object_function(obj, symbol_name)
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

    @property
    def state(self) -> str:
        if self.ratio is None:
            return "error"
        if self.ratio != 1.0:
            return "wip"
        if self.masked_unresolved or self.masked_mismatches:
            return "audit"
        return "match"


@dataclass(frozen=True, slots=True)
class ImageTotals:
    image: str
    function_count: int
    byte_total: int
    matched_functions: int
    matched_bytes: int
    scratch_count: int
    matched_scratches: int

    @property
    def byte_percentage(self) -> float:
        return self.matched_bytes / self.byte_total if self.byte_total else 0.0


def load_scratch_config(directory: Path) -> ScratchConfig:
    values: dict[str, str] = {}
    for token in shlex.split((directory / "scratch.conf").read_text(encoding="utf-8"), comments=True):
        key, _, value = token.partition("=")
        if value:
            values[key] = value
    if "FUNCTION" not in values:
        raise ValueError(f"{directory}/scratch.conf must set FUNCTION")
    return ScratchConfig(
        directory=directory,
        function=values["FUNCTION"],
        image=values.get("IMAGE", DEFAULT_SCRATCH_IMAGE),
        compiler=values.get("COMPILER", DEFAULT_SCRATCH_COMPILER),
        cflags=values.get("CFLAGS", DEFAULT_SCRATCH_CFLAGS),
        source=values.get("SOURCE", "scratch.cpp"),
        end_va=int(values["END"], 0) if "END" in values else None,
        symbol=values.get("SYMBOL"),
        note=values.get("NOTE", ""),
    )


FORBIDDEN_SOURCE_PATTERNS = (
    re.compile(r"\b__asm\b"),
    re.compile(r"\b_asm\b"),
    re.compile(r"__declspec\s*\(\s*naked\s*\)", re.IGNORECASE),
)


def validate_scratch_source(source: Path) -> None:
    text = source.read_text(encoding="latin1")
    for pattern in FORBIDDEN_SOURCE_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"{source}: inline assembly/naked functions are not allowed in scratches (no fakematching)",
            )


def _mtime_ns(path: Path) -> int | None:
    return path.stat().st_mtime_ns if path.exists() else None


class _ScratchIncludeResolver:
    def __init__(self, match_root: Path, *, repo_root: Path = REPO_ROOT) -> None:
        self.include_dirs = (
            match_root / "include",
            repo_root / "third_party" / "headers",
        )
        self._direct_dependencies: dict[tuple[Path, bool], tuple[Path, ...]] = {}

    def direct_dependencies(self, including_path: Path, *, source: bool) -> tuple[Path, ...]:
        cache_key = (including_path, source)
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
            candidates = [include_dir / include_name for include_dir in self.include_dirs]
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
    resolver = resolver or _ScratchIncludeResolver(match_root)
    source = config.directory / config.source
    pending = [source]
    visited = {source}
    headers: set[Path] = set()
    while pending:
        including_path = pending.pop()
        for dependency in resolver.direct_dependencies(including_path, source=including_path == source):
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
    return (
        config.directory / config.source,
        config.directory / "scratch.conf",
        match_root / "cl.sh",
        _compiler_executable_path(config, match_root),
        *_scratch_include_headers(config, match_root, resolver=include_resolver),
    )


def _scratch_build_key(
    config: ScratchConfig,
    match_root: Path,
    *,
    include_resolver: _ScratchIncludeResolver | None = None,
) -> dict[str, Any]:
    dependencies = _scratch_build_dependencies(config, match_root, include_resolver=include_resolver)
    return {
        "compiler": config.compiler,
        "argv": list(_scratch_compile_argv(config, match_root)),
        "dependencies": [
            [str(path.relative_to(match_root) if path.is_relative_to(match_root) else path), _mtime_ns(path)]
            for path in dependencies
        ],
    }


def _scratch_profile_digest(config: ScratchConfig) -> str:
    payload = {
        "compiler": config.compiler,
        "cflags": shlex.split(config.cflags),
        "source": config.source,
        "image": config.image,
        "function": config.function,
        "end_va": config.end_va,
        "symbol": config.symbol,
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _scratch_build_directory(config: ScratchConfig) -> Path:
    return config.directory / "build" / config.compiler / _scratch_profile_digest(config)


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
) -> Path:
    import shutil
    import subprocess
    import tempfile

    match_root = match_root.resolve()
    source = config.directory / config.source
    validate_scratch_source(source)
    build_dir = _scratch_build_directory(config)
    obj_name = Path(config.source).with_suffix(".obj").name
    obj_path = build_dir / obj_name
    if _scratch_object_is_current(
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
        shutil.copyfile(source, temp_source)
        completed = subprocess.run(
            command,
            cwd=temp_dir,
            env={**os.environ, "MSVC_VER": config.compiler},
            capture_output=True,
            text=True,
            check=False,
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


def _paths_for_image(image: str) -> tuple[Path, Path, Path]:
    return default_image_path(image), default_functions_path(image), default_metadata_path(image)


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
        },
        "image_mtime": _mtime_ns(image_path),
        "matcher_mtime": _mtime_ns(Path(__file__)),
        "manifest": _manifest_digest(manifest),
        "data_map_mtime": _mtime_ns(DEFAULT_DATA_MAP_PATH),
        "name_map_mtime": _mtime_ns(DEFAULT_NAME_MAP_PATH),
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
        "target_size": status.target_size,
        "ratio": status.ratio,
        "prefix_instructions": status.prefix_instructions,
        "target_instructions": status.target_instructions,
        "candidate_instructions": status.candidate_instructions,
        "error": status.error,
        "masked_ok": status.masked_ok,
        "masked_unresolved": status.masked_unresolved,
        "masked_mismatches": status.masked_mismatches,
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
) -> list[ScratchStatus]:
    if jobs < 1:
        raise ValueError("jobs must be positive")
    match_root = match_root.resolve()

    configs: list[ScratchConfig] = []
    for conf_path in sorted(match_root.glob("scratches/*/scratch.conf")):
        config = load_scratch_config(conf_path.parent)
        if compiler is not None or cflags is not None:
            config = replace(config, compiler=compiler or config.compiler, cflags=cflags or config.cflags)
        configs.append(config)

    manifest_cache: dict[str, FunctionManifest] = {}
    catalog_cache: dict[str, ReferenceCatalog] = {}
    for image_name in {config.image for config in configs}:
        _, functions_path, metadata_path = _paths_for_image(image_name)
        manifest_cache[image_name] = load_function_manifest(
            functions_path,
            metadata_path=metadata_path,
            image_name=image_name,
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
        cached = _load_cached_status(
            config,
            address=address,
            image_path=image_path,
            manifest=manifest,
            match_root=match_root,
            include_resolver=include_resolver,
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
            obj_path = compile_scratch(config, match_root, include_resolver=include_resolver)
            obj = parse_coff_object(obj_path.read_bytes())
            candidate = extract_object_function(obj, config.symbol)
            result = match_function(
                target_data,
                candidate,
                image=image,
                target_va=start,
                reference_catalog=catalog_cache[config.image],
            )
            status = ScratchStatus(
                config=config,
                address=function.address,
                target_size=len(target_data),
                ratio=result.ratio,
                prefix_instructions=result.prefix_instructions,
                target_instructions=len(result.target_lines),
                candidate_instructions=len(result.candidate_lines),
                error=None,
                masked_ok=result.masked_operand_audit.ok_count,
                masked_unresolved=result.masked_operand_audit.unresolved_count,
                masked_mismatches=result.masked_operand_audit.mismatch_count,
                audit=result.masked_operand_audit,
            )
            _store_cached_status(
                status,
                image_path=image_path,
                manifest=manifest,
                match_root=match_root,
                include_resolver=include_resolver,
            )
            return status
        except Exception as exc:
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
                error=str(exc).splitlines()[0] if str(exc) else type(exc).__name__,
            )

    if jobs == 1 or len(uncached) < 2:
        matched = list(map(match_config, uncached))
    else:
        with ThreadPoolExecutor(max_workers=min(jobs, len(uncached))) as executor:
            matched = list(executor.map(match_config, uncached))
    for status in matched:
        statuses_by_directory[status.config.directory] = status
    return [statuses_by_directory[config.directory] for config in configs]


STATUS_HEADER = ("state", "image", "function", "address", "bytes", "insns", "match", "prefix", "refs", "build", "note")
IMAGE_TOTALS_HEADER = ("image", "functions", "bytes", "code", "scratches")


def collect_image_totals(statuses: list[ScratchStatus]) -> list[ImageTotals]:
    totals: list[ImageTotals] = []
    images = sorted({*TRACKED_IMAGE_NAMES, *(status.config.image for status in statuses)})
    for image_name in images:
        image_path, functions_path, metadata_path = _paths_for_image(image_name)
        manifest = load_function_manifest(
            functions_path,
            metadata_path=metadata_path,
            image_name=image_name,
        )
        image = load_image(image_path, manifest.image_base)
        byte_total = sum(len(image.function_bytes(function.address, function.end)) for function in manifest.functions)
        image_statuses = [status for status in statuses if status.config.image == image_name]
        matched_by_function: dict[int, int] = {}
        for status in image_statuses:
            if status.state == "match":
                matched_by_function[status.address] = max(
                    matched_by_function.get(status.address, 0),
                    status.target_size,
                )
        totals.append(
            ImageTotals(
                image=image_name,
                function_count=len(manifest.functions),
                byte_total=byte_total,
                matched_functions=len(matched_by_function),
                matched_bytes=sum(matched_by_function.values()),
                scratch_count=len(image_statuses),
                matched_scratches=sum(1 for status in image_statuses if status.state == "match"),
            ),
        )
    return totals


def render_status_rows(statuses: list[ScratchStatus]) -> list[tuple[str, ...]]:
    rows = []
    default_build = f"{DEFAULT_SCRATCH_COMPILER} {DEFAULT_SCRATCH_CFLAGS}"
    for status in sorted(statuses, key=lambda item: (item.config.image, item.address, item.config.function)):
        ratio = f"{status.ratio:.2%}" if status.ratio is not None else "-"
        insns = f"{status.candidate_instructions}/{status.target_instructions}" if status.ratio is not None else "-"
        prefix = f"{status.prefix_instructions}/{status.target_instructions}" if status.ratio is not None else "-"
        refs = (
            f"{status.masked_ok}/{status.masked_unresolved}/{status.masked_mismatches}"
            if status.ratio is not None
            else "-"
        )
        build = f"{status.config.compiler} {status.config.cflags}"
        rows.append(
            (
                status.state,
                status.config.image,
                status.config.function,
                f"0x{status.address:08x}" if status.address else "-",
                str(status.target_size) if status.target_size else "-",
                insns,
                ratio,
                prefix,
                refs,
                "" if build == default_build else build,
                status.error or status.config.note,
            ),
        )
    return rows


def render_image_total_rows(totals: list[ImageTotals]) -> list[tuple[str, ...]]:
    return [
        (
            total.image,
            f"{total.matched_functions}/{total.function_count}",
            f"{total.matched_bytes}/{total.byte_total}",
            f"{total.byte_percentage:.1%}",
            f"{total.matched_scratches}/{total.scratch_count}",
        )
        for total in totals
    ]


def _overall_totals(totals: list[ImageTotals]) -> ImageTotals:
    return ImageTotals(
        image="all",
        function_count=sum(total.function_count for total in totals),
        byte_total=sum(total.byte_total for total in totals),
        matched_functions=sum(total.matched_functions for total in totals),
        matched_bytes=sum(total.matched_bytes for total in totals),
        scratch_count=sum(total.scratch_count for total in totals),
        matched_scratches=sum(total.matched_scratches for total in totals),
    )


def _image_summary(total: ImageTotals) -> str:
    return (
        f"{total.image}: {total.matched_functions}/{total.function_count} functions, "
        f"{total.matched_bytes}/{total.byte_total} bytes "
        f"({total.byte_percentage:.1%}) matched; "
        f"{total.matched_scratches}/{total.scratch_count} scratches verified"
    )


def render_status_table(statuses: list[ScratchStatus], totals: list[ImageTotals]) -> str:
    rows = [STATUS_HEADER, *render_status_rows(statuses)]
    widths = [max(len(row[column]) for row in rows) for column in range(len(STATUS_HEADER))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]
    overall = _overall_totals(totals)
    lines.append(
        f"\nall images: {overall.matched_functions}/{overall.function_count} functions, "
        f"{overall.matched_bytes}/{overall.byte_total} bytes "
        f"({overall.byte_percentage:.1%}) matched; "
        f"{overall.matched_scratches}/{overall.scratch_count} scratches verified",
    )
    lines.append("by image:")
    lines.extend(_image_summary(total) for total in totals)
    return "\n".join(lines)


def render_status_markdown(statuses: list[ScratchStatus], totals: list[ImageTotals]) -> str:
    overall = _overall_totals(totals)
    lines = [
        "# Matching Status",
        "",
        "Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.",
        "",
        f"**{overall.matched_functions}/{overall.function_count}** functions matched, "
        f"**{overall.matched_bytes}/{overall.byte_total}** code bytes "
        f"(**{overall.byte_percentage:.1%}**). Byte totals are manifest function "
        "extents with terminal padding trimmed.",
        "",
        "## Images",
        "",
        "| " + " | ".join(IMAGE_TOTALS_HEADER) + " |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in render_image_total_rows(totals):
        lines.append("| " + " | ".join(row) + " |")
    for total in totals:
        image_statuses = [status for status in statuses if status.config.image == total.image]
        lines.extend(
            [
                "",
                f"## {total.image}",
                "",
                f"**{total.matched_functions}/{total.function_count}** functions, "
                f"**{total.matched_bytes}/{total.byte_total}** bytes "
                f"(**{total.byte_percentage:.1%}**), "
                f"**{total.matched_scratches}/{total.scratch_count}** scratches verified.",
                "",
                "| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |",
                "|---|---|---|---:|---:|---:|---:|---:|---|---|",
            ],
        )
        for row in render_status_rows(image_statuses):
            lines.append("| " + " | ".join((row[0], *row[2:])) + " |")
        if not image_statuses:
            lines.append("| - | - | - | - | - | - | - | - | - | no scratches |")
    lines.append("")
    return "\n".join(lines)
