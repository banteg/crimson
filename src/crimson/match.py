from __future__ import annotations

import difflib
import json
import re
import shlex
import struct
from dataclasses import dataclass, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VERSION = "1.9.93-gog"
DEFAULT_GAME_DIR = REPO_ROOT / "game_bins" / "crimsonland" / DEFAULT_VERSION
DEFAULT_IMAGE_NAME = "crimsonland.exe"
DEFAULT_MATCH_ROOT = REPO_ROOT / "tools" / "match"
DEFAULT_FUNCTIONS_PATH = REPO_ROOT / "analysis" / "ida" / "raw" / DEFAULT_IMAGE_NAME / "functions.json"
DEFAULT_METADATA_PATH = REPO_ROOT / "analysis" / "ida" / "raw" / DEFAULT_IMAGE_NAME / "metadata.json"
DEFAULT_IMAGE_PATH = DEFAULT_GAME_DIR / DEFAULT_IMAGE_NAME

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
) -> FunctionManifest:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    functions: list[FunctionSymbol] = []
    for row in rows:
        if bool(row.get("external")) or bool(row.get("library")):
            continue
        address = parse_int(row["address"])
        end = parse_int(row["end"])
        functions.append(
            FunctionSymbol(
                name=str(row["name"]),
                address=address,
                end=end,
                size=int(row.get("size") or max(0, end - address)),
            ),
        )
    return FunctionManifest(
        image_name=image_name or Path(path).parent.name,
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


@dataclass(frozen=True, slots=True)
class MatchResult:
    ratio: float
    prefix_instructions: int
    target_lines: tuple[str, ...]
    candidate_lines: tuple[str, ...]

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
        "<HHIIIHH", data, 0,
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
    return wanted in symbol_name


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
        if _is_function_symbol(symbol) and symbol.section_number == target.section_number and symbol.value > target.value
    )
    end = siblings[0] if siblings else len(section.data)
    relocation_offsets = frozenset(
        relocation.virtual_address - target.value
        for relocation in section.relocations
        if target.value <= relocation.virtual_address < end
    )
    return ObjectFunction(
        name=target.name,
        data=section.data[target.value : end].rstrip(PADDING_BYTES),
        relocation_offsets=relocation_offsets,
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
    address_range: tuple[int, int] | None = None,
    base_address: int = 0,
) -> tuple[DisassemblyLine, ...]:
    try:
        import capstone
    except ModuleNotFoundError as exc:
        raise RuntimeError("capstone is required for matching; run `uv sync --dev`") from exc

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    relocation_offsets = relocation_offsets or frozenset()
    size = len(data)

    def is_masked_value(value: int) -> bool:
        return address_range is not None and address_range[0] <= value < address_range[1]

    lines: list[DisassemblyLine] = []
    for insn in md.disasm(data, base_address):
        insn_offset = insn.address - base_address
        is_branch = capstone.CS_GRP_JUMP in insn.groups or capstone.CS_GRP_CALL in insn.groups
        imm_masked = (
            any(
                insn_offset + rel_offset in relocation_offsets
                for rel_offset in range(insn.imm_offset, insn.imm_offset + max(insn.imm_size, 1))
            )
            if insn.imm_offset
            else False
        )
        disp_masked = (
            any(
                insn_offset + rel_offset in relocation_offsets
                for rel_offset in range(insn.disp_offset, insn.disp_offset + max(insn.disp_size, 1))
            )
            if insn.disp_offset
            else False
        )

        operands: list[str] = []
        for operand in insn.operands:
            if operand.type == capstone.x86.X86_OP_REG:
                operands.append(insn.reg_name(operand.reg))
            elif operand.type == capstone.x86.X86_OP_IMM:
                value = operand.imm
                target_offset = value - base_address
                if imm_masked:
                    operands.append("ADDR")
                elif is_branch and 0 <= target_offset < size:
                    operands.append(f"L{target_offset:x}")
                elif is_masked_value(value):
                    operands.append("ADDR")
                else:
                    operands.append(f"0x{value:x}" if value >= 0 else f"-0x{-value:x}")
            elif operand.type == capstone.x86.X86_OP_MEM:
                masked = disp_masked or is_masked_value(operand.mem.disp)
                operands.append(_format_memory_operand(insn, operand, masked))
            else:
                operands.append("?")
        lines.append(
            DisassemblyLine(
                offset=insn_offset,
                address=insn.address,
                text=f"{insn.mnemonic} {', '.join(operands)}".strip(),
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


def match_function(
    target_data: bytes,
    candidate: ObjectFunction,
    *,
    image: LoadedImage,
    target_va: int,
) -> MatchResult:
    address_range = (image.image_base, image.image_base + image.size_of_image)
    target_lines = normalize_function(
        target_data,
        address_range=address_range,
        base_address=target_va,
    )
    candidate_lines = normalize_function(
        candidate.data,
        relocation_offsets=candidate.relocation_offsets,
        address_range=address_range,
    )
    ratio = difflib.SequenceMatcher(a=target_lines, b=candidate_lines, autojunk=False).ratio()
    return MatchResult(
        ratio=ratio,
        prefix_instructions=common_prefix_length(target_lines, candidate_lines),
        target_lines=target_lines,
        candidate_lines=candidate_lines,
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
            (pending_equal[1] - pending_equal[0]) <= context
            or (pending_equal[3] - pending_equal[2]) <= context
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
    return match_function(image.function_bytes(start, end), candidate, image=image, target_va=start)


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
    address_range = (image.image_base, image.image_base + image.size_of_image)
    return MatchDump(
        target_lines=disassemble_normalized_function(
            image.function_bytes(start, end),
            address_range=address_range,
            base_address=start,
        ),
        candidate_lines=disassemble_normalized_function(
            candidate.data,
            relocation_offsets=candidate.relocation_offsets,
            address_range=address_range,
        ),
    )


DEFAULT_SCRATCH_IMAGE = DEFAULT_IMAGE_NAME
DEFAULT_SCRATCH_COMPILER = "msvc6.5"
DEFAULT_SCRATCH_CFLAGS = "/O2 /G6 /W3 /GR-"


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

    @property
    def state(self) -> str:
        if self.ratio is None:
            return "error"
        if self.ratio == 1.0:
            return "match"
        return "wip"


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
            raise ValueError(f"{source}: inline assembly/naked functions are not allowed in scratches (no fakematching)")


def compile_scratch(config: ScratchConfig, match_root: Path = DEFAULT_MATCH_ROOT) -> Path:
    import os
    import shutil
    import subprocess

    source = config.directory / config.source
    validate_scratch_source(source)
    build_dir = config.directory / "build" / config.compiler
    obj_name = Path(config.source).with_suffix(".obj").name
    obj_path = build_dir / obj_name
    if obj_path.exists() and obj_path.stat().st_mtime >= source.stat().st_mtime:
        return obj_path

    build_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(source, build_dir / Path(config.source).name)
    command = [str(match_root / "cl.sh"), "/c", *shlex.split(config.cflags), Path(config.source).name]
    completed = subprocess.run(
        command,
        cwd=build_dir,
        env={**os.environ, "MSVC_VER": config.compiler},
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or not obj_path.exists():
        raise RuntimeError(f"cl failed:\n{completed.stdout}{completed.stderr}")
    return obj_path


def _paths_for_image(image: str) -> tuple[Path, Path, Path]:
    return default_image_path(image), default_functions_path(image), default_metadata_path(image)


def collect_scratch_statuses(
    match_root: Path = DEFAULT_MATCH_ROOT,
    *,
    compiler: str | None = None,
    cflags: str | None = None,
) -> list[ScratchStatus]:
    statuses: list[ScratchStatus] = []
    manifest_cache: dict[str, FunctionManifest] = {}
    image_cache: dict[str, LoadedImage] = {}
    for conf_path in sorted(match_root.glob("scratches/*/scratch.conf")):
        config = load_scratch_config(conf_path.parent)
        if compiler is not None or cflags is not None:
            config = replace(
                config,
                compiler=compiler or config.compiler,
                cflags=cflags or config.cflags,
            )
        image_path, functions_path, metadata_path = _paths_for_image(config.image)
        if config.image not in manifest_cache:
            manifest_cache[config.image] = load_function_manifest(
                functions_path,
                metadata_path=metadata_path,
                image_name=config.image,
            )
        manifest = manifest_cache[config.image]
        try:
            function, start, end = resolve_function(manifest, config.function, end_override=config.end_va)
            if config.image not in image_cache:
                image_cache[config.image] = load_image(image_path, manifest.image_base)
            image = image_cache[config.image]
            target_data = image.function_bytes(start, end)
            obj_path = compile_scratch(config, match_root)
            obj = parse_coff_object(obj_path.read_bytes())
            candidate = extract_object_function(obj, config.symbol)
            result = match_function(target_data, candidate, image=image, target_va=start)
            statuses.append(
                ScratchStatus(
                    config=config,
                    address=function.address,
                    target_size=len(target_data),
                    ratio=result.ratio,
                    prefix_instructions=result.prefix_instructions,
                    target_instructions=len(result.target_lines),
                    candidate_instructions=len(result.candidate_lines),
                    error=None,
                ),
            )
        except Exception as exc:
            statuses.append(
                ScratchStatus(
                    config=config,
                    address=0,
                    target_size=0,
                    ratio=None,
                    prefix_instructions=0,
                    target_instructions=0,
                    candidate_instructions=0,
                    error=str(exc).splitlines()[0] if str(exc) else type(exc).__name__,
                ),
            )
    return statuses


STATUS_HEADER = ("state", "image", "function", "address", "bytes", "insns", "match", "prefix", "build", "note")


def render_status_rows(statuses: list[ScratchStatus]) -> list[tuple[str, ...]]:
    rows = []
    default_build = f"{DEFAULT_SCRATCH_COMPILER} {DEFAULT_SCRATCH_CFLAGS}"
    for status in sorted(statuses, key=lambda item: (item.config.image, item.address, item.config.function)):
        ratio = f"{status.ratio:.2%}" if status.ratio is not None else "-"
        insns = f"{status.candidate_instructions}/{status.target_instructions}" if status.ratio is not None else "-"
        prefix = f"{status.prefix_instructions}/{status.target_instructions}" if status.ratio is not None else "-"
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
                "" if build == default_build else build,
                status.error or status.config.note,
            ),
        )
    return rows


def render_status_summary_rows(statuses: list[ScratchStatus]) -> list[tuple[str, str, str]]:
    rows = []
    for image in sorted({status.config.image for status in statuses}):
        image_statuses = [status for status in statuses if status.config.image == image]
        matched = sum(1 for status in image_statuses if status.state == "match")
        rows.append((image, str(matched), str(len(image_statuses))))
    return rows


def render_status_table(statuses: list[ScratchStatus]) -> str:
    rows = [STATUS_HEADER, *render_status_rows(statuses)]
    widths = [max(len(row[column]) for row in rows) for column in range(len(STATUS_HEADER))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]
    matched = sum(1 for status in statuses if status.state == "match")
    lines.append(f"\nmatched scratches: {matched}/{len(statuses)}")
    summary_rows = [("image", "matched", "scratches"), *render_status_summary_rows(statuses)]
    if len(summary_rows) > 1:
        summary_widths = [max(len(row[column]) for row in summary_rows) for column in range(3)]
        lines.append("by image:")
        lines.extend(
            "  ".join(cell.ljust(width) for cell, width in zip(row, summary_widths)).rstrip()
            for row in summary_rows
        )
    return "\n".join(lines)


def render_status_markdown(statuses: list[ScratchStatus]) -> str:
    matched = sum(1 for status in statuses if status.state == "match")
    lines = [
        "# Matching Status",
        "",
        "Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.",
        "",
        f"Matched scratches: **{matched}/{len(statuses)}**.",
        "",
        "## Images",
        "",
        "| image | matched | scratches |",
        "|---|---:|---:|",
    ]
    for image, matched_count, total_count in render_status_summary_rows(statuses):
        lines.append(f"| {image} | {matched_count} | {total_count} |")
    lines.extend(
        [
            "",
            "## Scratches",
            "",
            "| state | image | function | address | bytes | insns | match | prefix | build | note |",
            "|---|---|---|---|---:|---:|---:|---:|---|---|",
        ],
    )
    for row in render_status_rows(statuses):
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return "\n".join(lines)
