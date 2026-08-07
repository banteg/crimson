from __future__ import annotations

import hashlib
import os
import re
import shlex
import struct
import tempfile
from collections import Counter, defaultdict
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path

from . import match as matchlib

AR_MAGIC = b"!<arch>\n"
AR_HEADER_SIZE = 60
AR_HEADER_TRAILER = b"`\n"


@dataclass(frozen=True, slots=True)
class CoffArchiveMember:
    name: str
    data: bytes


@dataclass(frozen=True, slots=True)
class ArchiveCandidate:
    member: str
    symbol: str
    size: int
    relocation_count: int
    compiler_id: int | None = None

    @property
    def compiler_product(self) -> int | None:
        return None if self.compiler_id is None else self.compiler_id >> 16

    @property
    def compiler_build(self) -> int | None:
        return None if self.compiler_id is None else self.compiler_id & 0xFFFF


@dataclass(frozen=True, slots=True)
class ArchiveFunctionMatch:
    address: int
    end: int
    name: str
    size: int
    instruction_count: int
    candidates: tuple[ArchiveCandidate, ...]

    @property
    def unique(self) -> bool:
        return len(self.candidates) == 1

    @property
    def symbol_unique(self) -> bool:
        return len({candidate.symbol for candidate in self.candidates}) == 1


@dataclass(frozen=True, slots=True)
class ArchiveMatchReport:
    archive: Path
    archive_sha256: str
    archive_members: int
    object_members: int
    object_functions: int
    image: Path
    range_start: int
    range_end: int
    target_functions: int
    target_bytes: int
    matched_functions: int
    matched_bytes: int
    unique_functions: int
    unique_bytes: int
    matches: tuple[ArchiveFunctionMatch, ...]
    excluded_target_functions: int = 0
    excluded_target_bytes: int = 0

    @property
    def member_counts(self) -> tuple[tuple[str, int], ...]:
        counts = Counter(match.candidates[0].member for match in self.matches if match.unique)
        return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    @property
    def symbol_unique_functions(self) -> int:
        return sum(match.symbol_unique for match in self.matches)

    @property
    def symbol_unique_bytes(self) -> int:
        return sum(match.size for match in self.matches if match.symbol_unique)


@dataclass(frozen=True, slots=True)
class ArchiveScratchWrite:
    directory: Path
    match: ArchiveFunctionMatch
    candidate: ArchiveCandidate
    reference_aliases: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ArchiveReferenceBinding:
    lookup_name: str
    object_symbols: tuple[str, ...]
    target_address: int
    occurrences: int
    addends: tuple[int, ...]
    functions: tuple[tuple[int, str], ...]
    members: tuple[str, ...]
    target_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _ArchiveReferenceEvidence:
    match_address: int
    match_name: str
    member: str
    object_symbol: str
    lookup_name: str
    target_address: int
    addend: int


@dataclass(frozen=True, slots=True)
class _NormalizedArchiveFunction:
    candidate: ArchiveCandidate
    data: bytes
    relocation_offsets: frozenset[int]


def _parse_decimal(raw: bytes, *, field: str) -> int:
    try:
        return int(raw.decode("ascii").strip() or "0", 10)
    except ValueError as exc:
        raise ValueError(f"invalid ar {field}: {raw!r}") from exc


def _long_member_name(table: bytes, offset: int) -> str:
    if not 0 <= offset < len(table):
        raise ValueError(f"ar long-name offset outside table: {offset}")
    slash_end = table.find(b"/\n", offset)
    nul_end = table.find(b"\x00", offset)
    ends = [end for end in (slash_end, nul_end) if end >= 0]
    end = min(ends, default=len(table))
    return table[offset:end].decode("latin1")


def parse_coff_archive(data: bytes) -> tuple[CoffArchiveMember, ...]:
    """Parse Microsoft/GNU ar members, including the COFF long-name table."""
    if not data.startswith(AR_MAGIC):
        raise ValueError("expected a COFF ar archive")

    raw_members: list[tuple[bytes, bytes]] = []
    offset = len(AR_MAGIC)
    while offset < len(data):
        if offset + AR_HEADER_SIZE > len(data):
            raise ValueError(f"truncated ar member header at 0x{offset:x}")
        header = data[offset : offset + AR_HEADER_SIZE]
        if header[58:60] != AR_HEADER_TRAILER:
            raise ValueError(f"invalid ar member trailer at 0x{offset:x}")
        size = _parse_decimal(header[48:58], field="member size")
        payload_start = offset + AR_HEADER_SIZE
        payload_end = payload_start + size
        if payload_end > len(data):
            raise ValueError(f"truncated ar member payload at 0x{offset:x}")
        raw_members.append((header[:16].rstrip(), data[payload_start:payload_end]))
        offset = payload_end + (size & 1)

    long_names = next((payload for name, payload in raw_members if name == b"//"), b"")
    members: list[CoffArchiveMember] = []
    for raw_name, raw_payload in raw_members:
        name_field = raw_name.decode("latin1")
        payload = raw_payload
        if name_field.startswith("#1/"):
            name_size = int(name_field[3:], 10)
            if name_size > len(payload):
                raise ValueError(f"truncated BSD ar member name: {name_field}")
            name = payload[:name_size].rstrip(b"\x00").decode("latin1")
            payload = payload[name_size:]
        elif name_field.startswith("/") and name_field[1:].isdigit():
            name = _long_member_name(long_names, int(name_field[1:], 10))
        elif name_field in {"/", "//"}:
            name = name_field
        else:
            name = name_field.removesuffix("/")
        members.append(CoffArchiveMember(name=name, data=payload))
    return tuple(members)


def _archive_function_index(
    members: tuple[CoffArchiveMember, ...],
) -> tuple[dict[tuple[int, int], list[_NormalizedArchiveFunction]], int, int]:
    index: dict[tuple[int, int], list[_NormalizedArchiveFunction]] = defaultdict(list)
    object_members = 0
    object_functions = 0
    for member in members:
        if member.name in {"/", "//"}:
            continue
        try:
            obj = matchlib.parse_coff_object(member.data)
        except (IndexError, struct.error, ValueError):
            continue
        object_members += 1
        compiler_ids = {
            symbol.value
            for symbol in obj.symbols
            if (
                symbol.name == "@comp.id"
                and symbol.section_number == -1
                and symbol.storage_class == matchlib.IMAGE_SYM_CLASS_STATIC
            )
        }
        compiler_id = next(iter(compiler_ids)) if len(compiler_ids) == 1 else None
        function_names = tuple(
            dict.fromkeys(
                symbol.name
                for symbol in obj.symbols
                if matchlib._is_function_symbol(symbol)
            ),
        )
        for function_name in function_names:
            function = matchlib.extract_object_function(obj, function_name)
            disassembly = matchlib.disassemble_normalized_function(
                function.data,
                relocation_offsets=function.relocation_offsets,
            )
            if not disassembly:
                continue
            significant_size = disassembly[-1].offset + disassembly[-1].size
            relocation_offsets = frozenset(
                offset
                for offset in function.relocation_offsets
                if offset + 4 <= significant_size
            )
            # Relocations can link to values the target normalizer cannot
            # recognize as addresses, notably VC6's FS:[0] SEH chain. Keep
            # this index structural and let _candidate_matches verify every
            # unrelocated byte after masking the candidate's relocations.
            object_functions += 1
            index[(significant_size, len(disassembly))].append(
                _NormalizedArchiveFunction(
                    candidate=ArchiveCandidate(
                        member=member.name,
                        symbol=function.name,
                        size=significant_size,
                        relocation_count=len(relocation_offsets),
                        compiler_id=compiler_id,
                    ),
                    data=function.data[:significant_size],
                    relocation_offsets=relocation_offsets,
                ),
            )
    return index, object_members, object_functions


def _mask_relocations(data: bytes, offsets: frozenset[int]) -> bytes | None:
    masked = bytearray(data)
    for offset in offsets:
        if offset < 0 or offset + 4 > len(masked):
            return None
        masked[offset : offset + 4] = b"\x00" * 4
    return bytes(masked)


def _candidate_matches(target: bytes, candidate: _NormalizedArchiveFunction) -> bool:
    if len(target) != len(candidate.data):
        return False
    masked_target = _mask_relocations(target, candidate.relocation_offsets)
    masked_candidate = _mask_relocations(candidate.data, candidate.relocation_offsets)
    return masked_target is not None and masked_target == masked_candidate


def match_coff_archive(
    archive_path: Path,
    *,
    image_path: Path,
    functions_path: Path,
    metadata_path: Path,
    range_start: int,
    range_end: int,
    excluded_addresses: Collection[int] = (),
) -> ArchiveMatchReport:
    if range_end <= range_start:
        raise ValueError("archive match range end must be greater than start")

    archive_data = archive_path.read_bytes()
    members = parse_coff_archive(archive_data)
    index, object_members, object_functions = _archive_function_index(members)
    image = matchlib.load_image(image_path)
    manifest = matchlib.load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=image_path.name,
        scope="all",
    )
    range_targets = tuple(
        function for function in manifest.functions if range_start <= function.address < range_end
    )
    excluded_address_set = frozenset(excluded_addresses)
    excluded_targets = tuple(
        function for function in range_targets if function.address in excluded_address_set
    )
    targets = tuple(
        function for function in range_targets if function.address not in excluded_address_set
    )

    matches: list[ArchiveFunctionMatch] = []
    target_bytes = 0
    for function in targets:
        target_data = image.function_bytes(function.address, function.end)
        target_bytes += len(target_data)
        lines = matchlib.normalize_function(
            target_data,
            address_range=(image.image_base, image.image_base + image.size_of_image),
            base_address=function.address,
        )
        candidates = tuple(
            candidate.candidate
            for candidate in index.get((len(target_data), len(lines)), ())
            if _candidate_matches(target_data, candidate)
        )
        if candidates:
            matches.append(
                ArchiveFunctionMatch(
                    address=function.address,
                    end=function.end,
                    name=function.name,
                    size=len(target_data),
                    instruction_count=len(lines),
                    candidates=candidates,
                ),
            )

    unique = tuple(match for match in matches if match.unique)
    return ArchiveMatchReport(
        archive=archive_path,
        archive_sha256=hashlib.sha256(archive_data).hexdigest(),
        archive_members=len(members),
        object_members=object_members,
        object_functions=object_functions,
        image=image_path,
        range_start=range_start,
        range_end=range_end,
        target_functions=len(targets),
        target_bytes=target_bytes,
        matched_functions=len(matches),
        matched_bytes=sum(match.size for match in matches),
        unique_functions=len(unique),
        unique_bytes=sum(match.size for match in unique),
        matches=tuple(matches),
        excluded_target_functions=len(excluded_targets),
        excluded_target_bytes=sum(
            len(image.function_bytes(function.address, function.end))
            for function in excluded_targets
        ),
    )


def _listed_archive_matches(
    report: ArchiveMatchReport,
    *,
    limit: int | None,
) -> tuple[ArchiveFunctionMatch, ...]:
    if limit is not None and limit < 1:
        raise ValueError("archive match listing limit must be positive")
    return report.matches if limit is None else report.matches[:limit]


def archive_match_payload(
    report: ArchiveMatchReport,
    *,
    limit: int | None = None,
) -> dict[str, object]:
    listed_matches = _listed_archive_matches(report, limit=limit)
    return {
        "archive": str(report.archive),
        "archive_sha256": report.archive_sha256,
        "archive_members": report.archive_members,
        "object_members": report.object_members,
        "object_functions": report.object_functions,
        "image": str(report.image),
        "range": {
            "start": f"0x{report.range_start:08x}",
            "end": f"0x{report.range_end:08x}",
        },
        "summary": {
            "target_functions": report.target_functions,
            "target_bytes": report.target_bytes,
            "matched_functions": report.matched_functions,
            "matched_bytes": report.matched_bytes,
            "unique_functions": report.unique_functions,
            "unique_bytes": report.unique_bytes,
            "symbol_unique_functions": report.symbol_unique_functions,
            "symbol_unique_bytes": report.symbol_unique_bytes,
        },
        "exclusions": {
            "target_functions": report.excluded_target_functions,
            "target_bytes": report.excluded_target_bytes,
        },
        "listing": {
            "returned_matches": len(listed_matches),
            "limit": limit,
            "truncated": len(listed_matches) < len(report.matches),
        },
        "members": [{"name": member, "unique_matches": count} for member, count in report.member_counts],
        "matches": [
            {
                "address": f"0x{match.address:08x}",
                "end": f"0x{match.end:08x}",
                "name": match.name,
                "size": match.size,
                "instructions": match.instruction_count,
                "unique": match.unique,
                "symbol_unique": match.symbol_unique,
                "candidates": [
                    {
                        "member": candidate.member,
                        "symbol": candidate.symbol,
                        "size": candidate.size,
                        "relocations": candidate.relocation_count,
                        "compiler": (
                            None
                            if candidate.compiler_id is None
                            else {
                                "id": f"0x{candidate.compiler_id:08x}",
                                "product": candidate.compiler_product,
                                "build": candidate.compiler_build,
                            }
                        ),
                    }
                    for candidate in match.candidates
                ],
            }
            for match in listed_matches
        ],
    }


def _scratch_directory_slug(name: str, address: int) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return slug or f"sub_{address:08x}"


def _scratch_note_suffix(name: str, address: int) -> str:
    suffix = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return suffix or f"sub-{address:08x}"


def _scratch_assignment(key: str, value: str) -> str:
    return f"{key}={shlex.quote(value)}"


def _write_text_atomic(path: Path, text: str) -> None:
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


def _archive_reference_evidence(
    report: ArchiveMatchReport,
    *,
    functions_path: Path,
    metadata_path: Path,
    include_symbol_unique: bool = False,
) -> tuple[tuple[_ArchiveReferenceEvidence, ...], matchlib.ReferenceCatalog]:
    members: dict[str, bytes] = {}
    for member in parse_coff_archive(report.archive.read_bytes()):
        if member.name in {"/", "//"}:
            continue
        if member.name in members:
            raise ValueError(f"archive contains duplicate member name {member.name!r}")
        members[member.name] = member.data

    manifest = matchlib.load_function_manifest(
        functions_path,
        metadata_path=metadata_path,
        image_name=report.image.name,
        scope="all",
    )
    image = matchlib.load_image(report.image, manifest.image_base)
    catalog = matchlib.load_reference_catalog(manifest, functions_path=functions_path)
    evidence: list[_ArchiveReferenceEvidence] = []
    for archive_match in report.matches:
        if not archive_match.unique and not (
            include_symbol_unique and archive_match.symbol_unique
        ):
            continue
        candidate = archive_match.candidates[0]
        member_data = members.get(candidate.member)
        if member_data is None:
            raise ValueError(f"archive member {candidate.member!r} disappeared during alias inference")
        obj = matchlib.parse_coff_object(member_data)
        function = matchlib.extract_object_function(obj, candidate.symbol)
        result = matchlib.match_function(
            image.function_bytes(archive_match.address, archive_match.end),
            function,
            image=image,
            target_va=archive_match.address,
            reference_catalog=catalog,
        )
        if result.ratio != 1.0:
            continue

        for entry in result.masked_operand_audit.entries:
            if entry.status != "unresolved":
                continue
            if len(entry.candidate_references) != 1 or len(entry.target_references) != 1:
                continue
            object_reference = entry.candidate_references[0]
            target_reference = entry.target_references[0]
            object_symbol = object_reference.text
            candidate_line = result.candidate_disassembly[entry.candidate_index]
            matching_relocations = tuple(
                reference
                for reference in function.relocation_references
                if reference.symbol_name == object_symbol
                and entry.candidate_offset
                <= reference.offset
                < entry.candidate_offset + candidate_line.size
            )
            if (
                object_reference.source != "reloc"
                or target_reference.source != "image"
                or target_reference.value is None
                or object_symbol.startswith("__imp_")
                or len(matching_relocations) != 1
                or matching_relocations[0].addend is None
                or any(character in object_symbol for character in ",:")
            ):
                continue
            addend = matching_relocations[0].addend
            assert addend is not None
            target_address = target_reference.value - addend
            if target_address < 0:
                continue
            evidence.append(
                _ArchiveReferenceEvidence(
                    match_address=archive_match.address,
                    match_name=archive_match.name,
                    member=candidate.member,
                    object_symbol=object_symbol,
                    lookup_name=matchlib._symbol_lookup_name(object_symbol),
                    target_address=target_address,
                    addend=addend,
                ),
            )
    return tuple(evidence), catalog


def infer_archive_reference_aliases(
    report: ArchiveMatchReport,
    *,
    functions_path: Path,
    metadata_path: Path,
    include_symbol_unique: bool = False,
) -> dict[int, tuple[tuple[str, str], ...]]:
    """Infer conservative object-to-image aliases from exact aligned references."""
    evidence, catalog = _archive_reference_evidence(
        report,
        functions_path=functions_path,
        metadata_path=metadata_path,
        include_symbol_unique=include_symbol_unique,
    )
    by_match: dict[int, list[_ArchiveReferenceEvidence]] = defaultdict(list)
    for item in evidence:
        by_match[item.match_address].append(item)

    aliases_by_address: dict[int, tuple[tuple[str, str], ...]] = {}
    for archive_match in report.matches:
        inferred: dict[str, tuple[str, int, str]] = {}
        conflicted: set[str] = set()
        for item in by_match.get(archive_match.address, ()):
            if item.addend != 0:
                continue
            target_names = tuple(
                name
                for name in catalog.names_by_address.get(item.target_address, ())
                if catalog.knows_name(name) and not any(character in name for character in ",:")
            )
            if not target_names:
                continue
            target_name = target_names[0]
            previous = inferred.get(item.lookup_name)
            current = (target_name, item.target_address, item.object_symbol)
            if previous is not None and previous[:2] != current[:2]:
                conflicted.add(item.lookup_name)
                continue
            inferred[item.lookup_name] = current
        aliases_by_address[archive_match.address] = tuple(
            sorted(
                (
                    object_symbol,
                    target_name,
                )
                for lookup_name, (target_name, _, object_symbol) in inferred.items()
                if lookup_name not in conflicted
            ),
        )
    return aliases_by_address


def infer_archive_reference_bindings(
    report: ArchiveMatchReport,
    *,
    functions_path: Path,
    metadata_path: Path,
    include_symbol_unique: bool = False,
) -> tuple[ArchiveReferenceBinding, ...]:
    """Report stable zero-addend archive symbols bound to one image address."""
    evidence, catalog = _archive_reference_evidence(
        report,
        functions_path=functions_path,
        metadata_path=metadata_path,
        include_symbol_unique=include_symbol_unique,
    )
    by_lookup: dict[str, list[_ArchiveReferenceEvidence]] = defaultdict(list)
    for item in evidence:
        by_lookup[item.lookup_name].append(item)

    bindings: list[ArchiveReferenceBinding] = []
    for lookup_name, items in by_lookup.items():
        target_addresses = {item.target_address for item in items}
        if len(target_addresses) != 1:
            continue
        target_address = next(iter(target_addresses))
        bindings.append(
            ArchiveReferenceBinding(
                lookup_name=lookup_name,
                object_symbols=tuple(sorted({item.object_symbol for item in items})),
                target_address=target_address,
                occurrences=len(items),
                addends=tuple(sorted({item.addend for item in items})),
                functions=tuple(sorted({(item.match_address, item.match_name) for item in items})),
                members=tuple(sorted({item.member for item in items})),
                target_names=tuple(catalog.names_by_address.get(target_address, ())),
            ),
        )
    return tuple(sorted(bindings, key=lambda item: (-item.occurrences, item.lookup_name)))


def archive_reference_bindings_payload(
    bindings: tuple[ArchiveReferenceBinding, ...],
    *,
    limit: int | None = None,
) -> dict[str, object]:
    if limit is not None and limit < 1:
        raise ValueError("archive reference binding listing limit must be positive")
    listed = bindings if limit is None else bindings[:limit]
    return {
        "count": len(bindings),
        "returned": len(listed),
        "limit": limit,
        "truncated": len(listed) < len(bindings),
        "bindings": [
            {
                "lookup_name": binding.lookup_name,
                "object_symbols": list(binding.object_symbols),
                "target_address": f"0x{binding.target_address:08x}",
                "target_names": list(binding.target_names),
                "occurrences": binding.occurrences,
                "addends": list(binding.addends),
                "functions": [
                    {"address": f"0x{address:08x}", "name": name}
                    for address, name in binding.functions
                ],
                "members": list(binding.members),
            }
            for binding in listed
        ],
    }


def render_archive_reference_bindings(
    bindings: tuple[ArchiveReferenceBinding, ...],
    *,
    limit: int | None = None,
) -> str:
    payload = archive_reference_bindings_payload(bindings, limit=limit)
    lines = [
        f"reference_bindings={payload['count']} returned={payload['returned']}"
        + (" truncated=true" if payload["truncated"] else ""),
    ]
    for binding in bindings if limit is None else bindings[:limit]:
        target = ",".join(binding.target_names) if binding.target_names else "unmapped"
        symbols = ",".join(binding.object_symbols)
        lines.append(
            f"reference_binding={symbols} target=0x{binding.target_address:08x} "
            f"occurrences={binding.occurrences} functions={len(binding.functions)} "
            f"addends={','.join(f'{addend:+#x}' for addend in binding.addends)} "
            f"target_names={target}",
        )
    return "\n".join(lines)


def write_archive_scratch_configs(
    report: ArchiveMatchReport,
    *,
    match_root: Path,
    expected_sha256: str,
    note_prefix: str,
    include_symbol_unique: bool = False,
    infer_reference_aliases: bool = False,
    functions_path: Path | None = None,
    metadata_path: Path | None = None,
) -> tuple[ArchiveScratchWrite, ...]:
    """Materialize pinned configs for unambiguous archive matches."""
    expected = expected_sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("expected archive SHA-256 must be 64 hexadecimal characters")
    if report.archive_sha256 != expected:
        raise ValueError(
            f"archive SHA-256 mismatch: expected {expected}, got {report.archive_sha256}",
        )
    if not note_prefix.strip():
        raise ValueError("archive scratch note prefix must not be empty")

    aliases_by_address = (
        infer_archive_reference_aliases(
            report,
            functions_path=functions_path or matchlib.default_functions_path(report.image.name),
            metadata_path=metadata_path or matchlib.default_metadata_path(report.image.name),
            include_symbol_unique=include_symbol_unique,
        )
        if infer_reference_aliases
        else {}
    )

    scratches_root = match_root / "scratches"
    reserved_directories: set[Path] = set()
    planned: list[ArchiveScratchWrite] = []
    for archive_match in report.matches:
        if not archive_match.unique and not (
            include_symbol_unique and archive_match.symbol_unique
        ):
            continue
        candidate = archive_match.candidates[0]
        slug = _scratch_directory_slug(archive_match.name, archive_match.address)
        directory = scratches_root / slug
        if directory.exists() or directory in reserved_directories:
            directory = scratches_root / f"{slug}_{archive_match.address:08x}"
        if directory.exists() or directory in reserved_directories:
            raise FileExistsError(f"refusing to overwrite archive scratch directory {directory}")
        reserved_directories.add(directory)
        planned.append(
            ArchiveScratchWrite(
                directory=directory,
                match=archive_match,
                candidate=candidate,
                reference_aliases=aliases_by_address.get(archive_match.address, ()),
            ),
        )

    archive_path = report.archive.resolve()
    for write in planned:
        relative_archive = Path(os.path.relpath(archive_path, start=write.directory.resolve()))
        note = f"{note_prefix}-{_scratch_note_suffix(write.match.name, write.match.address)}"
        config_lines = [
            _scratch_assignment("IMAGE", report.image.name),
            _scratch_assignment("FUNCTION", write.match.name),
            _scratch_assignment("ARCHIVE", relative_archive.as_posix()),
            _scratch_assignment("ARCHIVE_MEMBER", write.candidate.member),
            _scratch_assignment("ARCHIVE_SHA256", report.archive_sha256),
            _scratch_assignment("SYMBOL", write.candidate.symbol),
        ]
        if write.reference_aliases:
            config_lines.append(
                _scratch_assignment(
                    "REFERENCE_ALIASES",
                    ",".join(
                        f"{object_symbol}:{target_symbol}"
                        for object_symbol, target_symbol in write.reference_aliases
                    ),
                ),
            )
        config_lines.extend((_scratch_assignment("NOTE", note), ""))
        config = "\n".join(config_lines)
        _write_text_atomic(write.directory / "scratch.conf", config)
    return tuple(planned)


def render_archive_match_report(
    report: ArchiveMatchReport,
    *,
    show_matches: bool = False,
    limit: int | None = None,
) -> str:
    lines = [
        (
            f"archive={report.archive} sha256={report.archive_sha256} "
            f"members={report.archive_members} objects={report.object_members} "
            f"functions={report.object_functions}"
        ),
        (
            f"image={report.image.name} "
            f"range=0x{report.range_start:08x}..0x{report.range_end:08x} "
            f"excluded={report.excluded_target_functions} "
            f"excluded_bytes={report.excluded_target_bytes} "
            f"matched={report.matched_functions}/{report.target_functions} "
            f"bytes={report.matched_bytes}/{report.target_bytes} "
            f"unique={report.unique_functions} unique_bytes={report.unique_bytes} "
            f"symbol_unique={report.symbol_unique_functions} "
            f"symbol_unique_bytes={report.symbol_unique_bytes}"
        ),
    ]
    for member, count in report.member_counts:
        lines.append(f"member={member} unique_matches={count}")
    if show_matches:
        selected = _listed_archive_matches(report, limit=limit)
        for match in selected:
            candidates = ", ".join(
                (
                    f"{candidate.member}:{candidate.symbol} "
                    f"[product-{candidate.compiler_product}/build-{candidate.compiler_build}]"
                    if candidate.compiler_id is not None
                    else f"{candidate.member}:{candidate.symbol}"
                )
                for candidate in match.candidates
            )
            if match.unique:
                state = "unique"
            elif match.symbol_unique:
                state = f"symbol-unique:{len(match.candidates)}"
            else:
                state = f"ambiguous:{len(match.candidates)}"
            lines.append(
                f"0x{match.address:08x} {match.name} bytes={match.size} "
                f"insns={match.instruction_count} {state} <- {candidates}",
            )
    return "\n".join(lines)
