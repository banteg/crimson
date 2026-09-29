"""Other builds of a decomp family: registry, cross-build maps and match targets.

A family shares one source tree under ``decomp/<family>``. Its canonical build
carries the curated analysis. Every other build gets function and data maps
derived from the canonical image: a function whose body survives relinking
unchanged is found by search, and its relocated operands then name the callees
and globals it references in the other build. A canonical scratch can then be
compiled as that build (its compiler and ``CL_BUILD``) and compared against its
image.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, replace
from functools import cache
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import match as matchlib

REGISTRY_PATH = matchlib.REPO_ROOT / "decomp" / "builds.json"
MAPS_ROOT = matchlib.REPO_ROOT / "analysis" / "decomp"
# Literal byte runs shorter than this recur too often to anchor a search.
MIN_ANCHOR_BYTES = 8
# Bodies whose sizes differ by more than this are not paired by layout order.
MAX_SIZE_RATIO = 1.5
# VC6 starts compiled functions on this boundary, padding after the previous one.
FUNCTION_ALIGNMENT = 16
IMAGE_SCN_MEM_EXECUTE = 0x20000000
# How a build's function was placed, strongest first; see _Mapper.
EVIDENCE = ("exact", "interface", "referenced", "called", "ordered")
# Scratch states from worst to best; a scan keeps each scratch's best compiler.
SCAN_STATES = ("error", "wip", "audit", "match")


@dataclass(frozen=True, slots=True)
class BuildImage:
    build: str
    canonical_build: str | None
    cl_build: int
    name: str
    path: Path
    sha256: str
    profiles: tuple[str, ...]
    # Every profile that built game code in some build; other toolchains built prebuilt libraries.
    game_profiles: frozenset[str]

    @property
    def is_canonical(self) -> bool:
        return self.build == self.canonical_build

    @property
    def map_dir(self) -> Path:
        return MAPS_ROOT / self.build / self.name

    @property
    def target(self) -> matchlib.MatchTarget:
        if self.is_canonical:
            return matchlib.default_match_target(self.name)
        return matchlib.MatchTarget(
            image_path=self.path,
            functions_path=self.map_dir / "functions.json",
            metadata_path=self.map_dir / "metadata.json",
            image_name=f"{self.build}/{self.name}",
            data_map_path=self.map_dir / "data.json",
        )

    def scratch_configs(self, config: matchlib.ScratchConfig) -> tuple[matchlib.ScratchConfig, ...]:
        """Compile a canonical scratch as this build, once per compiler that could have built it.

        Game code takes the build's profiles, several for an incrementally rebuilt image;
        a prebuilt library keeps its own toolchain.
        """
        if self.is_canonical:
            return (config,)
        names = _reference_catalog(self)
        compilers = self.profiles if config.compiler in self.game_profiles else (config.compiler,)
        return tuple(
            replace(
                config,
                compiler=compiler,
                cflags=f"{config.cflags} /DCL_BUILD={self.cl_build}",
                # END_VA is a canonical address; this build's map carries its own extent.
                end_va=None,
                # An alias to a global this build's maps do not name leaves the reference unresolved.
                reference_aliases=tuple(alias for alias in config.reference_aliases if names.knows_name(alias[1])),
            )
            for compiler in compilers
        )

    def scratch_config(self, config: matchlib.ScratchConfig) -> matchlib.ScratchConfig:
        """Compile a canonical scratch as this build with its first applicable compiler."""
        return self.scratch_configs(config)[0]

    def state(self) -> str:
        if not self.path.is_file():
            return "missing"
        return "ok" if hashlib.sha256(self.path.read_bytes()).hexdigest() == self.sha256 else "changed"


@cache
def _reference_catalog(image: BuildImage) -> matchlib.ReferenceCatalog:
    target = image.target
    manifest = matchlib.load_function_manifest(
        target.functions_path,
        metadata_path=target.metadata_path,
        image_name=target.image_name,
    )
    return matchlib.load_reference_catalog(
        manifest,
        data_map_path=target.data_map_path,
        functions_path=target.functions_path,
    )


@dataclass(frozen=True, slots=True)
class Registry:
    builds: dict[str, dict[str, BuildImage]]
    # Builds published to decomp.dev, canonical first.
    reported: tuple[str, ...]

    def image(self, build: str, name: str) -> BuildImage:
        if build not in self.builds:
            raise ValueError(f"unknown build {build!r}; known: {', '.join(self.builds)}")
        if name not in self.builds[build]:
            raise ValueError(f"build {build} has no image {name!r}")
        return self.builds[build][name]

    def canonical(self, image: BuildImage) -> BuildImage:
        if image.canonical_build is None:
            raise ValueError(f"build {image.build} belongs to no family")
        return self.builds[image.canonical_build][image.name]


def load_registry(path: Path = REGISTRY_PATH) -> Registry:
    payload = json.loads(path.read_text(encoding="utf-8"))
    canonical = {family["id"]: family["canonical_build"] for family in payload["families"]}
    game_profiles = frozenset(
        profile for row in payload["builds"] for image in row["images"] for profile in image["profiles"]
    )
    return Registry(
        {
            row["id"]: {
                image["name"]: BuildImage(
                    build=row["id"],
                    canonical_build=canonical.get(row["family"]),
                    cl_build=row["cl_build"],
                    name=image["name"],
                    path=matchlib.REPO_ROOT / row["tree"] / image["name"],
                    sha256=image["sha256"],
                    profiles=tuple(image["profiles"]),
                    game_profiles=game_profiles,
                )
                for image in row["images"]
            }
            for row in payload["builds"]
        },
        tuple(
            sorted(
                (row["id"] for row in payload["builds"] if row.get("reported")),
                key=lambda build: build not in canonical.values(),
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class _Body:
    lines: tuple[matchlib.DisassemblyLine, ...]
    signature: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...]

    @property
    def size(self) -> int:
        # The disassembler removes only verified terminal alignment padding.
        # Raw manifest extents can contain different padding in another build.
        return max((line.offset + line.size for line in self.lines), default=0)


def _body(image: matchlib.LoadedImage, start: int, size: int) -> _Body:
    """Normalize a body so that only relinking-invariant content remains."""
    data = image.function_bytes(start, start + size)
    lines = matchlib.disassemble_normalized_function(
        data,
        address_range=(image.image_base, image.image_base + image.size_of_image),
        base_address=start,
        image=image,
    )

    def portable(reference: matchlib.MaskedReference) -> tuple[str, ...]:
        # Literal contents survive relinking; so do offsets inside the body.
        return tuple(
            key
            for key in reference.keys
            if not key.startswith("local:") or 0 <= int(key.removeprefix("local:"), 16) < len(data)
        )

    return _Body(
        lines,
        tuple((line.text, tuple(portable(ref) for ref in line.masked_references)) for line in lines),
    )


def _fixed_runs(body: _Body, data: bytes, start: int) -> list[tuple[int, bytes]]:
    """Byte runs that relinking cannot change: instructions without outside references."""
    relocatable = bytearray(len(data))
    for line in body.lines:
        if any(ref.value is None or not start <= ref.value < start + len(data) for ref in line.masked_references):
            relocatable[line.offset : line.offset + line.size] = b"\1" * line.size
    runs: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if relocatable[offset]:
            offset += 1
            continue
        end = relocatable.find(b"\1", offset)
        end = len(data) if end < 0 else end
        runs.append((offset, data[offset:end]))
        offset = end
    return runs


def _code_ranges(path: Path) -> list[tuple[int, int]]:
    import pefile

    with pefile.PE(str(path), fast_load=True) as pe:
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        return [
            (base + section.VirtualAddress, base + section.VirtualAddress + section.Misc_VirtualSize)
            for section in pe.sections
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE
        ]


def _imports(path: Path) -> list[dict[str, Any]]:
    """Import table in the layout of ``analysis/ida/raw/<image>/imports.json``."""
    import pefile

    with pefile.PE(str(path)) as pe:
        return [
            {
                "entries": [
                    {
                        "address": f"0x{entry.address:08X}",
                        "name": entry.name.decode("ascii") if entry.name else "",
                        "ordinal": entry.ordinal or 0,
                    }
                    for entry in module.imports
                ],
                "module": module.dll.decode("ascii").rsplit(".", 1)[0].upper(),
            }
            for module in pe.DIRECTORY_ENTRY_IMPORT
        ]


def map_build_image(image: BuildImage, canonical: BuildImage) -> dict[str, Any]:
    """Derive ``image``'s function and data maps from its family's canonical image."""
    return _Mapper(image, canonical).run()


def _grim_slot_offsets(build: str) -> dict[int, int]:
    """Pair interface slots by the actual DLL pointers and their mapped functions."""
    registry = load_registry()
    engine = registry.image(build, "grim.dll")
    canonical = registry.canonical(engine)

    def slots(image: BuildImage) -> dict[int, int]:
        catalog = _reference_catalog(image)
        addresses = catalog._addresses_for_symbol("grim_interface_vtable")
        if len(addresses) != 1:
            return {}
        loaded = matchlib.load_image(image.path)
        rows = json.loads(image.target.functions_path.read_text(encoding="utf-8"))
        identities = {
            matchlib.parse_int(row["address"]): matchlib.parse_int(row.get("canonical_address", row["address"]))
            for row in rows
        }
        result = {}
        # Stop at the first pointer outside executable memory; do not assume a slot count.
        code = _code_ranges(image.path)
        for offset in range(0, 0x400, 4):
            pointer = struct.unpack_from("<I", loaded.mapped, addresses[0] - loaded.image_base + offset)[0]
            if not any(start <= pointer < end for start, end in code):
                break
            if pointer in identities:
                result[offset] = identities[pointer]
        return result

    target_slots = slots(engine)
    return {
        offset: destinations[0]
        for offset, identity in slots(canonical).items()
        if len(destinations := [slot for slot, target in target_slots.items() if target == identity]) == 1
    }


def _grim_virtual_calls(body: _Body, interface_address: int) -> dict[int, int]:
    """Recognize direct thiscall dispatch through the known Grim object.

    Track register copies conservatively, clearing state at branches and after
    calls. An arbitrary indirect call never qualifies just because its offset fits.
    """
    registers: dict[str, str] = {}
    calls: dict[int, int] = {}
    branch_targets = {
        label for line in body.lines for label in matchlib.BRANCH_TARGET_RE.findall(line.text)
    }
    for index, line in enumerate(body.lines):
        if f"{line.offset:x}" in branch_targets:
            registers.clear()
        if (
            (dispatch := re.fullmatch(r"call dword \[(\w+)(?:\+0x([0-9a-f]+))?\]", line.text))
            and registers.get(dispatch[1]) == "vtable"
            and registers.get("ecx") == "object"
        ):
            calls[index] = int(dispatch[2] or "0", 16)
        if line.text.startswith(("call ", "jmp ", "j")):
            registers.clear()
            continue
        opcode = line.text.split(" ", 1)[0]
        if opcode in {"push", "cmp", "test", "nop"} or opcode.startswith("f") and opcode != "fnstsw":
            continue
        # Only model instructions with a single explicit register destination.
        # MUL/DIV, CDQ, XCHG and similar instructions can also overwrite tracked
        # registers through implicit or additional destinations.
        if opcode not in {
            "mov", "movzx", "movsx", "lea", "pop", "add", "sub", "adc", "sbb",
            "and", "or", "xor", "not", "neg", "inc", "dec", "shl", "shr", "sar",
            "sal", "rol", "ror", "rcl", "rcr",
        }:
            registers.clear()
            continue
        if not (assignment := re.match(r"\w+ (\w+)(?:, (.*))?$", line.text)):
            registers.clear()
            continue
        destination, operand = assignment.groups()
        previous = dict(registers)
        destination = {"al": "eax", "ah": "eax", "ax": "eax", "cl": "ecx", "ch": "ecx", "cx": "ecx",
                       "dl": "edx", "dh": "edx", "dx": "edx", "bl": "ebx", "bh": "ebx", "bx": "ebx"}.get(
            destination, destination,
        )
        registers.pop(destination, None)
        if not line.text.startswith("mov "):
            continue
        if operand == "dword [ADDR]" and any(ref.value == interface_address for ref in line.masked_references):
            registers[destination] = "object"
        elif operand in previous:
            registers[destination] = previous[operand]
        elif (
            operand and (dereference := re.fullmatch(r"dword \[(\w+)\]", operand))
            and previous.get(dereference[1]) == "object"
        ):
            registers[destination] = "vtable"
    return calls


class _Mapper:
    """Pair canonical functions with the functions of another build's image.

    Evidence, strongest first: ``exact`` bodies are identical up to relinking;
    ``referenced`` addresses come from an exact body's operand; ``called``
    addresses from the same call site of a mapped caller whose body changed but
    kept its call sequence; ``ordered`` addresses sit between mapped neighbours
    in the same layout order.
    """

    def __init__(self, image: BuildImage, canonical: BuildImage) -> None:
        self.image = image
        self.canonical = canonical
        target = canonical.target
        manifest = matchlib.load_function_manifest(
            target.functions_path,
            metadata_path=target.metadata_path,
            image_name=target.image_name,
            scope="all",
        )
        self.source = matchlib.load_image(target.image_path, manifest.image_base)
        self.target = matchlib.load_image(image.path)
        self.functions = sorted(manifest.functions, key=lambda function: function.address)
        self.by_address = {function.address: function for function in self.functions}
        self.starts = [function.address for function in self.functions]
        self.bodies = {
            function.address: _body(self.source, function.address, function.size) for function in self.functions
        }
        catalog = matchlib.load_reference_catalog(
            manifest, data_map_path=target.data_map_path, functions_path=target.functions_path,
        )
        self.function_aliases = {
            function.address: tuple(
                name for name in catalog.names_by_address.get(function.address, ()) if name != function.name
            )
            for function in self.functions
        }
        data_names: dict[int, set[str]] = defaultdict(set)
        for row in json.loads(target.data_map_path.read_text(encoding="utf-8"))["entries"]:
            if row.get("program") == target.image_name and row.get("kind", "data") == "data":
                data_names[matchlib.parse_int(row["address"])].update((row["name"], *row.get("aliases", ())))
        # A typed object and its first member can share an address. Keep both;
        # choosing the last name loses the base symbol used by compiled source.
        self.data_rows = sorted((address, tuple(sorted(names))) for address, names in data_names.items())
        self.data_addresses = [address for address, _ in self.data_rows]
        self.imports = {
            matchlib.parse_int(entry["address"])
            for module in json.loads(target.functions_path.with_name("imports.json").read_text(encoding="utf-8"))
            for entry in module["entries"]
        }
        self.code = [
            (start, self.target.mapped[start - self.target.image_base : end - self.target.image_base])
            for start, end in _code_ranges(image.path)
        ]
        self.entry_points = self._entry_points()
        self.mapped: dict[int, int] = {}
        self.evidence: dict[int, str] = {}
        self.hits: dict[int, list[int]] = {}
        self.function_votes: dict[int, set[int]] = defaultdict(set)
        self.call_votes: dict[int, set[int]] = defaultdict(set)
        self.data_votes: dict[str, set[int]] = defaultdict(set)
        self.paired_calls: set[int] = set()
        self.grim_slots = _grim_slot_offsets(image.build) if image.name == "crimsonland.exe" else {}
        self.grim_address = next(
            (address for address, names in self.data_rows if "grim_interface_ptr" in names), None,
        )

    def in_code(self, address: int) -> bool:
        return any(start <= address < start + len(section) for start, section in self.code)

    def _entry_points(self) -> list[int]:
        """Target addresses that start a function.

        Evidence: a direct call or pushed address; an aligned pointer in data;
        or an aligned address after padding that follows a return or jump.
        """
        import pefile

        found: set[int] = set()
        for start, section in self.code:
            for opcode, relative in ((0xE8, True), (0x68, False)):
                offset = section.find(opcode)
                while 0 <= offset <= len(section) - 5:
                    value = int.from_bytes(section[offset + 1 : offset + 5], "little")
                    address = (start + offset + 5 + value) & 0xFFFFFFFF if relative else value
                    if self.in_code(address):
                        found.add(address)
                    offset = section.find(opcode, offset + 1)
            for offset in range(-start % FUNCTION_ALIGNMENT, len(section), FUNCTION_ALIGNMENT):
                end = offset
                while end > 0 and section[end - 1] in matchlib.PADDING_BYTES:
                    end -= 1
                tail = section[max(0, end - 5) : end]
                if end < offset and (
                    tail[-1:] == b"\xc3"  # ret
                    or tail[-3:-2] == b"\xc2"  # ret imm16
                    or tail[-5:-4] == b"\xe9"  # jmp rel32
                    or tail[-2:-1] == b"\xeb"  # jmp rel8
                ):
                    found.add(start + offset)
        with pefile.PE(str(self.image.path), fast_load=True) as pe:
            for section in pe.sections:
                if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                    continue
                data = self.target.mapped[section.VirtualAddress : section.VirtualAddress + section.Misc_VirtualSize]
                for offset in range(0, len(data) - 3, 4):
                    value = int.from_bytes(data[offset : offset + 4], "little")
                    if value % FUNCTION_ALIGNMENT == 0 and self.in_code(value):
                        found.add(value)
            found.add(self.target.image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        return sorted(found)

    def body_at(self, address: int, size: int) -> _Body:
        return _body(self.target, address, size)

    def accept(self, address: int, target: int, evidence: str) -> bool:
        """Map a canonical function; report whether its body is exact there."""
        self.mapped[address] = target
        target_body = self.body_at(target, self.bodies[address].size)
        exact = target_body.signature == self.bodies[address].signature
        interface = not exact and self.interface_equivalent(address, target_body)
        self.evidence[address] = "exact" if exact else "interface" if interface else evidence
        return exact or interface

    def interface_equivalent(self, address: int, target: _Body) -> bool:
        """Every instruction agrees except independently paired Grim virtual slots."""
        if self.grim_address is None or not self.grim_slots:
            return False
        source = self.bodies[address]
        signature = list(source.signature)
        changed = False
        for index, offset in _grim_virtual_calls(source, self.grim_address).items():
            if offset not in self.grim_slots:
                return False
            mapped_offset = self.grim_slots[offset]
            if mapped_offset == offset:
                continue
            text, references = signature[index]
            signature[index] = (re.sub(r"\+0x[0-9a-f]+\]", f"+0x{mapped_offset:x}]", text), references)
            changed = True
        return changed and tuple(signature) == target.signature

    def run(self) -> dict[str, Any]:
        self.search()
        pending = [address for address, positions in self.hits.items() if len(positions) == 1]
        for address in pending:
            self.accept(address, self.hits[address][0], "exact")
        # Every new placement narrows the gaps and adds call sites; stop once none comes.
        while True:
            placed = len(self.mapped)
            for address in pending:
                self.propagate(address)
            pending = self.accept_votes() + self.fill_by_order()
            if not pending:
                self.pair_calls()
                pending = self.accept_votes()
            if not pending and len(self.mapped) == placed:
                break
        # A later vote can contradict an early single one; exact bodies stand on their own.
        for votes, evidence in ((self.function_votes, "referenced"), (self.call_votes, "called")):
            for address, targets in votes.items():
                if len(targets) > 1 and self.evidence.get(address) == evidence:
                    del self.mapped[address], self.evidence[address]
        return self.payload()

    def search(self) -> None:
        """Find bodies that survived relinking unchanged."""
        for function in self.functions:
            body = self.bodies[function.address]
            data = self.source.function_bytes(function.address, function.address + body.size)
            runs = _fixed_runs(body, data, function.address)
            anchor_offset, anchor = max(runs, key=lambda run: len(run[1]), default=(0, b""))
            if len(anchor) < MIN_ANCHOR_BYTES:
                continue
            positions = []
            for section_start, section in self.code:
                found = section.find(anchor)
                while found >= 0:
                    position = section_start + found - anchor_offset
                    offset = position - self.target.image_base
                    if all(
                        self.target.mapped[offset + run_offset : offset + run_offset + len(run)] == run
                        for run_offset, run in runs
                    ) and self.body_at(position, body.size).signature == body.signature:
                        positions.append(position)
                    found = section.find(anchor, found + 1)
            self.hits[function.address] = positions

    def propagate(self, address: int) -> None:
        """Pair an exact body's relocated operands with the target's."""
        function = self.by_address[address]
        pairs = zip(
            self.bodies[address].lines,
            self.body_at(self.mapped[address], self.bodies[address].size).lines,
            strict=True,
        )
        for source_line, target_line in pairs:
            for source_ref, target_ref in zip(
                source_line.masked_references,
                target_line.masked_references,
                strict=True,
            ):
                value, target_value = source_ref.value, target_ref.value
                if value is None or target_value is None or function.address <= value < function.end:
                    continue
                if value in self.by_address:
                    if self.in_code(target_value):
                        self.function_votes[value].add(target_value)
                    continue
                owner = bisect.bisect_right(self.starts, value) - 1
                if value in self.imports or (owner >= 0 and value < self.functions[owner].end):
                    continue
                if any(not key.startswith("local:") for key in source_ref.keys):
                    continue  # a literal, not a named global
                symbol = bisect.bisect_right(self.data_addresses, value) - 1
                if symbol < 0 or (symbol + 1 < len(self.data_rows) and value >= self.data_addresses[symbol + 1]):
                    continue
                symbol_address, names = self.data_rows[symbol]
                for name in names:
                    self.data_votes[name].add(target_value - (value - symbol_address))

    def accept_votes(self) -> list[int]:
        exact = []
        for votes, evidence in ((self.function_votes, "referenced"), (self.call_votes, "called")):
            for address, targets in votes.items():
                if address in self.mapped or len(targets) != 1:
                    continue
                target = next(iter(targets))
                if self.hits.get(address) and target not in self.hits[address]:
                    continue
                if evidence == "called" and self.function_votes.get(address, {target}) != {target}:
                    continue
                if self.accept(address, target, evidence):
                    exact.append(address)
        return exact

    def pair_calls(self) -> None:
        """Pair the call sites of changed bodies that kept their call sequence."""
        for address, target in list(self.mapped.items()):
            if self.evidence[address] in {"exact", "interface"} or address in self.paired_calls:
                continue
            self.paired_calls.add(address)
            source_calls = self.calls(self.bodies[address], self.by_address)
            target_calls = self.calls(self.body_at(target, self.extent(target) - target), None)
            if len(source_calls) != len(target_calls):
                continue
            if any(
                callee in self.mapped and self.mapped[callee] != target_callee
                for callee, target_callee in zip(source_calls, target_calls, strict=True)
            ):
                continue
            for callee, target_callee in zip(source_calls, target_calls, strict=True):
                self.call_votes[callee].add(target_callee)

    def calls(self, body: _Body, starts: dict[int, matchlib.FunctionSymbol] | None) -> list[int]:
        """Direct call targets in order: canonical function starts, or target code addresses."""
        return [
            reference.value
            for line in body.lines
            if line.text.startswith("call ")
            for reference in line.masked_references
            if reference.value is not None
            and (reference.value in starts if starts is not None else self.in_code(reference.value))
        ]

    def extent(self, target: int) -> int:
        """End of a target body whose size is unknown: the next known function or its section end."""
        boundaries = self.boundaries()
        following = bisect.bisect_right(boundaries, target)
        return min(
            boundaries[following] if following < len(boundaries) else 1 << 32,
            next(start + len(section) for start, section in self.code if start <= target < start + len(section)),
        )

    def boundaries(self) -> list[int]:
        return sorted({*self.entry_points, *self.mapped.values()})

    def fill_by_order(self) -> list[int]:
        """Pair unmapped functions between in-order mapped neighbours by layout and size.

        Between two neighbours a build can add, drop or inline functions, so the
        functions on each side are aligned in order, pairing only similar sizes.
        """
        exact = []
        taken = set(self.mapped.values())
        for (low, low_target), (high, high_target) in pairwise(_increasing(sorted(self.mapped.items()))):
            missing = [
                address
                for address in self.starts[bisect.bisect_right(self.starts, low) : bisect.bisect_left(self.starts, high)]
                if address not in self.mapped
            ]
            candidates = [
                address
                for address in self.entry_points[
                    bisect.bisect_right(self.entry_points, low_target) : bisect.bisect_left(
                        self.entry_points,
                        high_target,
                    )
                ]
                if address not in taken
            ]
            # A body found at several places is the one between these neighbours.
            for address in missing:
                between = [hit for hit in self.hits.get(address, ()) if low_target < hit < high_target]
                if len(between) == 1 and between[0] not in taken:
                    taken.add(between[0])
                    self.accept(address, between[0], "exact")
                    exact.append(address)
            missing = [address for address in missing if address not in self.mapped]
            candidates = [address for address in candidates if address not in taken]
            if not missing or not candidates:
                continue
            pairs = _align(
                [self.bodies[address].size for address in missing],
                [self.body_at(address, self.extent(address) - address).size for address in candidates],
            )
            for source_index, target_index in pairs:
                if self.accept(missing[source_index], candidates[target_index], "ordered"):
                    exact.append(missing[source_index])
        return exact

    def payload(self) -> dict[str, Any]:
        rows: dict[int, dict[str, Any]] = {}
        for address, target in sorted(self.mapped.items()):
            if target in rows:
                continue  # folded bodies keep the first canonical name
            function = self.by_address[address]
            evidence = self.evidence[address]
            # A changed body runs at most to the next known function.
            end = target + self.bodies[address].size if evidence in {"exact", "interface"} else self.extent(target)
            rows[target] = {
                "address": f"0x{target:08X}",
                "canonical_address": f"0x{address:08X}",
                "end": f"0x{end:08X}",
                "evidence": evidence,
                "name": function.name,
                "size": end - target,
            }
            if aliases := self.function_aliases[address]:
                rows[target]["aliases"] = list(aliases)
        program = self.image.target.image_name
        data_entries = [
            {"address": f"0x{next(iter(targets)):08x}", "name": name, "program": program}
            for name, targets in sorted(self.data_votes.items(), key=lambda item: min(item[1]))
            if len(targets) == 1
        ]
        counts = dict.fromkeys(EVIDENCE, 0)
        for row in rows.values():
            counts[row["evidence"]] += 1
        return {
            "functions": [rows[target] for target in sorted(rows)],
            "data": {
                "entries": data_entries,
                "notes": (
                    f"Globals named by exact {self.canonical.build} function bodies or bodies differing only "
                    "in independently mapped Grim virtual slots; "
                    "every observed reference to an entry agrees."
                ),
            },
            "imports": _imports(self.image.path),
            "metadata": {
                "canonical_build": self.canonical.build,
                "canonical_sha256": self.canonical.sha256,
                "file_path": self.image.path.relative_to(matchlib.REPO_ROOT).as_posix(),
                "image_base": f"0x{self.target.image_base:08X}",
                "sha256": self.image.sha256,
            },
            "summary": {
                "canonical_functions": len(self.functions),
                **counts,
                "conflicting": sum(
                    1 for votes in (self.function_votes, self.call_votes) for targets in votes.values() if len(targets) > 1
                ),
                "data": len(data_entries),
            },
        }


def _increasing(chain: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Longest run of canonical-ordered pairs whose targets also increase."""
    tails: list[int] = []
    tail_indices: list[int] = []
    previous = [-1] * len(chain)
    for index, (_, target) in enumerate(chain):
        position = bisect.bisect_left(tails, target)
        if position:
            previous[index] = tail_indices[position - 1]
        if position == len(tails):
            tails.append(target)
            tail_indices.append(index)
        else:
            tails[position] = target
            tail_indices[position] = index
    run = []
    index = tail_indices[-1] if tail_indices else -1
    while index >= 0:
        run.append(chain[index])
        index = previous[index]
    return run[::-1]


def _align(source_sizes: list[int], target_sizes: list[int]) -> list[tuple[int, int]]:
    """Order-preserving index pairs of similar size: the most pairs, then the closest sizes."""

    def error(source: int, target: int) -> float | None:
        if not source or not target:
            return None
        ratio = target / source
        return abs(math.log(ratio)) if 1 / MAX_SIZE_RATIO <= ratio <= MAX_SIZE_RATIO else None

    rows, columns = len(source_sizes), len(target_sizes)
    best = [[(0, 0.0)] * (columns + 1) for _ in range(rows + 1)]
    for row in range(rows - 1, -1, -1):
        for column in range(columns - 1, -1, -1):
            options = [best[row + 1][column], best[row][column + 1]]
            if (cost := error(source_sizes[row], target_sizes[column])) is not None:
                pairs, total = best[row + 1][column + 1]
                options.append((pairs + 1, total - cost))
            best[row][column] = max(options)
    result = []
    row = column = 0
    while row < rows and column < columns:
        cost = error(source_sizes[row], target_sizes[column])
        pairs, total = best[row + 1][column + 1]
        if cost is not None and best[row][column] == (pairs + 1, total - cost):
            result.append((row, column))
            row, column = row + 1, column + 1
        elif best[row][column] == best[row + 1][column]:
            row += 1
        else:
            column += 1
    return result


MAP_FILES = ("functions", "data", "imports", "metadata")


def build_map_files(image: BuildImage, payload: dict[str, Any]) -> dict[Path, str]:
    return {image.map_dir / f"{name}.json": json.dumps(payload[name], indent=2) + "\n" for name in MAP_FILES}


def write_build_map(image: BuildImage, payload: dict[str, Any]) -> None:
    image.map_dir.mkdir(parents=True, exist_ok=True)
    for path, text in build_map_files(image, payload).items():
        path.write_text(text, encoding="utf-8")
    _reference_catalog.cache_clear()


def stale_build_map_files(image: BuildImage, payload: dict[str, Any]) -> list[Path]:
    return [
        path
        for path, text in build_map_files(image, payload).items()
        if not path.is_file() or path.read_text(encoding="utf-8") != text
    ]


def mapped_images(registry: Registry) -> list[BuildImage]:
    """Family builds, with Grim mapped before callers that use its interface."""
    return sorted((
        image
        for images in registry.builds.values()
        for image in images.values()
        if image.canonical_build is not None and not image.is_canonical
    ), key=lambda image: (image.build, image.name != "grim.dll", image.name))


@dataclass(frozen=True, slots=True)
class BuildScanRow:
    status: matchlib.ScratchStatus
    evidence: str


def scan_build(
    registry: Registry,
    build: str,
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT,
    *,
    jobs: int = matchlib.DEFAULT_MATCH_JOBS,
) -> list[BuildScanRow]:
    """Compile every source scratch whose function the build's map places, as that build."""
    evidence: dict[tuple[str, str], str] = {}
    for name, image in registry.builds[build].items():
        if image.target.functions_path.is_file():
            for row in json.loads(image.target.functions_path.read_text(encoding="utf-8")):
                evidence[name, row["name"]] = row["evidence"]
    scratches: list[str] = []
    configs: list[matchlib.ScratchConfig] = []
    owners: list[int] = []
    for conf_path in sorted(match_root.resolve().glob("scratches/*/scratch.conf")):
        config = matchlib.load_scratch_config(conf_path.parent)
        if config.archive is not None or config.import_thunk is not None:
            continue
        if (config.image, config.function) not in evidence:
            continue
        for build_config in registry.image(build, config.image).scratch_configs(config):
            configs.append(build_config)
            owners.append(len(scratches))
        scratches.append(evidence[config.image, config.function])
    statuses = matchlib.evaluate_scratch_configs(
        configs,
        match_root,
        targets={name: image.target for name, image in registry.builds[build].items()},
        jobs=jobs,
        scope="all",
    )
    # Keep each scratch's best compiler.
    best: dict[int, matchlib.ScratchStatus] = {}
    for owner, status in zip(owners, statuses, strict=True):
        rank = (SCAN_STATES.index(status.state), status.ratio or 0.0)
        if owner not in best or rank > (SCAN_STATES.index(best[owner].state), best[owner].ratio or 0.0):
            best[owner] = status
    return [BuildScanRow(best[index], row_evidence) for index, row_evidence in enumerate(scratches)]
