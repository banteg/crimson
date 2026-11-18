"""Place freeware data symbols through the original operands of exact compiled bodies."""

from __future__ import annotations

import re
import struct
from collections import defaultdict
from typing import Any

import capstone
import pefile

from . import match, match_builds, match_data_report, match_source_receipt

Context = tuple[dict[str, Any], match.ScratchConfig, match.CoffObject, dict[int, int]]


def _exact(row: dict[str, Any]) -> bool:
    return (row.get("ownership") == "game" and row.get("native_kind") == "function"
            and row.get("candidate") == "source" and row["matched"] and row["proof"]["body_byte_exact"])


def _operand_sites(image: match.LoadedImage, row: dict[str, Any]) -> dict[int, int]:
    """Map absolute PE operand storage addresses to instruction starts; exclude direct branches."""
    sites = {}
    raw = image.function_bytes(row["address"], row["end"])
    for ins in match_builds._flow_disassembler().disasm(raw, row["address"]):
        if ins.disp_size == 4:
            sites[ins.address + ins.disp_offset] = ins.address
        if ins.imm_size == 4 and not ins.group(capstone.CS_GRP_BRANCH_RELATIVE):
            sites[ins.address + ins.imm_offset] = ins.address
    return sites


class _Image:
    def __init__(self, image: match_builds.BuildImage) -> None:
        self.target = match.load_image(image.path)
        with pefile.PE(str(image.path), fast_load=True) as pe:
            base = pe.OPTIONAL_HEADER.ImageBase
            self.ranges = [
                (base + s.VirtualAddress, base + s.VirtualAddress + s.Misc_VirtualSize)
                for s in pe.sections if s.Name.rstrip(b"\0").decode("ascii") in match_data_report.DATA_SECTIONS
                and not s.Characteristics & match_builds.IMAGE_SCN_MEM_EXECUTE
            ]
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            self.imports = {slot.address + offset for desc in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
                            for slot in desc.imports for offset in range(4)}

    def in_data(self, address: int) -> bool:
        return address not in self.imports and any(lo <= address < hi for lo, hi in self.ranges)

    @staticmethod
    def name(symbol: str, aliases: dict[str, str]) -> str | None:
        key = match._symbol_lookup_name(symbol)
        name = aliases.get(key, key)
        if symbol.startswith(("??_C@", "__real@", "$", ".")) or not re.fullmatch(r"[a-zA-Z_]\w*", name):
            return None
        return name


def _bindings(
    image: _Image, row: dict[str, Any], config: match.ScratchConfig, obj: match.CoffObject,
) -> tuple[dict[int, int], list[tuple[int, dict[str, Any]]]]:
    functions = [s for s in obj.symbols if match._is_function_symbol(s)
                 and (config.symbol is None or match._symbol_matches(s.name, config.symbol))]
    if len(functions) != 1:
        raise ValueError(f"{row['name']}: ambiguous freeware COFF function")
    function = functions[0]
    section = obj.sections[function.section_number - 1]
    symbols = {s.raw_index: s for s in obj.symbols}
    sites = _operand_sites(image.target, row)
    aliases = {match._symbol_lookup_name(raw): name for raw, name in config.reference_aliases}
    addresses: dict[int, set[int]] = defaultdict(set)
    refs: dict[tuple[int, str], dict[str, Any]] = {}
    for reloc in sorted(section.relocations, key=lambda reloc: reloc.virtual_address):
        off = reloc.virtual_address - function.value
        if not 0 <= off <= row["size"] - 4 or reloc.relocation_type not in (match.IMAGE_REL_I386_DIR32, match.IMAGE_REL_I386_REL32):
            continue
        site = row["address"] + off
        value = int.from_bytes(image.target.function_bytes(site, site + 4), "little")
        addend, = struct.unpack_from("<i", section.data, reloc.virtual_address)
        symbol = symbols[reloc.symbol_index]
        relative = reloc.relocation_type == match.IMAGE_REL_I386_REL32
        base = (value - addend + (site + 4 if relative else 0)) & 0xFFFFFFFF
        addresses[symbol.raw_index].add(base)
        if relative or not image.in_data(base) or match._is_import_symbol(symbol.name):
            continue
        if site not in sites:
            raise ValueError(f"{row['name']}: data relocation at {site:#x} is not an absolute instruction operand")
        key = (base, symbol.name)
        if key in refs:
            refs[key].setdefault("additional_operands", []).append([site, addend])
        else:
            refs[key] = {"function": row["address"], "site": site, "symbol": symbol.name, "addend": addend,
                         "name": image.name(symbol.name, aliases), "candidate_object_sha256": row["proof"]["candidate_object_sha256"]}
    bindings = {index: next(iter(values)) for index, values in addresses.items() if len(values) == 1}
    return bindings, [(base, ref) for (base, _), ref in refs.items()]


def _placements(
    image: match_builds.BuildImage, refs: dict[int, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    from . import match_freeware_data_ownership

    votes: dict[str, set[int]] = defaultdict(set)
    for address, witnesses in refs.items():
        for ref in witnesses:
            if ref["name"] is not None:
                votes[ref["name"]].add(address)
    ownership = match_freeware_data_ownership.LabelOwnership(image)
    result = []
    for address, witnesses in sorted(refs.items()):
        names = sorted({label for ref in witnesses if (label := ref["name"]) is not None
                        and votes[label] == {address} and ownership.placed.get(label, {address}) == {address}})
        owner, evidence = ownership.lookup(address, names)
        result.append({"image": image.name, "address": address, "names": names,
                       "owner": owner, "ownership_evidence": evidence,
                       "references": sorted(witnesses, key=lambda r: (r["function"], r["symbol"], r["site"]))})
    return result


def refresh(
    version: str, functions: list[dict[str, Any]], statuses: list[match.ScratchStatus],
) -> tuple[list[dict[str, Any]], list[Context]]:
    configs = {(s.config.image, s.address): s.config for s in statuses}
    placements = []
    contexts = []
    for name, image in match_builds.load_registry().builds[version].items():
        native = _Image(image)
        refs: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for row in functions:
            if row["image"] != name or not _exact(row):
                continue
            config = configs[name, row["address"]]
            data = match._scratch_object_path(config).read_bytes()
            if match_source_receipt.candidate_object_sha256(data, config) != row["proof"]["candidate_object_sha256"]:
                raise ValueError(f"{row['name']}: data references have a different source object")
            obj = match.parse_coff_object(data)
            addresses, witnesses = _bindings(native, row, config, obj)
            contexts.append((row, config, obj, addresses))
            for address, witness in witnesses:
                refs[address].append(witness)
        placements.extend(_placements(image, refs))
    return placements, contexts


def _aliases_for_row(image: match_builds.BuildImage, row: dict[str, Any]) -> dict[str, str]:
    """Find aliases active in this source, including build-specific overrides."""
    directory = match.DEFAULT_MATCH_ROOT / "scratches" / row["name"]
    if not (directory / "scratch.conf").is_file():
        return {}
    source = (match.REPO_ROOT / row["source"]).resolve()
    base_config = match.load_scratch_config(directory)
    aliases = {}
    for config in image.scratch_configs(base_config):
        if (config.directory / config.source).resolve() == source:
            aliases.update((match._symbol_lookup_name(raw), name) for raw, name in config.reference_aliases)
    return aliases


def validate(version: str, functions: list[dict[str, Any]], placements: list[dict[str, Any]]) -> None:
    """Verify saved operand locations, PE addresses, source aliases, conflicts and attributed owners."""
    expected = []
    for name, image in match_builds.load_registry().builds[version].items():
        native = _Image(image)
        exact = {r["address"]: r for r in functions if r["image"] == name and _exact(r)}
        decoded = {address: _operand_sites(native.target, row) for address, row in exact.items()}
        expected_sites = {
            at for operands in decoded.values() for at in operands
            if native.in_data(int.from_bytes(native.target.function_bytes(at, at + 4), "little"))
        }
        aliases: dict[int, dict[str, str]] = {}
        refs: dict[int, list[dict[str, Any]]] = defaultdict(list)
        sites = set()
        for placement in placements:
            if placement["image"] != name:
                continue
            address = placement["address"]
            if type(address) is not int or address in refs or not native.in_data(address) or not placement["references"]:
                raise ValueError(f"{name}: invalid or duplicate freeware data placement")
            symbols = set()
            for ref in placement["references"]:
                if ref.keys() - {"additional_operands"} != {"function", "symbol", "site", "addend", "name", "candidate_object_sha256"}:
                    raise ValueError(f"{name}: invalid freeware data reference receipt")
                function, symbol, at, addend = ref["function"], ref["symbol"], ref["site"], ref["addend"]
                if (type(function) is not int or function not in exact or not isinstance(symbol, str) or not symbol
                        or match._is_import_symbol(symbol) or (function, symbol) in symbols):
                    raise ValueError(f"{name}: invalid source object reference to {address:#x}")
                row = exact[function]
                if ref["candidate_object_sha256"] != row["proof"]["candidate_object_sha256"]:
                    raise ValueError(f"{name}: data references have a different source object")
                if function not in aliases:
                    aliases[function] = _aliases_for_row(image, row)
                if ref["name"] != native.name(symbol, aliases[function]):
                    raise ValueError(f"{name}: data reference differs from the source name at {at:#x}")
                previous = -1
                for site, displacement in [(at, addend), *ref.get("additional_operands", [])]:
                    if (type(site) is not int or site <= previous or site in sites or site not in decoded[function]
                            or type(displacement) is not int or not -(1 << 31) <= displacement < 1 << 31):
                        raise ValueError(f"{name}: invalid or duplicate data operand in {function:#x}")
                    value = int.from_bytes(native.target.function_bytes(site, site + 4), "little")
                    if (address + displacement) & 0xFFFFFFFF != value:
                        raise ValueError(f"{name}: data reference differs from original operand at {site:#x}")
                    sites.add(site)
                    previous = site
                symbols.add((function, symbol))
                refs[address].append(ref)
        if not expected_sites <= sites:
            raise ValueError(f"{name}: missing original data operand at {min(expected_sites - sites):#x}")
        expected.extend(_placements(image, refs))
    if placements != expected:
        raise ValueError("freeware data placements differ from the verified image, aliases or ownership")
