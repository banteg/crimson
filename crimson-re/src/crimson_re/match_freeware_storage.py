"""Verify a located source COFF data symbol against a freeware PE at its preferred base."""
from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import Mapping
from typing import Any

from . import match as matchlib
from .match_data_report import DATA_SECTIONS

# The trailing storage classifier on a VC6 decorated C++ data symbol records
# the declared type. Pointer-like encodings also describe arrays, so avoid them.
_SCALAR = re.compile(r"@[0234](_[NJK]|[CDEFGHIJKMN])[ABCD]$")
_WIDTH = {"C": 1, "D": 1, "E": 1, "_N": 1, "F": 2, "G": 2, "H": 4, "I": 4,
          "J": 4, "K": 4, "M": 4, "N": 8, "_J": 8, "_K": 8}
_PRIMARY_VTABLE = re.compile(r"\?\?_7.+@@6B@")
_LITERAL = re.compile(r"^\?\?_C@_([01])([0-9]|[A-P]+@)")


def _encoded_extent(name: str) -> tuple[int, str] | None:
    if (mangled := _SCALAR.search(name)) and name.lstrip("_").startswith("?"):
        return _WIDTH[mangled[1]], "vc6-scalar"
    if real := re.fullmatch(r"__real@(4|8)@[0-9a-fA-F]+", name):
        return int(real[1]), "vc6-real-literal"
    # MSVC encodes the exact byte count, including the terminator. Its single
    # decimal digit encodes 1..10 and its A..P digits encode hexadecimal nibbles.
    if literal := _LITERAL.match(name):
        encoded = literal[2]
        size = (int(encoded) + 1 if len(encoded) == 1 else
                int("".join(f"{ord(n) - ord('A'):x}" for n in encoded[:-1]), 16))
        return size, "vc6-string-literal"
    return None


def _terminated(name: str, data: bytes) -> bool:
    width = 2 if name.startswith("??_C@_1") else 1
    return len(data) % width == 0 and data.endswith(bytes(width))


def _extent(
    symbol: matchlib.CoffSymbol, section: matchlib.CoffSection | None, declared_size: int | None,
) -> tuple[int, str] | None:
    if _PRIMARY_VTABLE.fullmatch(symbol.name):
        if (section is None or symbol.storage_class != matchlib.IMAGE_SYM_CLASS_EXTERNAL or symbol.value
                or section.comdat_key != symbol.name or not section.characteristics & matchlib.IMAGE_SCN_LNK_COMDAT
                or section.name.split("$", 1)[0] != ".rdata" or not section.logical_size
                or section.logical_size % 4 or len(section.data) != section.logical_size or any(section.data)):
            return None
        slots = sorted((r.virtual_address, r.relocation_type) for r in section.relocations)
        if slots != [(offset, matchlib.IMAGE_REL_I386_DIR32) for offset in range(0, section.logical_size, 4)]:
            return None
        return section.logical_size, "vc6-vtable-comdat"
    encoded = _encoded_extent(symbol.name)
    if section is None:
        if (symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL and symbol.value > 0
                and (encoded is None or encoded[0] == symbol.value)):
            return symbol.value, "coff-common-size"
        return None
    if encoded is None:
        return (declared_size, "vc6-sizeof") if declared_size is not None else None
    size, method = encoded
    if method != "vc6-scalar":
        if (symbol.value or section.comdat_key != symbol.name or not section.characteristics & matchlib.IMAGE_SCN_LNK_COMDAT
                or section.characteristics & matchlib.IMAGE_SCN_CNT_UNINITIALIZED_DATA):
            return None
        if method == "vc6-string-literal" and not _terminated(symbol.name, section.data[:size]):
            return None
    return encoded


def _pe_relocations_agree(
    relocations: Mapping[int, int] | None, address: int, size: int, offsets: list[int],
) -> bool:
    if relocations is None:
        return True  # The linker stripped base relocations. The COFF recipe still has to resolve.
    end = address + size
    # Check unaligned fixups and partial intersections at both boundaries.
    sites = (range(address - 7, end) if size + 7 < len(relocations) else relocations.keys())
    overlapping = {}
    for site in sites:
        if kind := relocations.get(site):
            width = {1: 2, 2: 2, 3: 4, 4: 2, 10: 8}.get(kind, 8)
            if site < end and site + width > address:
                overlapping[site - address] = kind
    return overlapping == dict.fromkeys(offsets, 3)


def prove(
    obj: matchlib.CoffObject, symbol: matchlib.CoffSymbol, address: int, image: matchlib.LoadedImage,
    *, bindings: Mapping[int, int], relocations: Mapping[int, int] | None, declared_size: int | None = None,
) -> dict[str, Any] | None:
    """The caller establishes the symbol VA and any supplied sizeof or relocation target independently."""
    if (symbol.section_number < 0 or symbol.section_number > len(obj.sections)
            or symbol.storage_class not in {matchlib.IMAGE_SYM_CLASS_STATIC, matchlib.IMAGE_SYM_CLASS_EXTERNAL}
            or symbol.symbol_type & matchlib.SYM_TYPE_FUNCTION):
        return None
    section = obj.sections[symbol.section_number - 1] if symbol.section_number else None
    if section and (section.name.split("$", 1)[0] not in DATA_SECTIONS or symbol.name == section.name
                    or section.characteristics & (0x20000000 | matchlib.IMAGE_SCN_CNT_CODE)):
        return None
    extent = _extent(symbol, section, declared_size)
    if extent is None:
        return None
    size, method = extent
    if size <= 0 or (declared_size is not None and size != declared_size):
        return None
    original = matchlib._image_bytes(image, address, size)
    if original is None:
        return None
    fixups: list[dict[str, Any]] = []
    if section is None:
        storage = "coff-common"
    else:
        start = symbol.value
        end = start + size
        if section.logical_size is None or end > section.logical_size:
            return None
        if any(s.raw_index != symbol.raw_index and s.section_number == symbol.section_number and s.name != section.name
               and start <= s.value < end and s.storage_class in {matchlib.IMAGE_SYM_CLASS_STATIC, matchlib.IMAGE_SYM_CLASS_EXTERNAL}
               for s in obj.symbols):
            return None
        storage = "coff-bss" if section.characteristics & matchlib.IMAGE_SCN_CNT_UNINITIALIZED_DATA else "coff-data"
        data = bytearray(section.data[start:end])
        by_index = {s.raw_index: s for s in obj.symbols}
        for reloc in sorted(section.relocations, key=lambda item: item.virtual_address):
            width = matchlib.IMAGE_REL_I386_WIDTHS.get(reloc.relocation_type)
            offset = reloc.virtual_address - start
            if width is None:
                return None
            if width == 0 or offset >= size or offset + width <= 0:
                continue
            target = bindings.get(reloc.symbol_index)
            if (storage != "coff-data" or reloc.relocation_type != matchlib.IMAGE_REL_I386_DIR32
                    or target is None or reloc.symbol_index not in by_index or offset < 0 or offset + 4 > len(data)
                    or (fixups and offset < fixups[-1]["offset"] + 4)):
                return None
            addend, = struct.unpack_from("<i", data, offset)
            struct.pack_into("<I", data, offset, (target + addend) & 0xFFFFFFFF)
            fixups.append({"offset": offset, "symbol": by_index[reloc.symbol_index].name, "target": target, "addend": addend})
        if storage == "coff-data" and data != original:
            return None
    if storage in {"coff-bss", "coff-common"} and any(original):
        return None
    if not _pe_relocations_agree(relocations, address, size, [r["offset"] for r in fixups]):
        return None
    return {"symbol": symbol.name, "address": address, "size": size, "storage": storage, "extent_evidence": method,
            "initializer_sha256": hashlib.sha256(original).hexdigest(), "relocations": fixups}


def validate(
    receipt: dict[str, Any], image: matchlib.LoadedImage, *, relocations: Mapping[int, int] | None,
) -> None:
    """Ordinary report verification checks the receipt against original storage and fixup sites."""
    address, size, storage = receipt["address"], receipt["size"], receipt["storage"]
    if (type(address) is not int or type(size) is not int or size <= 0
            or storage not in {"coff-bss", "coff-common", "coff-data"}
            or receipt["extent_evidence"] not in {"coff-common-size", "vc6-sizeof", "vc6-scalar",
                                                  "vc6-string-literal", "vc6-real-literal", "vc6-vtable-comdat"}
            or (storage == "coff-common") != (receipt["extent_evidence"] == "coff-common-size")):
        raise ValueError("invalid freeware data storage or extent")
    method, name = receipt["extent_evidence"], receipt["symbol"]
    if not isinstance(name, str) or not name:
        raise ValueError("missing freeware data source symbol")
    encoded = _encoded_extent(name)
    if encoded is not None and (encoded[0] != size or (storage != "coff-common" and encoded[1] != method)):
        raise ValueError("freeware data extent differs from its decorated COFF symbol")
    if bool(_PRIMARY_VTABLE.fullmatch(name)) != (method == "vc6-vtable-comdat"):
        raise ValueError("invalid freeware virtual table extent")
    if encoded is None and method not in {"coff-common-size", "vc6-sizeof", "vc6-vtable-comdat"}:
        raise ValueError("freeware data extent requires a decorated COFF symbol")
    original = matchlib._image_bytes(image, address, size)
    if (original is None or hashlib.sha256(original).hexdigest() != receipt["initializer_sha256"]
            or (storage != "coff-data" and any(original))
            or (method in {"vc6-real-literal", "vc6-string-literal"} and storage != "coff-data")
            or (method == "vc6-string-literal" and not _terminated(name, original))):
        raise ValueError("freeware data initializer differs from the original image")
    offsets = []
    for fixup in receipt["relocations"]:
        offset, target, addend = fixup["offset"], fixup["target"], fixup["addend"]
        if (storage != "coff-data" or type(offset) is not int or offset < 0 or offset + 4 > size
                or (offsets and offset < offsets[-1] + 4) or not isinstance(fixup["symbol"], str) or not fixup["symbol"]
                or type(target) is not int or not 0 <= target < 2**32 or type(addend) is not int
                or not -(2**31) <= addend < 2**31 or struct.unpack_from("<I", original, offset)[0] != (target + addend) & 0xFFFFFFFF):
            raise ValueError("invalid freeware data pointer relocation")
        offsets.append(offset)
    if method == "vc6-vtable-comdat" and (
        storage != "coff-data" or size % 4 or offsets != list(range(0, size, 4))
        or any(fixup["addend"] for fixup in receipt["relocations"])
    ):
        raise ValueError("freeware virtual table requires a zero-addend method relocation at every slot")
    if not _pe_relocations_agree(relocations, address, size, offsets):
        raise ValueError("freeware data pointer sites differ from PE base relocations")
