"""Import and export records sharing the freeware images' data sections."""

from __future__ import annotations

import struct

import pefile

from .match_data_report import DATA_SECTIONS


def metadata_ranges(pe: pefile.PE) -> list[tuple[int, int, str]]:
    """Return disjoint, file-backed PE structures as half-open native address ranges."""
    if pe.OPTIONAL_HEADER.Magic != pefile.OPTIONAL_HEADER_MAGIC_PE:
        raise ValueError("freeware metadata requires a PE32 image")

    ranges: set[tuple[int, int, str]] = set()
    hint_names: set[tuple[int, int]] = set()

    def section_end(rva: int) -> int:
        section = pe.get_section_by_rva(rva)
        if section is None or rva < section.VirtualAddress:
            raise ValueError(f"PE metadata outside image sections at RVA {rva:#x}")
        return section.VirtualAddress + min(section.SizeOfRawData, section.Misc_VirtualSize)

    def record(rva: int, size: int, kind: str) -> bytes:
        if size <= 0 or rva + size > section_end(rva):
            raise ValueError(f"invalid {kind} extent at RVA {rva:#x}")
        data = pe.get_data(rva, size)
        if len(data) != size:
            raise ValueError(f"truncated {kind} at RVA {rva:#x}")
        ranges.add((rva, rva + size, kind))
        return data

    def name_record(rva: int, kind: str, prefix: int = 0) -> int:
        name = pe.get_string_at_rva(rva + prefix)
        if not name or not record(rva, prefix + len(name) + 1, kind).endswith(name + b"\0"):
            raise ValueError(f"unterminated {kind} at RVA {rva:#x}")
        return rva + prefix + len(name) + 1

    def directory(key: str) -> tuple[int, int]:
        index = pefile.DIRECTORY_ENTRY[key]
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if index >= len(directories):
            return 0, 0
        data = directories[index]
        if bool(data.VirtualAddress) != bool(data.Size):
            raise ValueError(f"invalid PE directory extent: {key}")
        return int(data.VirtualAddress), int(data.Size)

    import_rva, import_size = directory("IMAGE_DIRECTORY_ENTRY_IMPORT")
    iat_rva, iat_size = directory("IMAGE_DIRECTORY_ENTRY_IAT")
    export_rva, export_size = directory("IMAGE_DIRECTORY_ENTRY_EXPORT")
    if import_rva:
        end = import_rva + import_size
        for rva in range(import_rva, end - 19, 20):
            descriptor = record(rva, 20, "import-descriptors")
            if not any(descriptor):
                break
            lookup, _, _, name_rva, first = struct.unpack("<5I", descriptor)
            name_record(name_rva, "import-module-name")
            table = lookup or first
            # Each lookup table is terminated by a zero DWORD in the PE.
            for slot in range(table, section_end(table) - 3, 4):
                thunk = pe.get_dword_at_rva(slot)
                if thunk is None:
                    raise ValueError(f"truncated import thunk at RVA {slot:#x}")
                if thunk == 0:
                    break
                if not thunk & 0x80000000:
                    hint_names.add((thunk, name_record(thunk, "import-hint-name", prefix=2)))
            else:
                raise ValueError(f"unterminated import lookup table at RVA {table:#x}")
            size = slot + 4 - table
            if lookup and lookup != first:
                record(lookup, size, "import-lookup-table")
            if iat_rva and not iat_rva <= first < first + size <= iat_rva + iat_size:
                raise ValueError(f"import thunks outside declared IAT at RVA {first:#x}")
            entries = record(first, size, "import-address-table")
            if entries[-4:] != bytes(4) or any(not value for (value,) in struct.iter_unpack("<I", entries[:-4])):
                raise ValueError(f"import address table length differs from lookup at RVA {first:#x}")
        else:
            raise ValueError(f"unterminated import descriptors at RVA {import_rva:#x}")

    # Hint/name records allow a zero byte to align the next record to a word.
    starts = {lo for lo, _ in hint_names}
    for _, end in hint_names:
        if end % 2 and end + 1 in starts and pe.get_data(end, 1) == b"\0":
            record(end, 1, "import-name-alignment")

    if export_rva:
        if export_size < 40:
            raise ValueError("truncated PE export directory")
        header = record(export_rva, 40, "export-directory")
        name, _, count, named, addresses, names, ordinals = struct.unpack_from("<7I", header, 12)
        name_record(name, "export-module-name")
        if count:
            for (target,) in struct.iter_unpack("<I", record(addresses, 4 * count, "export-address-table")):
                export_end = export_rva + export_size
                if export_rva <= target < export_end and name_record(target, "export-forwarder") > export_end:
                    raise ValueError(f"forwarder crosses PE export directory end at RVA {target:#x}")
        if named:
            entries = record(ordinals, 2 * named, "export-ordinal-table")
            if any(index >= count for (index,) in struct.iter_unpack("<H", entries)):
                raise ValueError("export name ordinal outside function address table")
            for (rva,) in struct.iter_unpack("<I", record(names, 4 * named, "export-name-table")):
                name_record(rva, "export-name")

    base = int(pe.OPTIONAL_HEADER.ImageBase)
    result: list[tuple[int, int, str]] = []
    for lo, hi, kind in sorted(ranges):
        section = pe.get_section_by_rva(lo)
        if section.Name.rstrip(b"\0").decode("ascii") not in DATA_SECTIONS:
            continue
        start, end = base + lo, base + hi
        if result and start < result[-1][1]:
            raise ValueError(f"overlapping PE metadata at RVA {lo:#x}")
        if result and result[-1][1:] == (start, kind):
            previous = result.pop()
            start = previous[0]
        result.append((start, end, kind))
    return result
