from __future__ import annotations

import struct
from collections import Counter
from pathlib import Path

import pefile
import pytest

from crimson_re import match_builds
from crimson_re.match_freeware_pe_metadata import metadata_ranges
from tests.test_match_content_provenance import minimal_pe


def import_export_pe(tmp_path: Path) -> pefile.PE:
    path = tmp_path / "sample.dll"
    minimal_pe(path)
    data = bytearray(path.read_bytes())
    directories = 0x98 + 96
    struct.pack_into("<II", data, directories, 0x2140, 0x50)
    struct.pack_into("<II", data, directories + 8, 0x2040, 48)
    struct.pack_into("<II", data, directories + 12 * 8, 0x20a0, 16)
    section = memoryview(data)[0x400:0x600]
    section[:] = bytes(0x200)
    struct.pack_into("<5I", section, 0x40, 0x2090, 0, 0, 0x2120, 0x20a0)
    for table in (0x90, 0xa0):
        struct.pack_into("<4I", section, table, 0x2100, 0x80000007, 0x2108, 0)
    section[0x100:0x108] = b"\x03\x00Test\x00\x00"
    section[0x108:0x10d] = b"\x01\x00ID\x00"
    section[0x120:0x128] = b"dep.dll\x00"
    struct.pack_into("<7I", section, 0x14c, 0x2172, 1, 1, 1, 0x2168, 0x216c, 0x2170)
    struct.pack_into("<IIH", section, 0x168, 0x2188, 0x2180, 0)
    section[0x172:0x17a] = b"own.dll\x00"
    section[0x180:0x185] = b"Name\x00"
    section[0x188:0x190] = b"dep.Foo\x00"
    return pefile.PE(data=bytes(data), fast_load=True)


def test_metadata_bounds_names_tables_terminators_and_forwarders(tmp_path: Path) -> None:
    with import_export_pe(tmp_path) as pe:
        ranges = [(lo - 0x400000, hi - 0x400000, kind) for lo, hi, kind in metadata_ranges(pe)]
    assert (0x2040, 0x2068, "import-descriptors") in ranges
    assert (0x2090, 0x20a0, "import-lookup-table") in ranges
    assert (0x20a0, 0x20b0, "import-address-table") in ranges
    assert (0x2100, 0x2107, "import-hint-name") in ranges
    assert (0x2107, 0x2108, "import-name-alignment") in ranges
    assert (0x2108, 0x210d, "import-hint-name") in ranges
    assert (0x2188, 0x2190, "export-forwarder") in ranges
    for va in (0x2068, 0x210d, 0x2185):
        assert all(not lo <= va < hi for lo, hi, _ in ranges)


def test_shared_iat_and_ilt_count_the_same_storage_once(tmp_path: Path) -> None:
    with import_export_pe(tmp_path) as pe:
        pe.set_dword_at_rva(0x2040, 0)
        ranges = metadata_ranges(pe)
    assert not any(kind == "import-lookup-table" for _, _, kind in ranges)
    assert (0x4020a0, 0x4020b0, "import-address-table") in ranges


@pytest.mark.parametrize(("rva", "value", "error"), [
    (0x20ac, 0xdeadcafe, "address table length"),
    (0x2064, 0x20a0, "metadata outside image sections"),
    (0x2170, 1, "ordinal outside"),
    (0x216c, 0x20a0, "unterminated export-name"),
    (0x20a0, 0, "address table length"),
])
def test_unknown_boundaries_fail_closed(tmp_path: Path, rva: int, value: int, error: str) -> None:
    with import_export_pe(tmp_path) as pe:
        if rva == 0x2170:
            pe.set_word_at_rva(rva, value)  # EAT ordinal slots are 16-bit.
        else:
            pe.set_dword_at_rva(rva, value)
        with pytest.raises(ValueError, match=error):
            metadata_ranges(pe)


@pytest.mark.parametrize(("build", "exe_imports", "dll_imports", "dll_exports"), [
    ("1.0.2", 1834, 3004, 77),
    ("1.3.0", 2052, 3003, 78),
    ("1.4.0", 1898, 3026, 78),
])
def test_originals_reconcile_all_metadata_extents(build: str, exe_imports: int, dll_imports: int, dll_exports: int) -> None:
    for image in match_builds.load_registry().builds[build].values():
        if not image.path.is_file():
            pytest.skip("pinned freeware image unavailable")
        with pefile.PE(str(image.path), fast_load=True) as pe:
            ranges = metadata_ranges(pe)
            base = pe.OPTIONAL_HEADER.ImageBase
            iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]]
            assert (base + iat.VirtualAddress, base + iat.VirtualAddress + iat.Size, "import-address-table") in ranges
        totals = Counter()
        end = 0
        for lo, hi, kind in ranges:
            assert end <= lo < hi
            end = hi
            totals[kind.split("-")[0]] += hi - lo
        assert totals == ({"import": exe_imports} if image.name == "crimson.exe" else
                          {"import": dll_imports, "export": dll_exports})
