"""Fingerprint a complete compiler object for a matching report."""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

from . import match

# Separate a normalized receipt from a raw object that already names only its basename.
_STAGED_OBJNAME_DOMAIN = b"crimson-report-vc6-objname-v1\0"
_SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")


def candidate_object_sha256(data: bytes, config: match.ScratchConfig, match_root: Path | None = None) -> str:
    if config.archive is not None or config.import_thunk is not None:
        return match.coff_sha256(data)
    obj = match._scratch_object_path(config)
    stage = match._scratch_staging_directory(config, match_root or match.DEFAULT_MATCH_ROOT)
    return _source_object_sha256(data, stage / obj.name)


def _source_object_sha256(data: bytes, object_path: Path) -> str:
    try:
        normalized = _remove_staging_directory(data, object_path)
    except (ValueError, struct.error):
        normalized = None
    if normalized is None:
        return match.coff_sha256(data)
    return hashlib.sha256(_STAGED_OBJNAME_DOMAIN + normalized).hexdigest()


def _remove_staging_directory(data: bytes, object_path: Path) -> bytearray | None:
    machine, count, _, symbols_at, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data)
    if machine != match.IMAGE_FILE_MACHINE_I386 or optional_size:
        return None
    headers_end = 20 + count * _SECTION_HEADER.size
    if headers_end > len(data) or b".debug$S" not in data[20:headers_end]:
        return None
    headers = list(_SECTION_HEADER.iter_unpack(data[20:headers_end]))
    debug = [i for i, header in enumerate(headers) if header[0] == b".debug$S"]
    if len(debug) != 1:
        return None
    section = debug[0]
    _, _, _, size, start, reloc, line, nreloc, nline, flags = headers[section]
    if start < headers_end or start + size > symbols_at or symbols_at > len(data):
        return None
    if (reloc, line, nreloc, nline, flags) != (0, 0, 0, 0, 0x42100040):
        return None

    # Version 2, S_OBJNAME_ST, zero object signature, Pascal name. Only the
    # exact path supplied to this compiler invocation is eligible for removal.
    path = b"Z:" + os.fsencode(object_path.resolve()).replace(b"/", b"\\")
    if len(path) > 255:
        return None
    record = struct.pack("<IHHIB", 2, 7 + len(path), 0x0009, 0, len(path)) + path
    compiler_at = start + len(record)
    if size != len(record) + 58 or data[start:compiler_at] != record:
        return None
    if struct.unpack_from("<HH", data, compiler_at) != (56, 0x1013):
        return None
    # The known S_COMPILE2_ST includes 18 bytes of flags/versions, a counted
    # compiler name and a two-byte terminator. Keep its complete payload.
    if data[compiler_at + 22] != 33 or data[compiler_at + 56 : compiler_at + 58] != b"\0\0":
        return None

    # No code, data or relocation table may also claim the path bytes.
    obj = match.parse_coff_object(data)
    definitions = [
        sym
        for sym in obj.symbols
        if sym.name == ".debug$S"
        and sym.section_number == section + 1
        and sym.value == 0
        and sym.symbol_type == 0
        and sym.storage_class == match.IMAGE_SYM_CLASS_STATIC
        and len(sym.aux_records) == 1
    ]
    if len(definitions) != 1 or struct.unpack_from("<I", definitions[0].aux_records[0])[0] != size:
        return None
    extents = []
    for i, header in enumerate(headers):
        raw_size, raw, reloc, line, nreloc, nline, flags = header[3:]
        if flags & match.IMAGE_SCN_LNK_NRELOC_OVFL:
            return None
        if nline and not line:
            return None
        for pointer, length in ((raw, raw_size), (reloc, 10 * nreloc), (line, 6 * nline)):
            if not pointer:
                continue
            if not headers_end <= pointer <= symbols_at:
                return None
            if start <= pointer < start + size and not (i == section and pointer == start):
                return None
            if length:
                extents.append((pointer, pointer + length))
    previous_end = headers_end
    for lo, hi in sorted(extents):
        if lo < previous_end or hi > symbols_at:
            return None
        previous_end = hi

    name_at = start + 13
    basename_size = len(os.fsencode(object_path.name))
    removed = len(path) - basename_size
    result = bytearray(data)
    result[4:8] = bytes(4)
    struct.pack_into("<I", result, 8, symbols_at - removed)
    struct.pack_into("<H", result, start + 4, 7 + basename_size)
    result[start + 12] = basename_size
    struct.pack_into("<I", result, 20 + section * 40 + 16, size - removed)
    aux = symbols_at + 18 * (definitions[0].raw_index + 1)
    struct.pack_into("<I", result, aux, size - removed)
    for i, header in enumerate(headers):
        for field, pointer in zip((20, 24, 28), header[4:7], strict=True):
            if pointer >= start + size:
                struct.pack_into("<I", result, 20 + i * 40 + field, pointer - removed)
    del result[name_at : name_at + removed]
    return result
