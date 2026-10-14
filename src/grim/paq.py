"""
PAQ archive format (Crimsonland).

File layout:
  - magic: 4 bytes, ASCII "paq\\0"
  - entries: repeated until EOF
      - name: NUL-terminated UTF-8 string (relative path)
      - size: u32 little-endian payload size
      - payload: raw file bytes of length `size`
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from pathlib import Path

MAGIC = b"paq\x00"
_U32 = struct.Struct("<I")


def iter_entries_bytes(data: bytes) -> Iterator[tuple[str, bytes]]:
    if not data.startswith(MAGIC):
        raise ValueError("Invalid PAQ archive at offset 0: missing magic")
    pos = len(MAGIC)
    total = len(data)
    while pos < total:
        nul = data.find(b"\x00", pos)
        if nul < 0 or nul + 1 + _U32.size > total:
            raise ValueError(f"Invalid PAQ archive at offset {pos}: truncated entry header")
        try:
            name = data[pos:nul].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Invalid PAQ archive at offset {pos}: {exc}") from exc
        (size,) = _U32.unpack_from(data, nul + 1)
        payload_start = nul + 1 + _U32.size
        payload_end = payload_start + size
        if payload_end > total:
            raise ValueError(f"Invalid PAQ archive at offset {payload_end}: truncated payload")
        yield name, data[payload_start:payload_end]
        pos = payload_end


def iter_entries(source: str | Path) -> Iterator[tuple[str, bytes]]:
    data = Path(source).read_bytes()
    yield from iter_entries_bytes(data)


def read_paq(source: str | Path) -> list[tuple[str, bytes]]:
    return list(iter_entries(source))


def build_entries(entries: Iterable[tuple[str, bytes]]) -> bytes:
    parts: list[bytes] = [MAGIC]
    for name, data in entries:
        payload = data.tobytes() if isinstance(data, memoryview) else bytes(data)
        parts.append(str(name).encode("utf-8"))
        parts.append(b"\x00")
        parts.append(_U32.pack(len(payload)))
        parts.append(payload)
    return b"".join(parts)


def write_paq(dest: str | Path, entries: Iterable[tuple[str, bytes]]) -> None:
    Path(dest).write_bytes(build_entries(entries))
