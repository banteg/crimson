from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import BinaryIO, Iterable, Iterator, Mapping
import io

MAGIC = b"paq\x00"


class PaqFormatError(ValueError):
    pass


@dataclass(frozen=True)
class PaqEntry:
    name: str
    data: bytes


def _read_cstring(f: BinaryIO) -> bytes:
    buf = bytearray()
    while True:
        b = f.read(1)
        if not b:
            if not buf:
                return b""
            raise PaqFormatError("unexpected EOF while reading name")
        if b == b"\x00":
            return bytes(buf)
        buf += b


def _open_binary(source: str | Path | BinaryIO, mode: str) -> tuple[BinaryIO, bool]:
    if hasattr(source, "read") or hasattr(source, "write"):
        return source, False  # type: ignore[return-value]
    return open(Path(source), mode), True


def iter_entries(source: str | Path | BinaryIO) -> Iterator[PaqEntry]:
    f, should_close = _open_binary(source, "rb")
    try:
        header = f.read(4)
        if header != MAGIC:
            raise PaqFormatError(f"bad magic: {header!r}")
        while True:
            name_bytes = _read_cstring(f)
            if not name_bytes:
                return
            sizes = f.read(12)
            if len(sizes) != 12:
                raise PaqFormatError("unexpected EOF while reading entry header")
            total_size, head_lo, head_hi = struct.unpack("<III", sizes)
            if total_size < 0:
                raise PaqFormatError("negative size")
            data_len = max(total_size - 8, 0)
            data = f.read(data_len)
            if len(data) != data_len:
                raise PaqFormatError("unexpected EOF while reading entry data")
            head = struct.pack("<II", head_lo, head_hi)
            full = head[:total_size] + data
            name = name_bytes.decode("utf-8", "replace")
            yield PaqEntry(name=name, data=full)
    finally:
        if should_close:
            f.close()


def read_paq(source: str | Path | BinaryIO) -> dict[str, bytes]:
    return {entry.name: entry.data for entry in iter_entries(source)}


def decode_bytes(data: bytes) -> dict[str, bytes]:
    return read_paq(io.BytesIO(data))


def _iter_items(entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]):
    if isinstance(entries, Mapping):
        return entries.items()
    return ((e.name, e.data) if isinstance(e, PaqEntry) else e for e in entries)


def write_paq(dest: str | Path | BinaryIO, entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]) -> None:
    f, should_close = _open_binary(dest, "wb")
    try:
        f.write(MAGIC)
        for name, data in _iter_items(entries):
            if isinstance(name, Path):
                name = str(name)
            if isinstance(data, memoryview):
                data = data.tobytes()
            if not isinstance(data, (bytes, bytearray)):
                raise TypeError("entry data must be bytes-like")
            name_bytes = str(name).encode("utf-8")
            f.write(name_bytes)
            f.write(b"\x00")
            total_size = len(data)
            head = bytes(data[:8]).ljust(8, b"\x00")
            head_lo, head_hi = struct.unpack("<II", head)
            f.write(struct.pack("<III", total_size, head_lo, head_hi))
            if total_size > 8:
                f.write(data[8:])
    finally:
        if should_close:
            f.close()


def encode_bytes(entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    write_paq(buf, entries)
    return buf.getvalue()
