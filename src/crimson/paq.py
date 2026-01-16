from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Mapping

from construct import Bytes, CString, Int32ul, Struct
from construct.core import ConstructError

MAGIC = b"paq\x00"


class PaqFormatError(ValueError):
    pass


@dataclass(frozen=True)
class PaqEntry:
    name: str
    data: bytes


PAQ_ENTRY = Struct(
    "name" / CString("utf8"),
    "total_size" / Int32ul,
    "head_lo" / Int32ul,
    "head_hi" / Int32ul,
    "payload" / Bytes(lambda ctx: max(ctx.total_size - 8, 0)),
)


def _open_binary(source: str | Path | BinaryIO, mode: str) -> tuple[BinaryIO, bool]:
    if hasattr(source, "read") or hasattr(source, "write"):
        return source, False  # type: ignore[return-value]
    return open(Path(source), mode), True


def _iter_entries_bytes(data: bytes) -> Iterator[PaqEntry]:
    if data[:4] != MAGIC:
        raise PaqFormatError(f"bad magic: {data[:4]!r}")
    offset = 4
    size = len(data)
    while offset < size:
        try:
            entry = PAQ_ENTRY.parse(data[offset:])
        except ConstructError as exc:
            raise PaqFormatError(f"failed to parse entry: {exc}") from exc
        built = PAQ_ENTRY.build(entry)
        offset += len(built)
        head = (entry.head_lo.to_bytes(4, "little") + entry.head_hi.to_bytes(4, "little"))
        full = head[: entry.total_size] + entry.payload
        yield PaqEntry(name=entry.name, data=full)


def iter_entries(source: str | Path | BinaryIO) -> Iterator[PaqEntry]:
    f, should_close = _open_binary(source, "rb")
    try:
        data = f.read()
    finally:
        if should_close:
            f.close()
    yield from _iter_entries_bytes(data)


def read_paq(source: str | Path | BinaryIO) -> dict[str, bytes]:
    return {entry.name: entry.data for entry in iter_entries(source)}


def decode_bytes(data: bytes) -> dict[str, bytes]:
    return read_paq(io.BytesIO(data))


def _iter_items(entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]):
    if isinstance(entries, Mapping):
        return entries.items()
    return ((e.name, e.data) if isinstance(e, PaqEntry) else e for e in entries)


def _build_entries(entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]) -> bytes:
    out = bytearray()
    for name, data in _iter_items(entries):
        if isinstance(name, Path):
            name = str(name)
        if isinstance(data, memoryview):
            data = data.tobytes()
        total_size = len(data)
        head = bytes(data[:8]).ljust(8, b"\x00")
        head_lo = int.from_bytes(head[:4], "little")
        head_hi = int.from_bytes(head[4:8], "little")
        payload = bytes(data[8:]) if total_size > 8 else b""
        built = PAQ_ENTRY.build(
            {
                "name": str(name),
                "total_size": total_size,
                "head_lo": head_lo,
                "head_hi": head_hi,
                "payload": payload,
            },
        )
        out += built
    return bytes(out)


def write_paq(dest: str | Path | BinaryIO, entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]) -> None:
    f, should_close = _open_binary(dest, "wb")
    try:
        f.write(MAGIC)
        f.write(_build_entries(entries))
    finally:
        if should_close:
            f.close()


def encode_bytes(entries: Mapping[str, bytes] | Iterable[PaqEntry] | Iterable[tuple[str, bytes]]) -> bytes:
    return MAGIC + _build_entries(entries)
