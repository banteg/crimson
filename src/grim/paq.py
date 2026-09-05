from __future__ import annotations

"""
PAQ archive format (Crimsonland).

File layout:
  - magic: 4 bytes, ASCII "paq\\0"
  - entries: repeated until EOF
      - name: NUL-terminated UTF-8 string (relative path)
      - size: u32 little-endian payload size
      - payload: raw file bytes of length `size`
"""

from collections.abc import Iterable, Iterator
from io import BytesIO
from pathlib import Path

from construct import Bytes, Const, ConstructError, CString, GreedyRange, Int32ul, Struct, Terminated

MAGIC = b"paq\x00"


PAQ_ENTRY = Struct(
    "name" / CString("utf8"),
    "size" / Int32ul,
    "payload" / Bytes(lambda ctx: ctx.size),
)

PAQ = Struct(
    "magic" / Const(MAGIC),
    "entries" / GreedyRange(PAQ_ENTRY),
    Terminated,
)


def iter_entries_bytes(data: bytes) -> Iterator[tuple[str, bytes]]:
    stream = BytesIO(data)
    try:
        parsed = PAQ.parse_stream(stream)
    except ConstructError as exc:
        raise ValueError(f"Invalid PAQ archive at offset {stream.tell()}: {exc}") from exc
    for entry in parsed.entries:
        yield entry.name, entry.payload


def iter_entries(source: str | Path) -> Iterator[tuple[str, bytes]]:
    data = Path(source).read_bytes()
    yield from iter_entries_bytes(data)


def read_paq(source: str | Path) -> list[tuple[str, bytes]]:
    return list(iter_entries(source))


def decode_bytes(data: bytes) -> list[tuple[str, bytes]]:
    return list(iter_entries_bytes(data))


def build_entries(entries: Iterable[tuple[str, bytes]]) -> bytes:
    built_entries = []
    for name, data in entries:
        if isinstance(name, Path):
            name = str(name)
        if isinstance(data, memoryview):
            data = data.tobytes()
        built_entries.append(
            {
                "name": str(name),
                "size": len(data),
                "payload": bytes(data),
            },
        )
    return PAQ.build({"magic": MAGIC, "entries": built_entries})


def write_paq(dest: str | Path, entries: Iterable[tuple[str, bytes]]) -> None:
    data = build_entries(entries)
    Path(dest).write_bytes(data)


def encode_bytes(entries: Iterable[tuple[str, bytes]]) -> bytes:
    return build_entries(entries)
