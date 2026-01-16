from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Mapping

from construct import Bytes, Const, CString, GreedyRange, Int32ul, Struct

MAGIC = b"paq\x00"




PAQ_ENTRY = Struct(
    "name" / CString("utf8"),
    "total_size" / Int32ul,
    "head_lo" / Int32ul,
    "head_hi" / Int32ul,
    "payload" / Bytes(lambda ctx: max(ctx.total_size - 8, 0)),
)

PAQ = Struct(
    "magic" / Const(MAGIC),
    "entries" / GreedyRange(PAQ_ENTRY),
)


def iter_entries_bytes(data: bytes) -> Iterator[tuple[str, bytes]]:
    parsed = PAQ.parse(data)
    for entry in parsed.entries:
        head = (entry.head_lo.to_bytes(4, "little") + entry.head_hi.to_bytes(4, "little"))
        full = head[: entry.total_size] + entry.payload
        yield entry.name, full


def iter_entries(source: str | Path) -> Iterator[tuple[str, bytes]]:
    data = Path(source).read_bytes()
    yield from iter_entries_bytes(data)


def read_paq(source: str | Path) -> dict[str, bytes]:
    return {name: data for name, data in iter_entries(source)}


def decode_bytes(data: bytes) -> dict[str, bytes]:
    return {name: payload for name, payload in iter_entries_bytes(data)}


def iter_items(entries: Mapping[str, bytes] | Iterable[tuple[str, bytes]]):
    if isinstance(entries, Mapping):
        return entries.items()
    return entries


def build_entries(entries: Mapping[str, bytes] | Iterable[tuple[str, bytes]]) -> bytes:
    built_entries = []
    for name, data in iter_items(entries):
        if isinstance(name, Path):
            name = str(name)
        if isinstance(data, memoryview):
            data = data.tobytes()
        total_size = len(data)
        head = bytes(data[:8]).ljust(8, b"\x00")
        head_lo = int.from_bytes(head[:4], "little")
        head_hi = int.from_bytes(head[4:8], "little")
        payload = bytes(data[8:]) if total_size > 8 else b""
        built_entries.append(
            {
                "name": str(name),
                "total_size": total_size,
                "head_lo": head_lo,
                "head_hi": head_hi,
                "payload": payload,
            }
        )
    return PAQ.build({"magic": MAGIC, "entries": built_entries})


def write_paq(dest: str | Path, entries: Mapping[str, bytes] | Iterable[tuple[str, bytes]]) -> None:
    data = build_entries(entries)
    Path(dest).write_bytes(data)


def encode_bytes(entries: Mapping[str, bytes] | Iterable[tuple[str, bytes]]) -> bytes:
    return build_entries(entries)
