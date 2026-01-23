from __future__ import annotations

from grim import paq as grim_paq


def test_paq_roundtrip_entries() -> None:
    entries = [
        ("foo.txt", b"abc"),
        ("bar.bin", b"\x00\x01\x02"),
    ]
    blob = grim_paq.build_entries(entries)
    assert list(grim_paq.iter_entries_bytes(blob)) == entries
