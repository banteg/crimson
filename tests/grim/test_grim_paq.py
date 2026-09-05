from __future__ import annotations

import pytest

from grim import paq as grim_paq


def test_paq_roundtrip_entries() -> None:
    entries = [
        ("foo.txt", b"abc"),
        ("bar.bin", b"\x00\x01\x02"),
    ]
    blob = grim_paq.build_entries(entries)
    assert list(grim_paq.iter_entries_bytes(blob)) == entries


def test_paq_rejects_every_truncated_entry_boundary() -> None:
    first = grim_paq.build_entries([("first.txt", b"complete")])
    blob = grim_paq.build_entries([("first.txt", b"complete"), ("last.txt", b"payload")])
    # EOF between entries is valid. EOF inside a name, size or payload is not.
    assert grim_paq.decode_bytes(first) == [("first.txt", b"complete")]
    for end in range(len(first) + 1, len(blob)):
        with pytest.raises(ValueError, match="Invalid PAQ archive at offset"):
            grim_paq.decode_bytes(blob[:end])


@pytest.mark.parametrize("suffix", [b"broken", b"\x00", b"tail\x00\xff\xff\xff\xff"])
def test_paq_rejects_trailing_garbage(suffix: bytes) -> None:
    blob = grim_paq.build_entries([("first.txt", b"complete")])
    with pytest.raises(ValueError, match="Invalid PAQ archive at offset"):
        grim_paq.decode_bytes(blob + suffix)


def test_paq_accepts_empty_archive_and_empty_payload() -> None:
    assert grim_paq.decode_bytes(grim_paq.build_entries([])) == []
    assert grim_paq.decode_bytes(grim_paq.build_entries([("empty", b"")])) == [("empty", b"")]
