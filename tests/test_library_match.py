from __future__ import annotations

import struct
from pathlib import Path
from typing import cast

from crimson.library_match import (
    AR_MAGIC,
    archive_match_payload,
    match_coff_archive,
    parse_coff_archive,
    render_archive_match_report,
)
from crimson.match import LoadedImage


def _build_object(
    code: bytes,
    symbol: str = "_probe",
    relocations: tuple[int, ...] = (),
    compiler_id: int | None = None,
) -> bytes:
    header_size = 20
    section_header_size = 40
    code_offset = header_size + section_header_size
    relocation_offset = code_offset + len(code)
    symtab_offset = relocation_offset + len(relocations) * 10
    symbol_records = struct.pack("<8sIhHBB", symbol.encode(), 0, 1, 0x20, 2, 0)
    symbol_count = 1
    if compiler_id is not None:
        symbol_records += struct.pack("<8sIhHBB", b"@comp.id", compiler_id, -1, 0, 3, 0)
        symbol_count += 1
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, symtab_offset, symbol_count, 0, 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        0,
        0,
        len(code),
        code_offset,
        relocation_offset if relocations else 0,
        0,
        len(relocations),
        0,
        0x60000020,
    )
    relocation_records = b"".join(
        struct.pack("<IIH", offset, 0, 6)
        for offset in relocations
    )
    return header + section + code + relocation_records + symbol_records + struct.pack("<I", 4)


def _ar_member(name: bytes, payload: bytes) -> bytes:
    header = (
        name.ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(payload)).encode().ljust(10)
        + b"`\n"
    )
    return header + payload + (b"\n" if len(payload) & 1 else b"")


def _build_archive(member_name: str, payload: bytes) -> bytes:
    long_names = f"{member_name}/\n".encode()
    return AR_MAGIC + _ar_member(b"//", long_names) + _ar_member(b"/0", payload)


def test_parse_coff_archive_resolves_microsoft_long_names() -> None:
    archive = _build_archive(r"obj\i386\probe.obj", b"payload")

    members = parse_coff_archive(archive)

    assert members[0].name == "//"
    assert members[1].name == r"obj\i386\probe.obj"
    assert members[1].data == b"payload"


def test_archive_match_requires_exact_unrelocated_bytes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    object_code = bytes.fromhex("a100000000c3")
    linked_code = bytes.fromhex("a100104000c3")
    archive_path = tmp_path / "probe.lib"
    archive_path.write_bytes(
        _build_archive(
            r"obj\i386\probe.obj",
            _build_object(object_code, relocations=(1,), compiler_id=0x001D23DA),
        ),
    )
    image_path = tmp_path / "game.exe"
    image_path.write_bytes(b"unused")
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401000","end":"0x00401006","name":"native_probe","size":6,"library":false}]',
        encoding="utf-8",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"image_base":"0x00400000"}', encoding="utf-8")
    mapped = bytearray(0x2000)
    mapped[0x1000:0x1006] = linked_code
    monkeypatch.setattr(
        "crimson.library_match.matchlib.load_image",
        lambda path: LoadedImage(bytes(mapped), 0x00400000, len(mapped)),
    )

    report = match_coff_archive(
        archive_path,
        image_path=image_path,
        functions_path=functions_path,
        metadata_path=metadata_path,
        range_start=0x00401000,
        range_end=0x00401006,
    )

    assert report.object_members == 1
    assert report.object_functions == 1
    assert report.matched_functions == 1
    assert report.matched_bytes == 6
    assert report.unique_functions == 1
    assert report.matches[0].candidates[0].symbol == "_probe"
    assert report.matches[0].candidates[0].relocation_count == 1
    candidate = report.matches[0].candidates[0]
    assert candidate.compiler_product == 29
    assert candidate.compiler_build == 9178
    payload_matches = cast(
        "list[dict[str, object]]",
        archive_match_payload(report)["matches"],
    )
    payload_candidates = cast(
        "list[dict[str, object]]",
        payload_matches[0]["candidates"],
    )
    payload_candidate = payload_candidates[0]
    assert payload_candidate["compiler"] == {
        "id": "0x001d23da",
        "product": 29,
        "build": 9178,
    }
    rendered = render_archive_match_report(report, show_matches=True)
    assert "matched=1/1" in rendered
    assert "[product-29/build-9178]" in rendered


def test_archive_match_trims_untargeted_terminal_padding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    linked_code = bytes.fromhex("31c0c3")
    archive_path = tmp_path / "probe.lib"
    archive_path.write_bytes(
        _build_archive(
            r"obj\i386\probe.obj",
            _build_object(linked_code + bytes.fromhex("8bff")),
        ),
    )
    image_path = tmp_path / "game.exe"
    image_path.write_bytes(b"unused")
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401000","end":"0x00401003","name":"native_probe","size":3,"library":false}]',
        encoding="utf-8",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"image_base":"0x00400000"}', encoding="utf-8")
    mapped = bytearray(0x2000)
    mapped[0x1000:0x1005] = linked_code + bytes.fromhex("8bff")
    monkeypatch.setattr(
        "crimson.library_match.matchlib.load_image",
        lambda path: LoadedImage(bytes(mapped), 0x00400000, len(mapped)),
    )

    report = match_coff_archive(
        archive_path,
        image_path=image_path,
        functions_path=functions_path,
        metadata_path=metadata_path,
        range_start=0x00401000,
        range_end=0x00401003,
    )

    assert report.matched_functions == 1
    assert report.unique_functions == 1
    assert report.matches[0].candidates[0].size == len(linked_code)
