from __future__ import annotations

import json
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.library_match import (
    AR_MAGIC,
    archive_match_payload,
    archive_reference_bindings_payload,
    infer_archive_reference_bindings,
    match_coff_archive,
    parse_coff_archive,
    render_archive_match_report,
    write_archive_scratch_configs,
)
from crimson.match import (
    CoffObject,
    CoffSection,
    CoffSymbol,
    LoadedImage,
    load_scratch_config,
)


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


def _build_archive_members(members: list[tuple[str, bytes]]) -> bytes:
    long_names = b""
    encoded_members: list[bytes] = []
    for member_name, payload in members:
        name_offset = len(long_names)
        long_names += f"{member_name}/\n".encode()
        encoded_members.append(_ar_member(f"/{name_offset}".encode(), payload))
    return AR_MAGIC + _ar_member(b"//", long_names) + b"".join(encoded_members)


def _build_archive(member_name: str, payload: bytes) -> bytes:
    return _build_archive_members([(member_name, payload)])


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
        "["
        '{"address":"0x00401000","end":"0x00401006",'
        '"name":"native_probe","size":6,"library":false},'
        '{"address":"0x00401100","end":"0x00401101",'
        '"name":"probe","size":1,"library":false}'
        "]",
        encoding="utf-8",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"image_base":"0x00400000"}', encoding="utf-8")
    mapped = bytearray(0x2000)
    mapped[0x1000:0x1006] = linked_code
    monkeypatch.setattr(
        "crimson.library_match.matchlib.load_image",
        lambda path, image_base=None: LoadedImage(bytes(mapped), 0x00400000, len(mapped)),
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
    assert report.symbol_unique_functions == 1
    assert report.symbol_unique_bytes == 6
    assert report.matches[0].symbol_unique
    assert report.matches[0].candidates[0].symbol == "_probe"
    assert report.matches[0].candidates[0].relocation_count == 1
    assert report.excluded_target_functions == 0
    assert report.excluded_target_bytes == 0
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
    assert archive_match_payload(report)["exclusions"] == {
        "target_functions": 0,
        "target_bytes": 0,
    }
    assert payload_candidate["compiler"] == {
        "id": "0x001d23da",
        "product": 29,
        "build": 9178,
    }
    rendered = render_archive_match_report(report, show_matches=True)
    assert "matched=1/1" in rendered
    assert "[product-29/build-9178]" in rendered

    duplicate_candidate = replace(candidate, member=r"obj\i386\duplicate.obj")
    symbol_unique_match = replace(
        report.matches[0],
        candidates=(candidate, duplicate_candidate),
    )
    symbol_unique_report = replace(
        report,
        unique_functions=0,
        unique_bytes=0,
        matches=(symbol_unique_match,),
    )
    assert not symbol_unique_match.unique
    assert symbol_unique_match.symbol_unique
    assert symbol_unique_report.symbol_unique_functions == 1
    assert symbol_unique_report.symbol_unique_bytes == 6
    symbol_unique_payload = cast(
        "list[dict[str, object]]",
        archive_match_payload(symbol_unique_report)["matches"],
    )
    assert symbol_unique_payload[0]["symbol_unique"] is True
    assert "symbol-unique:2" in render_archive_match_report(
        symbol_unique_report,
        show_matches=True,
    )
    conflicting_candidate = replace(duplicate_candidate, symbol="_other")
    assert not replace(
        symbol_unique_match,
        candidates=(candidate, conflicting_candidate),
    ).symbol_unique

    generated_root = tmp_path / "generated"
    writes = write_archive_scratch_configs(
        report,
        match_root=generated_root,
        expected_sha256=report.archive_sha256,
        note_prefix="test-archive",
    )
    assert len(writes) == 1
    config = load_scratch_config(writes[0].directory)
    assert config.image == "game.exe"
    assert config.function == "native_probe"
    assert config.archive_member == r"obj\i386\probe.obj"
    assert config.archive_sha256 == report.archive_sha256
    assert config.symbol == "_probe"
    assert config.note == "test-archive-native-probe"
    assert (config.directory / cast(str, config.archive)).resolve() == archive_path.resolve()

    inferred_root = tmp_path / "generated-inferred"
    inferred_writes = write_archive_scratch_configs(
        report,
        match_root=inferred_root,
        expected_sha256=report.archive_sha256,
        note_prefix="test-archive",
        infer_reference_aliases=True,
        functions_path=functions_path,
        metadata_path=metadata_path,
    )
    assert inferred_writes[0].reference_aliases == (("_probe", "native_probe"),)
    inferred_config = load_scratch_config(inferred_writes[0].directory)
    assert inferred_config.reference_aliases == (("_probe", "native_probe"),)

    bindings = infer_archive_reference_bindings(
        report,
        functions_path=functions_path,
        metadata_path=metadata_path,
    )
    assert len(bindings) == 1
    assert bindings[0].object_symbols == ("_probe",)
    assert bindings[0].target_address == 0x00401000
    assert bindings[0].occurrences == 1
    assert bindings[0].addends == (0,)
    assert bindings[0].functions == ((0x00401000, "native_probe"),)
    assert bindings[0].target_names == ("native_probe",)
    assert archive_reference_bindings_payload(bindings)["bindings"] == [
        {
            "lookup_name": "probe",
            "object_symbols": ["_probe"],
            "target_address": "0x00401000",
            "target_names": ["native_probe"],
            "occurrences": 1,
            "addends": [0],
            "functions": [{"address": "0x00401000", "name": "native_probe"}],
            "members": [r"obj\i386\probe.obj"],
        },
    ]

    addend_archive_path = tmp_path / "probe-addend.lib"
    addend_archive_path.write_bytes(
        _build_archive(
            r"obj\i386\probe-addend.obj",
            _build_object(bytes.fromhex("a104000000c3"), relocations=(1,)),
        ),
    )
    addend_mapped = bytearray(0x2000)
    addend_mapped[0x1000:0x1006] = bytes.fromhex("a104104000c3")
    monkeypatch.setattr(
        "crimson.library_match.matchlib.load_image",
        lambda path, image_base=None: LoadedImage(
            bytes(addend_mapped),
            0x00400000,
            len(addend_mapped),
        ),
    )
    addend_report = match_coff_archive(
        addend_archive_path,
        image_path=image_path,
        functions_path=functions_path,
        metadata_path=metadata_path,
        range_start=0x00401000,
        range_end=0x00401006,
    )
    addend_bindings = infer_archive_reference_bindings(
        addend_report,
        functions_path=functions_path,
        metadata_path=metadata_path,
    )
    assert len(addend_bindings) == 1
    assert addend_bindings[0].target_address == 0x00401000
    assert addend_bindings[0].addends == (4,)

    symbol_unique_writes = write_archive_scratch_configs(
        symbol_unique_report,
        match_root=tmp_path / "generated-symbol-unique",
        expected_sha256=symbol_unique_report.archive_sha256,
        note_prefix="test-archive",
        include_symbol_unique=True,
    )
    assert len(symbol_unique_writes) == 1
    assert symbol_unique_writes[0].candidate.member == candidate.member

    with pytest.raises(ValueError, match="archive SHA-256 mismatch"):
        write_archive_scratch_configs(
            report,
            match_root=tmp_path / "wrong-hash",
            expected_sha256="0" * 64,
            note_prefix="test-archive",
        )

    repeated_report = replace(
        report,
        matched_functions=2,
        matched_bytes=12,
        unique_functions=2,
        unique_bytes=12,
        matches=(report.matches[0], report.matches[0]),
    )
    limited_payload = archive_match_payload(repeated_report, limit=1)
    assert limited_payload["summary"] == {
        "target_functions": 1,
        "target_bytes": 6,
        "matched_functions": 2,
        "matched_bytes": 12,
        "unique_functions": 2,
        "unique_bytes": 12,
        "symbol_unique_functions": 2,
        "symbol_unique_bytes": 12,
    }
    assert limited_payload["listing"] == {
        "returned_matches": 1,
        "limit": 1,
        "truncated": True,
    }
    assert len(cast("list[object]", limited_payload["matches"])) == 1

    excluded_report = match_coff_archive(
        archive_path,
        image_path=image_path,
        functions_path=functions_path,
        metadata_path=metadata_path,
        range_start=0x00401000,
        range_end=0x00401006,
        excluded_addresses={0x00401000},
    )
    assert excluded_report.target_functions == 0
    assert excluded_report.target_bytes == 0
    assert excluded_report.matched_functions == 0
    assert excluded_report.excluded_target_functions == 1
    assert excluded_report.excluded_target_bytes == 6
    assert "excluded=1 excluded_bytes=6" in render_archive_match_report(excluded_report)

    monkeypatch.setattr(
        "crimson.cli.match.matchlib.collect_scratch_statuses",
        lambda *args, **kwargs: [
            SimpleNamespace(
                address=0x00401000,
                config=SimpleNamespace(image="game.exe"),
            ),
        ],
    )
    completed = CliRunner().invoke(
        match_app,
        [
            "archive",
            str(archive_path),
            "--image",
            str(image_path),
            "--functions",
            str(functions_path),
            "--metadata",
            str(metadata_path),
            "--start",
            "0x00401000",
            "--end",
            "0x00401006",
            "--missing-scratches",
            "--match-root",
            str(tmp_path),
            "--json",
        ],
    )
    assert completed.exit_code == 0
    cli_payload = json.loads(completed.output)
    assert cli_payload["filters"] == {"missing_scratches": True}
    assert cli_payload["summary"]["matched_functions"] == 0
    assert cli_payload["exclusions"] == {"target_functions": 1, "target_bytes": 6}


def test_archive_reference_inference_tolerates_duplicate_member_names(
    tmp_path: Path,
    monkeypatch,
) -> None:
    object_code = bytes.fromhex("a100000000c3")
    linked_code = bytes.fromhex("a100104000c3")
    archive_path = tmp_path / "probe.lib"
    archive_path.write_bytes(
        _build_archive_members(
            [
                (r"obj\i386\duplicate.obj", b"first non-object"),
                (r"obj\i386\duplicate.obj", b"second non-object"),
                (
                    r"obj\i386\probe.obj",
                    _build_object(object_code, relocations=(1,)),
                ),
            ],
        ),
    )
    image_path = tmp_path / "game.exe"
    image_path.write_bytes(b"unused")
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401000","end":"0x00401006",'
        '"name":"native_probe","size":6,"library":false}]',
        encoding="utf-8",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"image_base":"0x00400000"}', encoding="utf-8")
    mapped = bytearray(0x2000)
    mapped[0x1000:0x1006] = linked_code
    monkeypatch.setattr(
        "crimson.library_match.matchlib.load_image",
        lambda path, image_base=None: LoadedImage(bytes(mapped), 0x00400000, len(mapped)),
    )

    report = match_coff_archive(
        archive_path,
        image_path=image_path,
        functions_path=functions_path,
        metadata_path=metadata_path,
        range_start=0x00401000,
        range_end=0x00401006,
    )
    bindings = infer_archive_reference_bindings(
        report,
        functions_path=functions_path,
        metadata_path=metadata_path,
    )

    assert len(bindings) == 1
    assert bindings[0].object_symbols == ("_probe",)
    assert bindings[0].target_address == 0x00401000


def test_archive_match_does_not_index_vc_code_packets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    code = bytes.fromhex("31c0c3b801000000c3")
    obj = CoffObject(
        sections=(CoffSection(".text", code, 0x20, ()),),
        symbols=(
            CoffSymbol(0, "_probe", 0, 1, 0x20, 2),
            CoffSymbol(1, "TAG_PACKET_0", 3, 1, 0x20, 3),
            CoffSymbol(2, "TAG_PACKET_1", 8, 1, 0x20, 3),
        ),
    )
    archive_path = tmp_path / "probe.lib"
    archive_path.write_bytes(_build_archive(r"obj\i386\probe.obj", b"object"))
    image_path = tmp_path / "game.exe"
    image_path.write_bytes(b"unused")
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401000","end":"0x00401009","name":"native_probe",'
        '"size":9,"library":false}]',
        encoding="utf-8",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"image_base":"0x00400000"}', encoding="utf-8")
    mapped = bytearray(0x2000)
    mapped[0x1000:0x1009] = code
    monkeypatch.setattr("crimson.library_match.matchlib.parse_coff_object", lambda data: obj)
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
        range_end=0x00401009,
    )

    assert report.object_functions == 1
    assert report.matched_functions == 1
    assert report.matches[0].candidates[0].symbol == "_probe"


def test_archive_match_accepts_zero_valued_linked_relocation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    linked_code = bytes.fromhex("64890d00000000c3")
    archive_path = tmp_path / "probe.lib"
    archive_path.write_bytes(
        _build_archive(
            r"obj\i386\probe.obj",
            _build_object(linked_code, relocations=(3,)),
        ),
    )
    image_path = tmp_path / "game.exe"
    image_path.write_bytes(b"unused")
    functions_path = tmp_path / "functions.json"
    functions_path.write_text(
        '[{"address":"0x00401000","end":"0x00401008","name":"native_probe","size":8,"library":false}]',
        encoding="utf-8",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"image_base":"0x00400000"}', encoding="utf-8")
    mapped = bytearray(0x2000)
    mapped[0x1000:0x1008] = linked_code
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
        range_end=0x00401008,
    )

    assert report.matched_functions == 1
    assert report.unique_functions == 1
    assert report.matches[0].candidates[0].symbol == "_probe"


def test_archive_match_trims_untargeted_terminal_padding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    linked_code = bytes.fromhex("31c0c3")
    padding = bytes.fromhex("8da424000000008d64240005000000008bff")
    archive_path = tmp_path / "probe.lib"
    archive_path.write_bytes(
        _build_archive(
            r"obj\i386\probe.obj",
            _build_object(linked_code + padding),
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
    mapped[0x1000 : 0x1003 + len(padding)] = linked_code + padding
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
