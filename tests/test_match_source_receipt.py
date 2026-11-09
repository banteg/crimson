import struct
from pathlib import Path

import pytest

from crimson_re import match
from crimson_re.match_source_receipt import _source_object_sha256, candidate_object_sha256


def _record(kind: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload) + 2, kind) + payload


def _compile_record(*, kind: int = 0x1013, backend_build: int = 9044) -> bytes:
    brand = b"Microsoft (R) Optimizing Compiler"
    versions = struct.pack("<I7H", 0x201, 5, 12, 0, 8964, 12, 0, backend_build)
    return _record(kind, versions + bytes([len(brand)]) + brand + b"\0\0")


def _object(
    path: bytes,
    *,
    path_count: int | None = None,
    compiler_record: bytes = _compile_record(),
    opcode: int = 0xA1,
    addend: int = 4,
    data: bytes = b"contents",
    reloc_symbol: int = 4,
    reloc_type: int = 6,
    debug_checksum: int = 0,
    overlap: str | None = None,
) -> bytes:
    # VC6 Processor Pack writes CodeView signature 2, S_OBJNAME_ST and S_COMPILE2_ST.
    count = len(path) if path_count is None else path_count
    objname = _record(0x0009, struct.pack("<IB", 0, count) + path)
    debug = struct.pack("<I", 2) + objname + compiler_record
    text = bytes([opcode]) + struct.pack("<I", addend) + b"\xc3"
    # mov eax,[.data+4] / ret; section symbols have raw indexes 0, 2, and 4.
    relocation = struct.pack("<IIH", 1, reloc_symbol, reloc_type)
    sections = (
        (b".debug$S", debug, 0x42100040, b""),
        (b".text", text, 0x60500020, relocation),
        (b".data", data, 0xC0300040, b""),
    )
    debug_start = 20 + 40 * len(sections)
    headers, bodies, symbols = bytearray(), bytearray(), bytearray()
    for number, (name, body, flags, relocs) in enumerate(sections, 1):
        start = debug_start + len(bodies)
        reloc_start = start + len(body) if relocs else 0
        if name == b".text" and overlap == "raw":
            start = debug_start + 13  # the object path starts here
        if name == b".text" and overlap == "relocations":
            reloc_start = debug_start + len(debug) - 2
        headers += struct.pack(
            "<8sIIIIIIHHI",
            name,
            0,
            0,
            len(body),
            start,
            reloc_start,
            0,
            len(relocs) // 10,
            0,
            flags,
        )
        bodies += body + relocs
        if name == b".debug$S" and overlap == "relocations":
            # The two trailing zeroes of S_COMPILE2_ST double as the first bytes
            # of a valid relocation, so ordinary relocation validation accepts it.
            bodies += struct.pack("<IIH", 0, reloc_symbol, reloc_type)[2:]
        symbols += struct.pack("<8sIhHBB", name, 0, number, 0, 3, 1)
        checksum = debug_checksum if name == b".debug$S" else 0
        symbols += struct.pack("<IHHIHB3x", len(body), len(relocs) // 10, 0, checksum, 0, 0)

    header = struct.pack("<HHIIIHH", 0x14C, len(sections), 731, debug_start + len(bodies), 6, 0, 0)
    return header + headers + bodies + symbols + struct.pack("<I", 4)


_STAGE = Path("tools/match/scratches/player/build/msvc6.5pp/.0123456789abcdef.stage/player.obj")
_OUTPUT = Path("/checkout") / _STAGE


def _wibo_name(output: Path) -> bytes:
    return ("Z:" + str(output).replace("/", "\\")).encode("ascii")


@pytest.mark.parametrize("stage", [_STAGE, Path("tools/match/.cache/13579bdf2468ace0/player.obj")])
def test_checkout_directory_is_the_only_difference_accepted(stage):
    other_output = Path("/longer/checkout") / stage
    first = _object(_wibo_name(_OUTPUT))
    second = _object(_wibo_name(other_output))
    assert match.coff_sha256(first) != match.coff_sha256(second)
    assert _source_object_sha256(first, _OUTPUT) == _source_object_sha256(second, other_output)


@pytest.mark.parametrize(
    "embedded",
    [
        _wibo_name(_OUTPUT.parent.parent / ".other.stage" / _OUTPUT.name),
        _wibo_name(_OUTPUT.with_name("enemy.obj")),
        b"player.obj",
    ],
    ids=["wrong-directory", "wrong-basename", "untrusted-relative-basename"],
)
def test_untrusted_object_name_keeps_its_raw_receipt(embedded):
    trusted = _object(_wibo_name(_OUTPUT))
    untrusted = _object(embedded)
    assert _source_object_sha256(untrusted, _OUTPUT) == match.coff_sha256(untrusted)
    assert _source_object_sha256(untrusted, _OUTPUT) != _source_object_sha256(trusted, _OUTPUT)


@pytest.mark.parametrize(
    "changes",
    [
        {"path_count": 3},
        {"compiler_record": _compile_record(kind=0x0013)},
        {"compiler_record": _compile_record().replace(b"\x21Microsoft", b"\x42Microsoft")},
        {"compiler_record": _compile_record() + _record(0x0013, b"unknown")},
        {"overlap": "raw"},
        {"overlap": "relocations"},
    ],
    ids=[
        "malformed-path-count", "unexpected-compiler-record", "malformed-compiler-string",
        "extra-debug-record", "overlapping-raw-data", "overlapping-relocations",
    ],
)
def test_unsupported_coff_layout_keeps_its_raw_receipt(changes):
    data = _object(_wibo_name(_OUTPUT), **changes)
    match.parse_coff_object(data)
    assert _source_object_sha256(data, _OUTPUT) == match.coff_sha256(data)


@pytest.mark.parametrize(
    "changes",
    [
        {"opcode": 0xA3},
        {"data": b"changed!"},
        {"addend": 0},
        {"reloc_symbol": 2},
        {"reloc_type": 0x14},
        {"compiler_record": _compile_record(backend_build=9045)},
        {"debug_checksum": 1},
    ],
    ids=["code", "data", "addend", "relocation-target", "relocation-type", "compiler-version", "aux-checksum"],
)
def test_receipt_detects_changed_object_contents(changes):
    name = _wibo_name(_OUTPUT)
    original, changed = _object(name), _object(name, **changes)
    assert match.coff_sha256(original) != match.coff_sha256(changed)
    assert _source_object_sha256(original, _OUTPUT) != _source_object_sha256(changed, _OUTPUT)


@pytest.mark.parametrize("artifact", ["archive", "import_thunk"])
def test_non_source_candidates_keep_the_raw_object_receipt(tmp_path, artifact):
    config = match.ScratchConfig(
        tmp_path, "f", "grim.dll", "msvc6.5pp", "/O2", "f.cpp", None, "f", "",
        archive="test.lib" if artifact == "archive" else None,
        import_thunk="GetTickCount" if artifact == "import_thunk" else None,
    )
    data = _object(_wibo_name(_OUTPUT))
    assert _source_object_sha256(data, _OUTPUT) != match.coff_sha256(data)
    assert candidate_object_sha256(data, config) == match.coff_sha256(data)


def test_truncated_compiler_record_keeps_its_raw_receipt():
    data = _object(_wibo_name(_OUTPUT))
    truncated = data[: data.index(b"Microsoft") - 4]
    assert _source_object_sha256(truncated, _OUTPUT) == match.coff_sha256(truncated)
