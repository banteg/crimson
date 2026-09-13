"""Verify signed date-index behavior and the exact scope of the source change."""

import argparse
import json
import struct
from dataclasses import asdict
from pathlib import Path

import capstone
import unicorn
from replay import HERE, SCRATCH, baseline, compile_source, sha
from unicorn import x86_const as x86

from crimson import match

IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
WINDOW = (0x1015, 0x1043)
NATIVE_START, NATIVE_CALL = 0x0044345D, 0x00443486
CANDIDATE_CALL = 0x103D
CODE, STACK, INTERFACE = 0x01000000, 0x02000000, 0x03000000


def address(reference):
    values = {int(key.removeprefix("address:"), 16) for key in reference.keys if key.startswith("address:")}
    assert len(values) == 1
    return values.pop()


def execute(image, code, start, end, selected, date, interface):
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    mu.mem_map(image.image_base, (len(image.mapped) + 4095) & ~4095)
    mu.mem_write(image.image_base, image.mapped)
    mu.mem_map(CODE, 0x10000)
    mu.mem_map(STACK, 0x10000)
    mu.mem_map(INTERFACE, 0x1000)
    mu.mem_write(interface, struct.pack("<I", INTERFACE))
    mu.mem_write(INTERFACE, struct.pack("<I", INTERFACE + 0x100))
    if code is not None:
        mu.mem_write(CODE, code)
    results = []
    for value in range(256):
        mu.mem_write(date, bytes([value]))
        mu.mem_write(selected, bytes.fromhex("c0dec0de"))
        mu.reg_write(x86.UC_X86_REG_ESP, STACK + 0x8000)
        for reg in (x86.UC_X86_REG_EAX, x86.UC_X86_REG_EBX, x86.UC_X86_REG_ECX, x86.UC_X86_REG_EDX):
            mu.reg_write(reg, 0xA5A5A5A5)
        mu.emu_start(start, end, count=20)
        assert mu.reg_read(x86.UC_X86_REG_EIP) == end
        assert mu.reg_read(x86.UC_X86_REG_ESP) == STACK + 0x8000 - 16
        expected_color = struct.pack("<4I", 0x3F800000, 0x3F800000, 0x3F800000, 0x3F4CCCCD)
        assert bytes(mu.mem_read(STACK + 0x8000 - 16, 16)) == expected_color
        assert mu.reg_read(x86.UC_X86_REG_ECX) == INTERFACE
        assert mu.reg_read(x86.UC_X86_REG_EDX) == INTERFACE + 0x100
        results.append(struct.unpack("<i", mu.mem_read(selected, 4))[0])
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    data = json.loads((HERE / "controls.json").read_text())
    sources = [baseline(data), (match.REPO_ROOT / SCRATCH / "scratch.cpp").read_text()]
    assert sources[1] == sources[0].replace(
        "date_filter_list.selected_index = config_blob.highscore_date_mode;",
        "date_filter_list.selected_index = (signed char)config_blob.highscore_date_mode;",
    )
    compiled = [compile_source(source, out / label) for source, label in zip(sources, ("before", "after"), strict=True)]
    bodies = [pair[0] for pair in compiled]
    matches = [pair[1] for pair in compiled]
    assert all(len(body.data) == 7894 for body in bodies)
    first, last = WINDOW
    assert bodies[0].data[:first] == bodies[1].data[:first]
    assert bodies[0].data[last:] == bodies[1].data[last:]
    outside_refs = [
        [asdict(ref) for ref in body.relocation_references if not first <= ref.offset < last] for body in bodies
    ]
    assert outside_refs[0] == outside_refs[1]
    assert all(not result.exact and not result.body_byte_exact for result in matches)
    assert [len(result.candidate_lines) for result in matches] == [1969, 1968]
    assert all(
        result.prefix_instructions == 45 and result.masked_operand_audit.problem_count == 4 for result in matches
    )
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    image = match.load_image(match.default_image_path())
    native = [row for row in matches[1].target_disassembly if NATIVE_START <= row.address < NATIVE_CALL]
    native_refs = [reference for row in native for reference in row.masked_references]
    date, selected, interface = map(address, native_refs)
    assert [row.text for row in native][:2] == ["movsx ecx, byte [ADDR]", "mov dword [ADDR], ecx"]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    outcomes = [execute(image, None, NATIVE_START, NATIVE_CALL, selected, date, interface)]
    for body, result in compiled:
        patched = bytearray(body.data)
        rows = [row for row in result.candidate_disassembly if first <= row.offset < CANDIDATE_CALL]
        refs = [reference for row in rows for reference in row.masked_references]
        assert sorted(map(address, refs)) == sorted([date, selected, interface])
        for row in rows:
            if not row.masked_references:
                continue
            assert len(row.masked_references) == 1
            instruction = next(decoder.disasm(body.data[row.offset : row.offset + row.size], row.offset))
            assert instruction.disp_size == 4
            struct.pack_into("<I", patched, row.offset + instruction.disp_offset, address(row.masked_references[0]))
        outcomes.append(execute(image, bytes(patched), CODE + first, CODE + CANDIDATE_CALL, selected, date, interface))
    expected = [value if value < 128 else value - 256 for value in range(256)]
    assert outcomes[0] == outcomes[2] == expected
    assert outcomes[1] == list(range(256))
    payload = {
        "schema": 1,
        "verified": True,
        "base_commit": data["base_commit"],
        "source_sha256": [sha(source.encode()) for source in sources],
        "body_sha256": [sha(body.data) for body in bodies],
        "image_sha256": IMAGE_SHA,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "candidate_window": list(WINDOW),
        "native_window": [NATIVE_START, NATIVE_CALL],
        "body_bytes": 7894,
        "outside_window_bytes_unchanged": 7894 - last + first,
        "outside_relocations_unchanged": len(outside_refs[0]),
        "exhaustive_byte_inputs": 256,
        "corrected_inputs": 128,
        "color_arguments_and_this_preserved": True,
        "normalized_exact": False,
        "body_byte_exact": False,
        "unicorn_version": unicorn.__version__,
        "limitations": "Executes the date conversion and color-call setup only; excludes the call and the rest of the UI.",
    }
    (out / "results.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
