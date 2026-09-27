"""Check encoded straight-line regions, masking only audited COFF relocations."""

import difflib
from dataclasses import asdict, replace

import capstone

from crimson import match

MOVEMENT = (0x4140D8, 0x4140F7, 0x414339, 0x414358, 0x414B80, 0x414B9F, 0x414E45, 0x414E64)
REGIONS = [(f"movement-{address:x}", address, 5) for address in MOVEMENT] + [
    ("keyboard-turn-right", 0x4144DC, 12),
    ("keyboard-turn-left", 0x414520, 13),
    ("smoke-angle", 0x415A68, 37),
]


def pairs(program):
    r = program.result
    out = {}
    # No branch instructions are included in the selected regions. Their
    # ordinary normalized lines must pair without any register/stack mask.
    for block in difflib.SequenceMatcher(a=r.target_lines, b=r.candidate_lines, autojunk=False).get_matching_blocks():
        out.update((block.a + i, block.b + i) for i in range(block.size))
    return out


def check(program, region, *, corrupt_byte=False, corrupt_reference=False):
    name, address, count = region
    r = program.result
    i = next(i for i, line in enumerate(r.target_disassembly) if line.address == address)
    mapping = pairs(program)
    indices = [mapping[k] for k in range(i, i + count)]
    assert indices == list(range(indices[0], indices[0] + count)), name
    native_body = program.image.function_bytes(program.native_start, program.native_end)
    relocations = {ref.offset: ref for ref in program.body.relocation_references}
    rows, native_region, candidate_region = [], bytearray(), bytearray()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    changed = False
    for n, k in enumerate(indices):
        target, candidate = r.target_disassembly[i + n], r.candidate_disassembly[k]
        assert not target.text.split()[0].startswith("j"), target
        assert target.size == candidate.size and target.text == candidate.text
        a = bytearray(native_body[target.offset : target.offset + target.size])
        b = bytearray(program.body.data[candidate.offset : candidate.offset + candidate.size])
        refs = candidate.masked_references
        if corrupt_reference and refs and not changed:
            refs = (replace(refs[0], keys=("deliberately-wrong-reference",)), *refs[1:])
            changed = True
        assert match._masked_reference_status(target.masked_references, refs) == "ok"
        local = [
            offset
            for offset in sorted(program.body.relocation_offsets)
            if candidate.offset <= offset < candidate.offset + candidate.size
        ]
        assert len(local) == len(refs), (target, candidate, local)
        decoded = [next(decoder.disasm(raw, 0)) for raw in (a, b)]
        masked = []
        for offset in local:
            relocation = relocations[offset]
            assert relocation.relocation_type in (6, 20), relocation
            start = offset - candidate.offset
            assert start > 0 and start + 4 <= candidate.size
            assert len(refs) == 1
            field = refs[0].kind
            assert field in ("disp", "imm")
            for instruction in decoded:
                assert getattr(instruction, field + "_offset") == start, (target, refs, field, start)
                assert getattr(instruction, field + "_size") == 4
            # DIR32 operands and REL32 calls occupy the same four bytes in
            # these fixed, equally sized native/candidate instructions.
            a[start : start + 4] = b[start : start + 4] = bytes(4)
            masked.append(
                {
                    "offset": start,
                    "symbol": relocation.symbol_name,
                    "type": relocation.relocation_type,
                    "addend": relocation.addend,
                },
            )
        if corrupt_byte and not changed:
            b[0] ^= 1
            changed = True
        assert a == b, (name, hex(target.address), a.hex(), b.hex())
        native_region.extend(a)
        candidate_region.extend(b)
        rows.append(
            {
                "native_address": target.address,
                "candidate_offset": candidate.offset,
                "instruction": target.text,
                "masked_bytes": a.hex(),
                "relocations": masked,
                "native_references": [asdict(ref) for ref in target.masked_references],
                "candidate_references": [asdict(ref) for ref in refs],
            },
        )
    assert native_region == candidate_region
    return {
        "name": name,
        "native_start": address,
        "instructions": count,
        "bytes": len(native_region),
        "relocations": sum(len(row["relocations"]) for row in rows),
        "rows": rows,
    }


def rejected(program, region, **kwargs):
    try:
        check(program, region, **kwargs)
    except (AssertionError, KeyError):
        return True
    raise AssertionError((region, kwargs, "control unexpectedly passed"))


def verify(current, ablations):
    rows = [check(current, region) for region in REGIONS]
    controls = {
        "wrong-opcode": rejected(current, REGIONS[0], corrupt_byte=True),
        "wrong-reference": rejected(current, REGIONS[0], corrupt_reference=True),
        "without-movement-groups": all(
            rejected(ablations["without_movement_groups"], region) for region in REGIONS[:8]
        ),
        "without-turn-temporary": all(
            rejected(ablations["without_turn_temporary"], region) for region in REGIONS[8:10]
        ),
        "without-smoke-reuse": rejected(ablations["without_smoke_reuse"], REGIONS[10]),
    }
    assert all(controls.values())
    return {"regions": rows, "rejecting_controls": controls}
