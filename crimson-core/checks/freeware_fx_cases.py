"""The four FX writers share their capped counts with the next render pass."""

import ctypes
import math
import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable

COUNTERS = (0x452DA0, 0x452E80, 0x452E88, 0x452E84)
# Native addresses, including the final writable slot beyond each draw count.
POOLS = (
    ("impacts", 0x438828, 64, "<i9f"),
    ("blood", 0x43C6B0, 64, "<2f"),
    ("shells", 0x440DC8, 32, "<2f"),
    ("corpse positions", 0x436AF8, 64, "<2f"),
    ("corpse colors", 0x442498, 64, "<4f"),
    ("corpse angles", 0x43C8B4, 64, "<f"),
    ("corpse sizes", 0x438378, 64, "<f"),
    ("corpse species", 0x442390, 64, "<i"),
)


def compare_queues(check, pe, case, *, exact=True):
    check.dll.combat_fx_snapshot()
    cursor = check.symbol("combat_fx_storage")
    assert struct.unpack("<4i", ctypes.string_at(cursor, 16)) == tuple(pe.read_i32(a) for a in COUNTERS), case
    cursor += 16
    for name, base, count, fmt in POOLS:
        size = struct.calcsize(fmt) * count
        expected, actual = pe.read(base, size), ctypes.string_at(cursor, size)
        cursor += size
        if expected == actual:
            continue
        for i, (ours, original) in enumerate(
            zip(struct.iter_unpack(fmt, actual), struct.iter_unpack(fmt, expected), strict=True),
        ):
            if exact:
                assert struct.pack(fmt, *ours) == struct.pack(fmt, *original), (case, name, i, ours, original)
            else:
                assert all(
                    math.isclose(a, b, abs_tol=0.001, rel_tol=0.000002) if isinstance(a, float) else a == b
                    for a, b in zip(ours, original, strict=True)
                ), (case, name, i, ours, original)
    assert ctypes.c_uint32.from_address(check.symbol("freeware_rng_state")).value == pe.rand_state, case


def check_early_fx_writes(exe, edition, lines):
    if edition == "1.0.2":
        corpse, blood, seed = 0x405950, 0x4058D0, 0x41DCC8
        corpse_count, blood_count = 0x428878, 0x428870
        pos, tint, angle, size, species, blood_pos = 0x420C90, 0x424ED0, 0x4247C0, 0x421D90, 0x424DC8, 0x4245C0
    else:
        corpse, blood, seed = 0x40AA80, 0x40AA00, 0x42B634
        corpse_count, blood_count = 0x44781C, 0x447814
        pos, tint, angle, size, species, blood_pos = 0x42E620, 0x4370A0, 0x433C0C, 0x42FE90, 0x436F98, 0x433A08
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=seed)
    pe.rand_state = 0x21357
    for i in range(66):
        point = pe.alloc_f32s(i + 0.5, i - 5)
        color = pe.alloc_f32s(i / 128, 0.25, 0.75, 1)
        pe.call(corpse, point, color, i * 0.125, float(i + 42), i % 2)
        pe.call(blood, point)
    assert f"fxcounts {pe.read_i32(corpse_count)} {pe.read_i32(blood_count)} {pe.rand_state}" in lines
    pools = [(pos, "<2f"), (tint, "<4f"), (angle, "<f"), (size, "<f"), (species, "<i"), (blood_pos, "<2f")]
    slots = [line.split()[1:] for line in lines if line.startswith("fxslot ")]
    for i, row in zip(range(64), slots, strict=True):
        expected = [i]
        for address, fmt in pools:
            width = struct.calcsize(fmt)
            expected.extend(struct.unpack(fmt, pe.read(address + i * width, width)))
        assert list(map(float, row)) == expected, (edition, i, row, expected)
    print(f"{edition}: 66 original corpse and blood writes matched every slot and the CRT state")
