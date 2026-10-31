"""The four FX writers share their capped counts with the next render pass."""

import ctypes
import math
import struct

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
