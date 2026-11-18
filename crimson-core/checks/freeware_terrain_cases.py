"""Compare the terrain target built by 0x40e060, including the original layer renderer."""

import ctypes
import math
import struct

from freeware_ui_cases import UiOracle


def check_generation(check, exe):
    original = UiOracle(exe)
    pe = original.pe
    level = pe.alloc(0x80)
    pe.write_u32(0x43CBB8, level)
    pe.write_u32(0x452D28, 710)
    original.textures.update({801: "arrow", 802: "blood"})
    layers = []
    for layer in range(2):
        entries = []
        for i in range(3):
            k = 3 * layer + i
            obj = struct.pack(
                "<5fiB7x4f",
                112.5 + k * 3,
                213 - k * 0.5,
                0.25 + k * 0.125,
                45 + i,
                62 - i * 1.5,
                802 if i == 2 else 801,
                (0, 1, 2, 3, 0, 1)[k],
                0.25,
                0.375,
                0.625,
                0.75,
            )
            entries.append(pe.alloc(len(obj), data=obj))
            ctypes.memmove(check.symbol("combat_ground_objects") + 48 * k, obj, 48)
        layers.append(pe.alloc(12, data=struct.pack("<3I", *entries)))
    pe.write_f32(0x452D40, 0.625)
    total = 0
    for safe, textured, populated, w, h, seed in (
        (0, 1, 0, 1024, 1024, 1),
        (0, 1, 0, 1024, 1024, 87),
        (0, 1, 0, 1024, 1024, 13456),
        (0, 1, 1, 765, 513, 177),
        (0, 1, 0, 2048, 2048, 42),  # The original area-times-density calculation wraps at 32 bits.
        (0, 0, 1, 1024, 1024, 951),
        (0, 1, 1, 15, 3, 234),
        (0, 0, 0, 0, 0, 9),
        (1, 1, 1, 1024, 1024, 79),
        (1, 0, 0, 513, 767, 88),
    ):
        check.dll.combat_world_start(0)
        for i, entries in enumerate(layers):
            pe.write(level + 24 + 16 * i, struct.pack("<II", entries, entries + 12) if populated else bytes(8))
        pe.write_u8(0x452D51, safe)
        pe.write_u32(0x42FBD8, w)
        pe.write_u32(0x42FBDC, h)
        pe.write_f32(0x43CBC0, -27.5)
        pe.write_f32(0x43CBC4, 11.25)
        original.reset_draw()
        pe.rand_state = seed
        pe.call(0x40E060, textured)
        n = check.dll.combat_generate(seed, safe, textured, w, h, populated)
        case = ("generate", safe, textured, populated, w, h, seed)
        total += original.compare(check, n, case)
        assert original.targets == ([] if safe else [710, 0xFFFFFFFF]), case
        assert len(original.clears) == int(not safe), case
        fields = (ctypes.c_float * 16).from_address(check.symbol("combat_ground_state"))
        assert list(fields[:3]) == [7 if safe else 8, 1, 1], case
        assert list(fields[3:8]) == [
            pe.read_f32(0x43CBC0),
            pe.read_f32(0x43CBC4),
            original.filter,
            original.source,
            original.blend,
        ], case
        color = (0.25, 0.5, 0.75, 1) if safe else original.clears[0]
        assert all(math.isclose(a, b, abs_tol=1e-7) for a, b in zip(fields[8:12], color, strict=True)), case
        assert fields[12] == (1 if safe else n), case
        assert ctypes.c_uint32.from_address(check.symbol("freeware_rng_state")).value == pe.rand_state, case
    return total
