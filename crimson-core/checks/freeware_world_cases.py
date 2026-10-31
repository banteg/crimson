"""Run the released world renderers with the same pools and capture ordered Grim submissions."""

import ctypes
import math
import struct

from freeware_ui_cases import UiOracle


def check_world(check, exe):
    original = UiOracle(exe)
    pe = original.pe
    original.textures[701] = "goblin"
    pe.write_u32(0x452D2C, 701)
    pe.call(0x408DC0)  # Original 8x8 atlas initializer.
    total = 0
    for flags in range(4):
        check.dll.combat_world_start(flags)
        pe.write_f32(0x43CBC0, -27.5)
        pe.write_f32(0x43CBC4, 11.25)
        pe.write_u8(0x44289B, flags & 1)
        pe.write_f32(0x452DBC, 2 if flags & 2 else 0)
        pe.write(0x442AF8, bytes(512 * 128))
        for addr in (0x4387F8, 0x452E80, 0x452E88):
            pe.write_u32(addr, 0)
        for i, (kind, animation, death, infected) in enumerate(
            [(0, 4, 16, 0), (1, 18, 16, 1), (0, 19.5, 16, 0), (1, 15.45, 6.5, 0), (0, 4, -0.25, 0), (1, 4, -0.125, 1)],
        ):
            slot = (0, 1, 19, 63, 220, 511)[i]
            record = bytearray(128)
            record[0] = 1
            record[12] = infected
            for offset, value in (
                (20, death),
                (24, 140.5 + i * 11),
                (28, 81.25 - i),
                (44, 0.5 + i / 8),
                (52, 28 + i * 3),
                (56, 0.3),
                (60, 0.7),
                (64, 0.9),
                (68, 0.625),
                (124, animation),
            ):
                struct.pack_into("<f", record, offset, value)
            struct.pack_into("<i", record, 116, kind)
            data = bytes(record)
            pe.write(0x442AF8 + slot * 128, data)
            ctypes.memmove(check.symbol("creature_pool") + slot * 128, data, 128)
        for frame in range(2):
            original.reset_draw()
            pe.call(0x40FD10)
            n = check.dll.combat_world_render(0)
            total += original.compare(check, n, ("creatures", flags, frame))
            state = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
            assert tuple(state[:3]) == tuple(pe.read_i32(a) for a in (0x4387F8, 0x452E80, 0x452E88))
            last = pe.read_i32(0x452E88) - 1
            expected = (
                pe.read_f32(0x436AF8 + 8 * last),
                pe.read_f32(0x436AFC + 8 * last),
                pe.read_f32(0x438378 + 4 * last),
                pe.read_f32(0x43C8B4 + 4 * last),
                62 if pe.read_i32(0x442390 + 4 * last) else 31,
            )
            assert all(math.isclose(a, b, abs_tol=0.0001) for a, b in zip(state[3:8], expected, strict=True))
            assert ctypes.string_at(check.symbol("creature_pool"), 512 * 128) == pe.read(0x442AF8, 512 * 128)
    return total
