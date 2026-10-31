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
    return total + check_player_draws(check, original)


def check_player_draws(check, original):
    pe = original.pe
    original.textures[702] = "ugluk"
    pe.write_u32(0x43831C, 702)
    pe.stub(0x405630, 0)
    pe.write_u32(0x452E10, 12)
    pe.write_u32(0x452DE8, 2)
    total = 0
    for i in range(27):
        slot = i % 2
        count = 2 if slot or i % 4 else 1
        kind = i % 7
        distance = (31, 32, 33)[i // 7 % 3]
        check.dll.combat_world_start(0)
        data = bytearray(0x310)
        for j in range(2):
            offset = j * 0x188
            for field, value in (
                (0x18, 235.5 + 100 * j),
                (0x1C, 97.25 - 32 * j),
                (0x28, 0 if i == 26 else 71),
                (0x2C, 2.55),
                (0x34, 46.5),
                (0x6C, 3),
                (0x7C, (0, 7.25, 14.8)[i % 3]),
                (0x8C, 0.625),
                (0x164, 17),
                (0x168, 0.245 if i % 2 else 0),
                (0x16C, -1.123),
                (0x178, (0, 0.42, 3)[i % 3]),
            ):
                struct.pack_into("<f", data, offset + field, value)
            for perk, value in ((2, i % 3 == 1), (12, i % 4 == 0)):
                struct.pack_into("<i", data, offset + 0x94 + perk * 4, value)
        pe.write(0x438478, bytes(data))
        ctypes.memmove(check.symbol("player_state_table"), bytes(data), len(data))
        check.dll.combat_world_player(slot, count, kind, distance)
        for addr, value in ((0x452D8C, slot), (0x4428A0, count), (0x4387E8, kind), (0x452E60, 0), (0x452E68, 8)):
            pe.write_u32(addr, value)
        for addr, value in (
            (0x452D40, 1.375),
            (0x452E64, 2.5 if kind else 0),
            (0x4369F0, 235.5 + 100 * slot + distance),
            (0x4369F4, 97.25 - 32 * slot),
            (0x452DBC, 0),
            (0x452E6C, 0),
            (0x452DC8, -1),
            (0x4387B8, 0),
            (0x4387BC, 0),
            (0x452BF8, 0),
            (0x452BFC, 0),
            (0x452DB8, 0),
        ):
            pe.write_f32(addr, value)
        original.reset_draw()
        pe.call(0x4103B0)
        n = check.dll.combat_world_render(1)
        total += original.compare(check, n, ("player", i, kind, distance))
        got = ctypes.string_at(check.symbol("player_state_table"), len(data))
        assert got == pe.read(0x438478, len(data)), (
            "player record",
            i,
            next((k for k, (a, b) in enumerate(zip(got, pe.read(0x438478, len(data)), strict=True)) if a != b), None),
        )
        state = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
        expected = [pe.read_f32(0x452E64), pe.read_i32(0x4387E8)] + [
            pe.read_f32(a)
            for a in (
                0x452DBC,
                0x452E6C,
                0x452DC8,
                0x4387B8,
                0x4387BC,
                0x452BF8,
                0x452BFC,
                0x452DB8,
                0x438504 + slot * 0x188,
            )
        ]
        assert list(state[8:19]) == expected, ("pickup", i, list(state[8:19]), expected)
    return total
